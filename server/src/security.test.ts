import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import { openDb, setSetting } from './db.js';
import { hashPassword, Sealer, sha256hex } from './lib/crypto.js';
import { newTotpSecret, totpAt } from './lib/totp.js';
import { Ctx, scopeHook } from './ctx.js';
import { config } from './config.js';
import { authRoutes, requireAdmin } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { registerSecurityHeaders } from './headers.js';

const PW = 'correct horse battery';

async function panel() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-sec-'));
  (config as { dataDir: string }).dataDir = dir;
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 7)));
  db.prepare(`INSERT INTO admins (id, username, pw_hash, role) VALUES (1, 'boss', ?, 'owner')`).run(hashPassword(PW));
  const app = Fastify() as unknown as FastifyInstance;
  await app.register(cookie);
  registerSecurityHeaders(app, { tls: true });
  await authRoutes(app, ctx);
  await app.register(async (secured) => {
    secured.addHook('preHandler', requireAdmin(ctx));
    secured.addHook('preHandler', scopeHook(ctx));
    const deps = { backups: { settings: () => ({}) }, bot: {}, sub: {} } as unknown as Parameters<typeof adminRoutes>[2];
    await adminRoutes(secured, ctx, deps);
    // маршрут без отдельного права (как «проверить вход»): область роли всё равно действует
    secured.post('/api/v1/servers/:id/check', async () => ({ ok: true }));
  });
  const login = async (body: Record<string, unknown>, ip = '198.51.100.1') =>
    app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'boss', password: PW, ...body }, remoteAddress: ip });
  const cookieOf = (r: { cookies: Array<{ name: string; value: string }> }) => `fleet_session=${r.cookies.find((c) => c.name === 'fleet_session')!.value}`;
  return { db, ctx, app, login, cookieOf };
}

test('вход: неизвестный логин и неверный пароль неотличимы; перебор с разных адресов упирается в лимит логина', async () => {
  const p = await panel();
  const a = await p.login({ username: 'nobody', password: 'x'.repeat(12) });
  const b = await p.login({ password: 'wrong password!' });
  assert.equal(a.statusCode, 401);
  assert.equal(b.statusCode, 401);
  assert.equal(a.json().error, b.json().error);
  // 20 неудач на логин с 20 разных адресов — дальше пауза даже для верного пароля с нового адреса
  for (let i = 0; i < 19; i++) await p.login({ password: 'wrong password!' }, `203.0.113.${i + 10}`);
  assert.equal((await p.login({}, '192.0.2.200')).statusCode, 429);
  // другой логин с того же нового адреса не заблокирован
  assert.equal((await p.login({ username: 'other', password: 'x'.repeat(12) }, '192.0.2.201')).statusCode, 401);
});

test('вход: код 2FA одноразовый', async () => {
  const p = await panel();
  const secret = newTotpSecret();
  p.db.prepare('UPDATE admins SET totp_enabled = 1, totp_sealed = ? WHERE id = 1').run(p.ctx.seal(secret));
  assert.equal((await p.login({})).statusCode, 428);
  const otp = totpAt(secret, Date.now());
  assert.equal((await p.login({ otp })).statusCode, 200);
  assert.equal((await p.login({ otp }, '198.51.100.2')).statusCode, 401, 'тот же код второй раз не пускает');
});

test('2FA: включённую нельзя сбросить без действующего кода (украденная сессия не снимет второй фактор)', async () => {
  const p = await panel();
  const secret = newTotpSecret();
  p.db.prepare('UPDATE admins SET totp_enabled = 1, totp_sealed = ? WHERE id = 1').run(p.ctx.seal(secret));
  const c = p.cookieOf(await p.login({ otp: totpAt(secret, Date.now()) }));
  const setup = (otp?: string) => p.app.inject({ method: 'POST', url: '/api/v1/me/2fa/setup', headers: { cookie: c, 'x-fleet': '1', ...(otp ? { 'x-fleet-otp': otp } : {}) } });
  const r = await setup();
  assert.equal(r.statusCode, 428);
  assert.equal((p.db.prepare('SELECT totp_enabled FROM admins WHERE id = 1').get() as { totp_enabled: number }).totp_enabled, 1);
  assert.equal((await setup('000000')).statusCode, 428);
  assert.equal((await setup(totpAt(secret, Date.now()))).statusCode, 200);
});

test('смена пароля закрывает остальные сессии, текущая остаётся', async () => {
  const p = await panel();
  const mine = p.cookieOf(await p.login({}));
  const other = p.cookieOf(await p.login({}, '198.51.100.9'));
  const r = await p.app.inject({ method: 'POST', url: '/api/v1/me/password', headers: { cookie: mine, 'x-fleet': '1' }, payload: { current: PW, next: 'a much better password' } });
  assert.equal(r.statusCode, 200);
  const me = (c: string) => p.app.inject({ method: 'GET', url: '/api/v1/me/notify', headers: { cookie: c } });
  assert.equal((await me(mine)).statusCode, 200);
  assert.equal((await me(other)).statusCode, 401);
  const n = (p.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE admin_id = 1').get() as { n: number }).n;
  assert.equal(n, 1);
  assert.ok(p.db.prepare('SELECT 1 FROM sessions WHERE token_hash = ?').get(sha256hex(mine.split('=')[1]!)));
});

test('область роли действует и на маршрутах без отдельного права', async () => {
  const p = await panel();
  p.db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('ops', 'ops', '[]', ?)`).run(JSON.stringify({ servers: ['s1'] }));
  p.db.prepare(`INSERT INTO admins (id, username, pw_hash, role) VALUES (2, 'ops1', ?, 'ops')`).run(hashPassword(PW));
  const r = await p.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'ops1', password: PW }, remoteAddress: '198.51.100.3' });
  const c = p.cookieOf(r);
  const check = (id: string) => p.app.inject({ method: 'POST', url: `/api/v1/servers/${id}/check`, headers: { cookie: c, 'x-fleet': '1' } });
  assert.equal((await check('s1')).statusCode, 200);
  assert.equal((await check('s2')).statusCode, 403);
});

test('заголовки безопасности: без фреймов, без Referer, API не кэшируется, HSTS по HTTPS', async () => {
  const p = await panel();
  const r = await p.app.inject({ method: 'GET', url: '/api/v1/auth/state' });
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.equal(r.headers['referrer-policy'], 'no-referrer');
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.match(String(r.headers['content-security-policy']), /frame-ancestors 'none'/);
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.match(String(r.headers['strict-transport-security']), /max-age=/);
});

test('2FA для действий: 5 неверных кодов — пауза, перебор не идёт', async () => {
  const p = await panel();
  const secret = newTotpSecret();
  p.db.prepare('UPDATE admins SET totp_enabled = 1, totp_sealed = ? WHERE id = 1').run(p.ctx.seal(secret));
  const c = p.cookieOf(await p.login({ otp: totpAt(secret, Date.now()) }));
  const setup = (otp: string) => p.app.inject({ method: 'POST', url: '/api/v1/me/2fa/setup', headers: { cookie: c, 'x-fleet': '1', 'x-fleet-otp': otp } });
  for (const bad of ['000001', '000002', '000003', '000004', '000005']) assert.equal((await setup(bad)).statusCode, 428);
  // дальше даже верный код не принимается, пока не пройдёт пауза
  const r = await setup(totpAt(secret, Date.now()));
  assert.equal(r.statusCode, 429);
  assert.equal((p.db.prepare('SELECT totp_enabled FROM admins WHERE id = 1').get() as { totp_enabled: number }).totp_enabled, 1);
});

test('пользователи VPN: роль с лимитом на администратора видит только своих; ссылки доступа — только с правом менять', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-sec-u-'));
  (config as { dataDir: string }).dataDir = dir;
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 8)));
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('reseller', 'reseller', '["users.edit","users.delete"]', '{"maxUsers":5}')`).run();
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('viewer', 'viewer', '[]', '{}')`).run();
  for (const [id, name, role] of [[1, 'own', 'owner'], [2, 'r1', 'reseller'], [3, 'r2', 'reseller'], [4, 'v', 'viewer']] as const)
    db.prepare(`INSERT INTO admins (id, username, pw_hash, role) VALUES (?, ?, 'x', ?)`).run(id, name, role);
  setSetting(db, 'sub.host', 'sub.example'); setSetting(db, 'sub.port', 2096);
  for (const [id, by] of [['u1', 2], ['u2', 3], ['u3', 1]] as const)
    db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, created_by) VALUES (?, ?, ?, ?, ?)`).run(id, id, `tok-${id}`, `kn-${id}`, by);
  const as = async (admin: { id: number; username: string; role: string }) => {
    const app = Fastify();
    app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { ...admin, totp: false, totpSecret: null }; });
    const { userRoutes } = await import('./routes/users.js');
    await userRoutes(app as unknown as FastifyInstance, ctx);
    return app;
  };
  const r1 = await as({ id: 2, username: 'r1', role: 'reseller' });
  assert.deepEqual((await r1.inject({ method: 'GET', url: '/api/v1/users' })).json().map((u: { id: string }) => u.id), ['u1']);
  assert.equal((await r1.inject({ method: 'GET', url: '/api/v1/users/u2' })).statusCode, 404);
  assert.equal((await r1.inject({ method: 'DELETE', url: '/api/v1/users/u2' })).statusCode, 404, 'чужого клиента не удалить');
  assert.equal((await r1.inject({ method: 'POST', url: '/api/v1/users/u3/rotate', payload: { what: 'sub' } })).statusCode, 404);
  assert.ok(db.prepare(`SELECT 1 FROM users WHERE id = 'u2'`).get());
  assert.match(String((await r1.inject({ method: 'GET', url: '/api/v1/users/u1' })).json().subUrl), /tok-u1/);
  // роль без права менять пользователей видит всех, но не их ссылки доступа
  const v = await as({ id: 4, username: 'v', role: 'viewer' });
  const list = (await v.inject({ method: 'GET', url: '/api/v1/users' })).json() as Array<{ subUrl: string | null; knockUrl: string | null }>;
  assert.equal(list.length, 3);
  assert.ok(list.every((u) => u.subUrl === null && u.knockUrl === null));
  assert.equal((await v.inject({ method: 'GET', url: '/api/v1/users/u1/links' })).statusCode, 403);
  // owner — все и со ссылками
  const o = await as({ id: 1, username: 'own', role: 'owner' });
  assert.equal((await o.inject({ method: 'GET', url: '/api/v1/users' })).json().length, 3);
});
