import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { createdBy, roleOf } from './roles.js';
import { saveUser, userBody } from './routes/users.js';

/** Роль «reseller»: до 2 пользователей и 1 конфигурации на администратора, у пользователя не больше 3 устройств. */
function fixture(scope: Record<string, unknown> = { maxUsers: 2, maxTemplates: 1, maxDevices: 3 }) {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-rlim-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 5)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed) VALUES ('s1', 's1', '203.0.113.1', 'exit', 'k', 'x')`).run();
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('reseller', 'reseller', '["users.edit","users.limits","configs.edit"]', ?)`).run(JSON.stringify(scope));
  for (const [id, name, role] of [[1, 'own', 'owner'], [2, 'r1', 'reseller'], [3, 'r2', 'reseller']] as const)
    db.prepare(`INSERT INTO admins (id, username, pw_hash, role) VALUES (?, ?, 'x', ?)`).run(id, name, role);
  db.prepare(`INSERT INTO limit_groups (name, devices) VALUES ('five', 5)`).run();
  // группа по умолчанию — без лимита устройств (из коробки у неё 3)
  db.prepare(`UPDATE limit_groups SET devices = NULL WHERE name = 'default'`).run();
  return { db, ctx };
}

/** Панель с API пользователей и конфигураций от имени администратора adminId. */
async function api(ctx: Ctx, admin: { id: number; username: string; role: string }) {
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { ...admin, totp: false, totpSecret: null }; });
  const { userRoutes } = await import('./routes/users.js');
  const { templateRoutes } = await import('./routes/templates.js');
  await userRoutes(app, ctx);
  await templateRoutes(app, ctx);
  return app;
}

test('лимит роли: устройств у пользователя — не больше потолка; без лимита нельзя, группа лимитов считается', () => {
  const { ctx } = fixture();
  const r = roleOf(ctx.db, 'reseller');
  assert.throws(() => saveUser(ctx, null, userBody.parse({ name: 'a' }), r, 2), /не больше 3 \(сейчас без лимита/);
  assert.throws(() => saveUser(ctx, null, userBody.parse({ name: 'a', deviceLimit: 4 }), r, 2), /не больше 3 \(указано 4\)/);
  assert.throws(() => saveUser(ctx, null, userBody.parse({ name: 'a', limitGroup: 'five' }), r, 2), /указано 5/, 'лимит из группы');
  const id = saveUser(ctx, null, userBody.parse({ name: 'a', deviceLimit: 3 }), r, 2);
  // правка тем же администратором тоже не выводит за потолок; owner — может
  assert.throws(() => saveUser(ctx, id, userBody.parse({ name: 'a', deviceLimit: 10 }), r, 2), /не больше 3/);
  saveUser(ctx, id, userBody.parse({ name: 'a', deviceLimit: 10 }));
});

test('лимит роли: пользователей — на каждого администратора; удалённый освобождает место', () => {
  const { ctx, db } = fixture();
  const r = roleOf(db, 'reseller');
  saveUser(ctx, null, userBody.parse({ name: 'a', deviceLimit: 1 }), r, 2);
  const b = saveUser(ctx, null, userBody.parse({ name: 'b', deviceLimit: 1 }), r, 2);
  assert.throws(() => saveUser(ctx, null, userBody.parse({ name: 'c', deviceLimit: 1 }), r, 2), /не больше 2 пользователей \(создано 2\)/);
  // у второго администратора той же роли — свой счёт
  saveUser(ctx, null, userBody.parse({ name: 'd', deviceLimit: 1 }), r, 3);
  assert.deepEqual(createdBy(db, 2), { users: 2, templates: 0 });
  // правка существующего не упирается в лимит
  saveUser(ctx, b, userBody.parse({ name: 'b', deviceLimit: 2 }), r, 2);
  db.prepare('DELETE FROM users WHERE id = ?').run(b);
  saveUser(ctx, null, userBody.parse({ name: 'c', deviceLimit: 1 }), r, 2);
  // пользователи owner и без лимита роли не считаются и не ограничены
  for (const n of ['x', 'y', 'z']) saveUser(ctx, null, userBody.parse({ name: n }), roleOf(db, 'owner'), 1);
});

test('лимит роли через API: пользователи, конфигурации и группы лимитов', async () => {
  const { ctx, db } = fixture();
  const app = await api(ctx, { id: 2, username: 'r1', role: 'reseller' });
  const user = (name: string, deviceLimit: number | null) => app.inject({ method: 'POST', url: '/api/v1/users', payload: { name, deviceLimit } });
  assert.equal((await user('a', 2)).statusCode, 200);
  const no = await user('b', null);
  assert.equal(no.statusCode, 403);
  assert.match(no.body, /лимит устройств/);
  // конфигурации: одна на администратора
  const tpl = (name: string, port: number) => app.inject({ method: 'POST', url: '/api/v1/templates', payload: { name, protocol: 'vless', port, sni: ['www.apple.com'], nodeIds: ['s1'], settings: { security: 'reality' } } });
  assert.equal((await tpl('one', 8443)).statusCode, 200);
  const second = await tpl('two', 8444);
  assert.equal(second.statusCode, 403);
  assert.match(second.body, /не больше 1 конфигураций \(создано 1\)/);
  assert.equal((db.prepare(`SELECT created_by FROM templates WHERE name = 'one'`).get() as { created_by: number }).created_by, 2);
  // группа лимитов с бо́льшим числом устройств обошла бы потолок
  const grp = await app.inject({ method: 'PUT', url: '/api/v1/limit-groups', payload: { name: 'big', trafficGb: null, days: null, devices: 10 } });
  assert.equal(grp.statusCode, 403);
  assert.equal((await app.inject({ method: 'PUT', url: '/api/v1/limit-groups', payload: { name: 'ok', trafficGb: null, days: null, devices: 3 } })).statusCode, 200);
  await app.close();
});

test('роль без лимитов — как раньше', () => {
  const { ctx, db } = fixture({});
  const r = roleOf(db, 'reseller');
  assert.equal(r.scope.maxUsers, null);
  for (const n of ['a', 'b', 'c']) saveUser(ctx, null, userBody.parse({ name: n }), r, 2);
});
