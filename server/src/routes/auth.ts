import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fs from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import type { Db } from '../db.js';
import type { Ctx, Role } from '../ctx.js';
import { config } from '../config.js';
import { hashPassword, randomToken, sha256hex, verifyPassword } from '../lib/crypto.js';
import { verifyTotp } from '../lib/totp.js';
import { createdBy, roleOf } from '../roles.js';
import { audit } from '../lib/audit.js';
import { movedTo } from '../migrate.js';

export const COOKIE = 'fleet_session';

const creds = z.object({
  username: z.string().trim().min(3).max(64).regex(/^[a-zA-Z0-9_.-]+$/),
  password: z.string().min(12).max(256),
});

function isLoopback(ip: string) {
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

interface AdminRow { id: number; username: string; role: Role; totp_enabled: number; totp_sealed: string | null; pw_hash: string }

export function sessionAdmin(ctx: Ctx, req: FastifyRequest) {
  const token = req.cookies[COOKIE];
  if (!token) return undefined;
  const a = ctx.db
    .prepare(`SELECT a.id, a.username, a.role, a.totp_enabled, a.totp_sealed, s.console FROM sessions s JOIN admins a ON a.id = s.admin_id
       WHERE s.token_hash = ? AND s.expires_at > datetime('now')`)
    .get(sha256hex(token)) as (Omit<AdminRow, 'pw_hash'> & { console: number }) | undefined;
  if (!a) return undefined;
  return {
    id: a.id, username: a.console ? `${a.username} (консоль)` : a.username, role: a.role, totp: !!a.totp_enabled,
    totpSecret: a.totp_sealed ? ctx.open(a.totp_sealed) : null, console: !!a.console,
  };
}

/** Защита API: сессия + заголовок X-Fleet на изменяющих запросах (CSRF: кросс-сайт его не пошлёт без CORS). */
export function requireAdmin(ctx: Ctx) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const admin = sessionAdmin(ctx, req);
    if (!admin) return reply.code(401).send({ error: 'unauthorized' });
    if (req.method !== 'GET' && req.headers['x-fleet'] !== '1') return reply.code(403).send({ error: 'missing X-Fleet header' });
    // панель перенесена: серверами управляет новая — здесь только просмотр (и возврат управления owner-ом)
    const moved = movedTo(ctx.db);
    if (moved && req.method !== 'GET' && !req.url.endsWith('/api/v1/panel/move/cancel'))
      return reply.code(409).send({ error: `панель перенесена на ${moved} — управляйте серверами там` });
    req.admin = admin;
  };
}

export function startSession(db: Db, req: FastifyRequest, reply: FastifyReply, adminId: number) {
  const token = randomToken();
  db.prepare(`INSERT INTO sessions (token_hash, admin_id, expires_at, ip) VALUES (?, ?, datetime('now', ?), ?)`).run(
    sha256hex(token), adminId, `+${config.sessionTtlHours} hours`, req.ip);
  db.prepare(`UPDATE admins SET last_login_at = datetime('now') WHERE id = ?`).run(adminId);
  reply.setCookie(COOKIE, token, { path: config.basePath, httpOnly: true, sameSite: 'strict', secure: config.secureCookies, maxAge: config.sessionTtlHours * 3600 });
}

export async function authRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const hasAdmins = () => !!db.prepare('SELECT 1 FROM admins LIMIT 1').get();

  app.get('/api/v1/auth/state', async (req) => {
    const admin = sessionAdmin(ctx, req);
    const role = admin ? roleOf(db, admin.role) : null;
    // права и область — чтобы интерфейс показывал только доступное; проверяет всё равно сервер
    return { setupNeeded: !hasAdmins(), loggedIn: !!admin, username: admin?.username ?? null, role: admin?.role ?? null, roleName: role?.name ?? null,
      perms: role?.perms ?? [], scope: role?.scope ?? null, owner: role?.owner ?? false, totp: admin?.totp ?? false,
      // сколько этот администратор уже создал — для подсказок «создано 3 из 10» у лимитов роли
      created: admin ? createdBy(db, admin.id) : null,
      // панель перенесена на другой сервер: баннер со ссылкой на новую
      movedTo: movedTo(db) };
  });

  // Первичная настройка owner: пока нет ни одного админа — с loopback или по одноразовому токену установщика.
  const tokenFile = path.join(config.dataDir, 'setup-token');
  const setupTokenOk = (t: string | undefined) => {
    if (!t || !fs.existsSync(tokenFile)) return false;
    const want = Buffer.from(fs.readFileSync(tokenFile, 'utf8').trim());
    const got = Buffer.from(t);
    return want.length === got.length && timingSafeEqual(want, got);
  };
  app.post('/api/v1/auth/setup', async (req, reply) => {
    if (hasAdmins()) return reply.code(409).send({ error: 'already set up' });
    const body = creds.extend({ token: z.string().optional() }).parse(req.body);
    if (!isLoopback(req.ip) && !setupTokenOk(body.token))
      return reply.code(403).send({ error: 'нужна ссылка первичной настройки (команда: eskadra url)' });
    const r = db.prepare(`INSERT INTO admins (username, pw_hash, role) VALUES (?, ?, 'owner')`).run(body.username, hashPassword(body.password));
    if (fs.existsSync(tokenFile)) fs.unlinkSync(tokenFile);
    audit(db, body.username, 'admin.setup', undefined, { ip: req.ip });
    startSession(db, req, reply, Number(r.lastInsertRowid));
    return { ok: true };
  });

  const fails = new Map<string, { n: number; at: number }>();
  app.post('/api/v1/auth/login', async (req, reply) => {
    const f = fails.get(req.ip);
    if (f && f.n >= 10 && Date.now() - f.at < 15 * 60_000) return reply.code(429).send({ error: 'слишком много попыток, подождите 15 минут' });
    const body = z.object({ username: z.string(), password: z.string(), otp: z.string().optional() }).parse(req.body);
    const row = db.prepare('SELECT id, pw_hash, totp_enabled, totp_sealed FROM admins WHERE username = ?').get(body.username) as AdminRow | undefined;
    const bad = () => {
      fails.set(req.ip, { n: (f && Date.now() - f.at < 15 * 60_000 ? f.n : 0) + 1, at: Date.now() });
      audit(db, body.username, 'admin.login_failed', undefined, { ip: req.ip });
      return reply.code(401).send({ error: 'неверный логин или пароль' });
    };
    if (!row || !verifyPassword(body.password, row.pw_hash)) return bad();
    if (row.totp_enabled) {
      if (!body.otp) return reply.code(428).send({ error: 'нужен код 2FA', kind: 'otp' });
      if (!verifyTotp(ctx.open(row.totp_sealed!), body.otp)) return bad();
    }
    fails.delete(req.ip);
    db.prepare(`DELETE FROM sessions WHERE expires_at <= datetime('now')`).run();
    startSession(db, req, reply, row.id);
    audit(db, body.username, 'admin.login', undefined, { ip: req.ip });
    return { ok: true };
  });

  app.post('/api/v1/auth/logout', async (req, reply) => {
    const token = req.cookies[COOKIE];
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256hex(token));
    reply.clearCookie(COOKIE, { path: config.basePath });
    return { ok: true };
  });
}

export { hashPassword };
