import type { FastifyInstance } from 'fastify';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { Ctx, guard, HttpError, type UserRow } from '../ctx.js';
import { getSetting } from '../db.js';
import { config } from '../config.js';
import { randomToken } from '../lib/crypto.js';
import { audit } from '../lib/audit.js';
import { effectiveLimits, json, period, Vpn } from '../vpn.js';
import { pushAllowedIp, revokeAllowedIp } from '../access.js';
import { checkUserQuota, roleOf, ScopeError, scopeUserBody, type RoleInfo } from '../roles.js';

/** Онлайн — если подключения пользователя видели за последнюю минуту (опрос узлов раз в 30 с). */
const ONLINE_MS = 75_000;

export const userBody = z.object({
  name: z.string().trim().min(1).max(48).regex(/^[\p{L}0-9 ._-]+$/u),
  tgId: z.string().regex(/^\d{3,20}$/).nullable().default(null),
  limitGroup: z.string().default('default'),
  trafficLimitGb: z.number().min(0).nullable().default(null),
  expireAt: z.string().nullable().default(null),
  deviceLimit: z.number().int().min(0).nullable().default(null),
  overAction: z.enum(['disable', 'notify']).default('disable'),
  modes: z.array(z.enum(['direct', 'via'])).min(1).default(['direct', 'via']),
  nodeIds: z.array(z.string()).nullable().default(null),
  /** Конфигурации, профили которых попадают в подписку; null — все. */
  templateIds: z.array(z.string()).nullable().default(null),
  wlMode: z.enum(['exact', 'prefix', 'asn']).default('exact'),
  status: z.enum(['active', 'disabled']).default('active'),
  /** Комментарий: кто это. Не передан — прежний не меняется (бот и привязка Telegram его не шлют). */
  note: z.string().trim().max(500).optional(),
  /** Выключенные варианты подключения (ключи профилей). Не передано — прежние не меняются. */
  excludedProfiles: z.array(z.string().regex(/^[dv]:[\w-]+:[\w-]+$/).max(160)).max(500).optional(),
});

export function subBase(ctx: Ctx): string | null {
  const host = getSetting<string>(ctx.db, 'sub.host', '');
  const port = getSetting<number>(ctx.db, 'sub.port', 0);
  const scheme = config.subTls ? 'https' : getSetting<string>(ctx.db, 'sub.scheme', 'http');
  if (!host || !port) return null;
  return `${scheme}://${host.includes(':') ? `[${host}]` : host}:${port}`;
}

/**
 * Создать (id = null) или изменить пользователя — панель и бот. role — кто сохраняет: конфигурации, серверы,
 * режимы и группа лимитов приводятся к области роли (roles.ts), выданное вне области остаётся как было.
 */
export function saveUser(ctx: Ctx, id: string | null, input: z.infer<typeof userBody>, role: RoleInfo = roleOf(ctx.db, 'owner'), adminId: number | null = null): string {
  const { db } = ctx;
  const prev = id ? (db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined) ?? null : null;
  let b: z.infer<typeof userBody>;
  try {
    b = scopeUserBody(db, role, prev, input);
    // лимиты роли: сколько пользователей создаёт её администратор и потолок устройств
    checkUserQuota(db, role, adminId, !id, b);
  } catch (e) { if (e instanceof ScopeError) throw new HttpError(403, e.message); throw e; }
  if (b.nodeIds) for (const n of b.nodeIds) ctx.server(n);
  if (!db.prepare('SELECT 1 FROM limit_groups WHERE name = ?').get(b.limitGroup)) throw new HttpError(400, 'нет такой группы лимитов');
  if (b.templateIds) for (const t of b.templateIds) if (!db.prepare('SELECT 1 FROM templates WHERE id = ?').get(t)) throw new HttpError(400, 'нет такой конфигурации');
  const vals = [b.name, b.tgId, b.limitGroup, b.trafficLimitGb, b.expireAt, b.deviceLimit, b.overAction, JSON.stringify(b.modes),
    b.nodeIds ? JSON.stringify(b.nodeIds) : null, b.templateIds ? JSON.stringify(b.templateIds) : null, b.wlMode, b.status];
  if (id) {
    if (b.note !== undefined) db.prepare('UPDATE users SET note = ? WHERE id = ?').run(b.note || null, id);
    if (b.excludedProfiles !== undefined) db.prepare('UPDATE users SET excluded_profiles = ? WHERE id = ?').run(b.excludedProfiles.length ? JSON.stringify(b.excludedProfiles) : null, id);
    db.prepare(`UPDATE users SET name=?, tg_id=?, limit_group=?, traffic_limit_gb=?, expire_at=?, device_limit=?, over_action=?, modes=?, node_ids=?, template_ids=?, wl_mode=?, status=?,
      disabled_reason = CASE WHEN ? = 'active' THEN NULL ELSE disabled_reason END WHERE id=?`).run(...vals, b.status, id);
    return id;
  }
  const nid = 'u-' + randomBytes(4).toString('hex');
  db.prepare(`INSERT INTO users (name, tg_id, limit_group, traffic_limit_gb, expire_at, device_limit, over_action, modes, node_ids, template_ids, wl_mode, status, id, sub_token, knock_token, note, excluded_profiles, created_by)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...vals, nid, randomToken(18), randomToken(18), b.note || null, b.excludedProfiles?.length ? JSON.stringify(b.excludedProfiles) : null, adminId);
  return nid;
}

export async function userRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const vpn = new Vpn(ctx);
  /** Конфигурации и профили, которые каждая даст пользователю в подписке (с учётом режимов и серверов, без учёта выбора конфигураций). */
  const configsOf = (u: UserRow) => {
    const allowed = json<string[] | null>(u.template_ids, null);
    // все варианты, какие дала бы конфигурация (без учёта выбора конфигураций и выключенных вариантов); on — включён ли
    const all = vpn.profiles({ ...u, template_ids: null, excluded_profiles: null });
    const off = json<string[]>(u.excluded_profiles, []);
    return vpn.userTemplates().map((t) => ({ id: t.id, name: t.name, allowed: !allowed || allowed.includes(t.id),
      profiles: all.filter((p) => p.template.id === t.id).map((p) => ({ key: p.key, name: p.name, on: !off.includes(p.key) })) }));
  };
  const getUser = (id: string) => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    if (!u) throw new HttpError(404, 'пользователь не найден');
    return u;
  };

  const onlineOf = (uid: string) => {
    const r = db.prepare('SELECT MAX(last_seen) AS at, SUM(blocked = 0) AS n FROM user_devices WHERE user_id = ?').get(uid) as { at: string | null; n: number | null };
    const at = r.at ?? getSetting<string | null>(db, `seen.${uid}`, null);
    return { online: !!r.at && Date.now() - Date.parse(r.at) < ONLINE_MS && (r.n ?? 0) > 0, lastSeen: at };
  };

  const view = (u: UserRow) => {
    const t = db.prepare('SELECT up, down FROM traffic WHERE user_id = ? AND period = ?').get(u.id, period()) as { up: number; down: number } | undefined;
    const lim = effectiveLimits(ctx, u);
    const ips = db.prepare(`SELECT id, cidr, source, expires_at FROM allowed_ips WHERE user_id = ? AND expires_at > ? ORDER BY expires_at DESC`)
      .all(u.id, new Date().toISOString());
    const base = subBase(ctx);
    return {
      id: u.id, name: u.name, note: u.note ?? '', tg_id: u.tg_id, status: u.status, disabled_reason: u.disabled_reason,
      limit_group: u.limit_group, traffic_limit_gb: u.traffic_limit_gb, expire_at: u.expire_at, device_limit: u.device_limit,
      over_action: u.over_action, modes: json<string[]>(u.modes, []), node_ids: json<string[] | null>(u.node_ids, null), template_ids: json<string[] | null>(u.template_ids, null), wl_mode: u.wl_mode,
      configs: configsOf(u),
      excluded_profiles: json<string[]>(u.excluded_profiles, []),
      effective: lim,
      traffic: { up: t?.up ?? 0, down: t?.down ?? 0, period: period() },
      allowedIps: ips,
      // устройства (IP с открытыми соединениями) за последние минуты; blocked — сверх лимита
      devices: db.prepare('SELECT ip, first_seen, last_seen, blocked FROM user_devices WHERE user_id = ? ORDER BY first_seen, ip').all(u.id),
      // онлайн: подключения видели на последнем опросе узлов (раз в 30 с, devices.ts); lastSeen — когда видели последний раз
      ...onlineOf(u.id),
      subUrl: base ? `${base}/s/${u.sub_token}` : null,
      knockUrl: base ? `${base}/k/${u.knock_token}` : null,
      profiles: vpn.profiles(u).length,
    };
  };

  const roleOfReq = (req: { admin?: { role: string } }) => roleOf(db, req.admin!.role);

  app.get('/api/v1/users', async () => vpn.users().map(view));

  app.get<{ Params: { id: string } }>('/api/v1/users/:id', async (req) => view(getUser(req.params.id)));

  app.post('/api/v1/users', { preHandler: guard(ctx, 'users.edit') }, async (req) => {
    const b = userBody.parse(req.body);
    if (db.prepare('SELECT 1 FROM users WHERE name = ?').get(b.name)) throw new HttpError(409, 'пользователь с таким именем уже есть');
    const id = saveUser(ctx, null, b, roleOfReq(req), req.admin!.id);
    vpn.markDirty();
    audit(db, req.admin!.username, 'user.create', id, { name: b.name });
    return view(getUser(id));
  });

  app.put<{ Params: { id: string } }>('/api/v1/users/:id', { preHandler: guard(ctx, 'users.edit') }, async (req) => {
    const u = getUser(req.params.id);
    const b = userBody.parse(req.body);
    saveUser(ctx, u.id, b, roleOfReq(req), req.admin!.id);
    vpn.markDirty();
    audit(db, req.admin!.username, 'user.update', u.id, b);
    return view(getUser(u.id));
  });

  app.delete<{ Params: { id: string } }>('/api/v1/users/:id', { preHandler: guard(ctx, 'users.delete') }, async (req) => {
    const u = getUser(req.params.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
    vpn.markDirty();
    audit(db, req.admin!.username, 'user.delete', u.id, { name: u.name });
    return { ok: true };
  });

  /** Отдельные ссылки на каждый профиль (§12.4.1). */
  app.get<{ Params: { id: string } }>('/api/v1/users/:id/links', async (req) => {
    const u = getUser(req.params.id);
    return vpn.profiles(u).map((p) => ({ key: p.key, name: p.name, mode: p.mode, uri: vpn.link(u, p) }));
  });

  app.post<{ Params: { id: string } }>('/api/v1/users/:id/rotate', { preHandler: guard(ctx, 'users.edit') }, async (req) => {
    const u = getUser(req.params.id);
    const { what } = z.object({ what: z.enum(['sub', 'links', 'knock']) }).parse(req.body);
    if (what === 'sub') db.prepare('UPDATE users SET sub_token = ? WHERE id = ?').run(randomToken(18), u.id);
    if (what === 'knock') db.prepare('UPDATE users SET knock_token = ? WHERE id = ?').run(randomToken(18), u.id);
    if (what === 'links') { vpn.rotateCreds(u.id); vpn.markDirty(); }
    audit(db, req.admin!.username, `user.rotate_${what}`, u.id);
    return view(getUser(u.id));
  });

  app.post<{ Params: { id: string } }>('/api/v1/users/:id/allowed-ips', { preHandler: guard(ctx, 'users.edit') }, async (req) => {
    const u = getUser(req.params.id);
    const b = z.object({ cidr: z.string(), ttlHours: z.number().min(1).max(720).default(12) }).parse(req.body);
    const ip = b.cidr.split('/')[0]!;
    if (!isIP(ip)) throw new HttpError(400, 'неверный адрес');
    await pushAllowedIp(ctx, u, b.cidr, 'admin', b.ttlHours * 3600);
    audit(db, req.admin!.username, 'user.allow_ip', u.id, b);
    return view(getUser(u.id));
  });

  app.delete<{ Params: { id: string; ipId: string } }>('/api/v1/users/:id/allowed-ips/:ipId', { preHandler: guard(ctx, 'users.edit') }, async (req) => {
    const u = getUser(req.params.id);
    await revokeAllowedIp(ctx, u, Number(req.params.ipId));
    audit(db, req.admin!.username, 'user.revoke_ip', u.id, { id: req.params.ipId });
    return view(getUser(u.id));
  });

  // группы лимитов
  app.get('/api/v1/limit-groups', async () => db.prepare('SELECT * FROM limit_groups ORDER BY name').all());
  app.put('/api/v1/limit-groups', { preHandler: guard(ctx, 'users.limits') }, async (req) => {
    const b = z.object({ name: z.string().trim().min(1).max(32), trafficGb: z.number().min(0).nullable(), days: z.number().int().min(1).nullable(), devices: z.number().int().min(0).nullable() }).parse(req.body);
    // потолок устройств роли нельзя обойти группой лимитов: группа без лимита или с большим лимитом — тоже нельзя
    const role = roleOfReq(req);
    const max = role.owner ? null : role.scope.maxDevices;
    if (max !== null && (b.devices === null || b.devices > max)) throw new HttpError(403, `роль «${role.name}»: устройств в группе лимитов — не больше ${max}`);
    db.prepare(`INSERT INTO limit_groups (name, traffic_gb, days, devices) VALUES (?, ?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET traffic_gb = excluded.traffic_gb, days = excluded.days, devices = excluded.devices`).run(b.name, b.trafficGb, b.days, b.devices);
    audit(db, req.admin!.username, 'limit_group.save', b.name, b);
    return db.prepare('SELECT * FROM limit_groups ORDER BY name').all();
  });
}
