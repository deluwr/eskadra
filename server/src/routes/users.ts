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

const userBody = z.object({
  name: z.string().trim().min(1).max(48).regex(/^[\p{L}0-9 ._-]+$/u),
  tgId: z.string().regex(/^\d{3,20}$/).nullable().default(null),
  limitGroup: z.string().default('default'),
  trafficLimitGb: z.number().min(0).nullable().default(null),
  expireAt: z.string().nullable().default(null),
  deviceLimit: z.number().int().min(0).nullable().default(null),
  overAction: z.enum(['disable', 'notify']).default('disable'),
  modes: z.array(z.enum(['direct', 'via'])).min(1).default(['direct', 'via']),
  nodeIds: z.array(z.string()).nullable().default(null),
  wlMode: z.enum(['exact', 'prefix', 'asn']).default('exact'),
  status: z.enum(['active', 'disabled']).default('active'),
});

export function subBase(ctx: Ctx): string | null {
  const host = getSetting<string>(ctx.db, 'sub.host', '');
  const port = getSetting<number>(ctx.db, 'sub.port', 0);
  const scheme = config.subTls ? 'https' : getSetting<string>(ctx.db, 'sub.scheme', 'http');
  if (!host || !port) return null;
  return `${scheme}://${host.includes(':') ? `[${host}]` : host}:${port}`;
}

export async function userRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const vpn = new Vpn(ctx);
  const getUser = (id: string) => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    if (!u) throw new HttpError(404, 'пользователь не найден');
    return u;
  };

  const view = (u: UserRow) => {
    const t = db.prepare('SELECT up, down FROM traffic WHERE user_id = ? AND period = ?').get(u.id, period()) as { up: number; down: number } | undefined;
    const lim = effectiveLimits(ctx, u);
    const ips = db.prepare(`SELECT id, cidr, source, expires_at FROM allowed_ips WHERE user_id = ? AND expires_at > ? ORDER BY expires_at DESC`)
      .all(u.id, new Date().toISOString());
    const base = subBase(ctx);
    return {
      id: u.id, name: u.name, tg_id: u.tg_id, status: u.status, disabled_reason: u.disabled_reason,
      limit_group: u.limit_group, traffic_limit_gb: u.traffic_limit_gb, expire_at: u.expire_at, device_limit: u.device_limit,
      over_action: u.over_action, modes: json<string[]>(u.modes, []), node_ids: json<string[] | null>(u.node_ids, null), wl_mode: u.wl_mode,
      effective: lim,
      traffic: { up: t?.up ?? 0, down: t?.down ?? 0, period: period() },
      allowedIps: ips,
      subUrl: base ? `${base}/s/${u.sub_token}` : null,
      knockUrl: base ? `${base}/k/${u.knock_token}` : null,
      profiles: vpn.profiles(u).length,
    };
  };

  const save = (id: string | null, b: z.infer<typeof userBody>) => {
    if (b.nodeIds) for (const n of b.nodeIds) ctx.server(n);
    if (!db.prepare('SELECT 1 FROM limit_groups WHERE name = ?').get(b.limitGroup)) throw new HttpError(400, 'нет такой группы лимитов');
    const vals = [b.name, b.tgId, b.limitGroup, b.trafficLimitGb, b.expireAt, b.deviceLimit, b.overAction, JSON.stringify(b.modes),
      b.nodeIds ? JSON.stringify(b.nodeIds) : null, b.wlMode, b.status];
    if (id) {
      db.prepare(`UPDATE users SET name=?, tg_id=?, limit_group=?, traffic_limit_gb=?, expire_at=?, device_limit=?, over_action=?, modes=?, node_ids=?, wl_mode=?, status=?,
        disabled_reason = CASE WHEN ? = 'active' THEN NULL ELSE disabled_reason END WHERE id=?`).run(...vals, b.status, id);
      return id;
    }
    const nid = 'u-' + randomBytes(4).toString('hex');
    db.prepare(`INSERT INTO users (name, tg_id, limit_group, traffic_limit_gb, expire_at, device_limit, over_action, modes, node_ids, wl_mode, status, id, sub_token, knock_token)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...vals, nid, randomToken(18), randomToken(18));
    return nid;
  };

  app.get('/api/v1/users', async () => vpn.users().map(view));

  app.get<{ Params: { id: string } }>('/api/v1/users/:id', async (req) => view(getUser(req.params.id)));

  app.post('/api/v1/users', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const b = userBody.parse(req.body);
    if (db.prepare('SELECT 1 FROM users WHERE name = ?').get(b.name)) throw new HttpError(409, 'пользователь с таким именем уже есть');
    const id = save(null, b);
    vpn.markDirty();
    audit(db, req.admin!.username, 'user.create', id, { name: b.name });
    return view(getUser(id));
  });

  app.put<{ Params: { id: string } }>('/api/v1/users/:id', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const u = getUser(req.params.id);
    const b = userBody.parse(req.body);
    save(u.id, b);
    vpn.markDirty();
    audit(db, req.admin!.username, 'user.update', u.id, b);
    return view(getUser(u.id));
  });

  app.delete<{ Params: { id: string } }>('/api/v1/users/:id', { preHandler: guard(ctx, 'admin') }, async (req) => {
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

  app.post<{ Params: { id: string } }>('/api/v1/users/:id/rotate', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const u = getUser(req.params.id);
    const { what } = z.object({ what: z.enum(['sub', 'links', 'knock']) }).parse(req.body);
    if (what === 'sub') db.prepare('UPDATE users SET sub_token = ? WHERE id = ?').run(randomToken(18), u.id);
    if (what === 'knock') db.prepare('UPDATE users SET knock_token = ? WHERE id = ?').run(randomToken(18), u.id);
    if (what === 'links') { vpn.rotateCreds(u.id); vpn.markDirty(); }
    audit(db, req.admin!.username, `user.rotate_${what}`, u.id);
    return view(getUser(u.id));
  });

  app.post<{ Params: { id: string } }>('/api/v1/users/:id/allowed-ips', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const u = getUser(req.params.id);
    const b = z.object({ cidr: z.string(), ttlHours: z.number().min(1).max(720).default(12) }).parse(req.body);
    const ip = b.cidr.split('/')[0]!;
    if (!isIP(ip)) throw new HttpError(400, 'неверный адрес');
    await pushAllowedIp(ctx, u, b.cidr, 'admin', b.ttlHours * 3600);
    audit(db, req.admin!.username, 'user.allow_ip', u.id, b);
    return view(getUser(u.id));
  });

  app.delete<{ Params: { id: string; ipId: string } }>('/api/v1/users/:id/allowed-ips/:ipId', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const u = getUser(req.params.id);
    await revokeAllowedIp(ctx, u, Number(req.params.ipId));
    audit(db, req.admin!.username, 'user.revoke_ip', u.id, { id: req.params.ipId });
    return view(getUser(u.id));
  });

  // группы лимитов
  app.get('/api/v1/limit-groups', async () => db.prepare('SELECT * FROM limit_groups ORDER BY name').all());
  app.put('/api/v1/limit-groups', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const b = z.object({ name: z.string().trim().min(1).max(32), trafficGb: z.number().min(0).nullable(), days: z.number().int().min(1).nullable(), devices: z.number().int().min(0).nullable() }).parse(req.body);
    db.prepare(`INSERT INTO limit_groups (name, traffic_gb, days, devices) VALUES (?, ?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET traffic_gb = excluded.traffic_gb, days = excluded.days, devices = excluded.devices`).run(b.name, b.trafficGb, b.days, b.devices);
    audit(db, req.admin!.username, 'limit_group.save', b.name, b);
    return db.prepare('SELECT * FROM limit_groups ORDER BY name').all();
  });
}
