import type { FastifyInstance } from 'fastify';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { Ops } from '../ops.js';
import { botProxyOptions, botProxySetting, saveBotProxy } from '../botproxy.js';
import { panelReleases, versionInfo } from '../version.js';
import { cmpVersion } from '../releases.js';
import { Ctx, guard, HttpError } from '../ctx.js';
import { getSetting, setSetting } from '../db.js';
import { hashPassword, sha256hex, verifyPassword } from '../lib/crypto.js';
import { newTotpSecret, otpauthUri, verifyTotp } from '../lib/totp.js';
import { audit, verifyAuditChain } from '../lib/audit.js';
import { COOKIE } from './auth.js';
import { publicView, stageOf } from './servers.js';
import { Vpn, json, period } from '../vpn.js';
import type { Backups } from '../backup.js';
import type { Bot } from '../bot.js';
import { attentionOf } from '../attention.js';
import { listSnapshots, MIN_ROLLBACK_WITH_DATA, requestUpdate, snapshotDb, stageRollbackData, updateHelperInstalled, updateStatus } from '../update.js';
import { armRestore, decryptBackup, stageRestore } from '../restorelib.js';
import { config } from '../config.js';
import { NOTIFY } from '../botadmin.js';
import { listRoles, PERM_KEYS, PERMS, type Perm } from '../roles.js';
import { blocksOf } from '../blocks.js';
import type { SubService } from '../subsvc.js';

async function detectEgressIp(): Promise<string> {
  const res = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(8000) });
  const { ip } = (await res.json()) as { ip: string };
  if (!isIP(ip)) throw new Error('egress IP detection returned garbage');
  return ip;
}

export async function adminRoutes(app: FastifyInstance, ctx: Ctx, deps: { backups: Backups; bot: Bot; sub: SubService }) {
  const { db } = ctx;
  const vpn = new Vpn(ctx);
  const who = (req: { admin?: { username: string } }) => req.admin!.username;

  // ───── обзор ─────
  app.get('/api/v1/overview', async () => {
    const servers = ctx.servers();
    const users = vpn.users();
    const traffic = db.prepare('SELECT COALESCE(SUM(up + down), 0) AS t FROM traffic WHERE period = ?').get(period()) as { t: number };
    const lastBackup = db.prepare('SELECT * FROM backups ORDER BY id DESC LIMIT 1').get();
    const attention = attentionOf(ctx, vpn);
    return {
      servers: servers.map((s) => ({ ...publicView(ctx, s), stage: stageOf(s) })),
      counts: { servers: servers.length, online: servers.filter((s) => s.last_seen_at && !s.fail_since).length, users: users.length, activeUsers: users.filter((u) => u.status === 'active').length },
      trafficBytes: traffic.t,
      lastBackup,
      attention,
      recent: db.prepare('SELECT id, ts, actor, action, target FROM audit_log ORDER BY id DESC LIMIT 8').all(),
      executorIps: ctx.executorIps(),
      routes: routesOf(),
    };
  });

  /** Маршруты конфигураций со входом для схемы на обзоре: вход → выходы в их порядке, замеры «Авто» и выбранный выход. */
  const routesOf = () => vpn.templates().filter((t) => t.entry_id).map((t) => {
    const sp = vpn.spec(t);
    const health = new Map((db.prepare('SELECT exit_id, rtt_ms, mbps, ok, error FROM exit_health WHERE template_id = ?').all(t.id) as Array<{ exit_id: string; rtt_ms: number | null; mbps: number | null; ok: number; error: string | null }>).map((h) => [h.exit_id, h]));
    const ov = getSetting<string | null>(db, `auto.actual.${t.id}`, null) ?? getSetting<string | null>(db, `auto.override.${t.id}`, null);
    return {
      id: t.id, name: t.name, entryId: t.entry_id, autoMode: sp.autoMode,
      selected: ov ? ov.slice(`to-${t.id}-`.length) : null,
      exits: vpn.relayTargets(t).map((x) => ({ id: x.id, health: health.get(x.id) ?? null })),
    };
  });

  // ───── порты и связность ─────
  app.get('/api/v1/connectivity', async () => {
    const servers = ctx.servers();
    return {
      servers: servers.map((s) => ({ id: s.id, name: s.name, group: s.group_name, role: s.role, ufw: !!s.ufw_active, sshPorts: JSON.parse(s.ssh_ports ?? '[]'), fwMode: s.fw_mode })),
      inbounds: db.prepare(`SELECT i.server_id, i.port, i.proto, i.state, t.name AS template FROM inbounds i JOIN templates t ON t.id = i.template_id ORDER BY i.port`).all(),
      checks: db.prepare('SELECT * FROM peer_checks').all(),
      groups: db.prepare('SELECT * FROM groups ORDER BY name').all(),
    };
  });

  /** Группы и их серверы: политика (скрытность, связность, диапазон портов) задаётся на группу. */
  app.get('/api/v1/groups', async () =>
    db.prepare(`SELECT g.*, (SELECT COUNT(*) FROM servers s WHERE s.group_name = g.name) AS servers FROM groups g ORDER BY g.name`).all());

  app.delete<{ Params: { name: string } }>('/api/v1/groups/:name', { preHandler: guard(ctx, 'ports.groups') }, async (req) => {
    const name = req.params.name;
    if (name === 'default') throw new HttpError(409, 'группу default удалить нельзя');
    if (db.prepare('SELECT 1 FROM servers WHERE group_name = ?').get(name)) throw new HttpError(409, 'в группе есть серверы — сначала перенесите их в другую группу');
    db.prepare('DELETE FROM groups WHERE name = ?').run(name);
    audit(db, who(req), 'group.delete', name);
    return db.prepare('SELECT * FROM groups ORDER BY name').all();
  });

  app.put('/api/v1/groups', { preHandler: guard(ctx, 'ports.groups') }, async (req) => {
    const b = z.object({
      name: z.string().trim().min(1).max(32),
      stealth: z.enum(['S0', 'S1', 'S2', 'S3', 'S4']),
      peerScope: z.enum(['services', 'chain', 'all', 'none']),
      portRange: z.string().regex(/^\s*\d{1,5}(-\d{1,5})?(\s*,\s*\d{1,5}(-\d{1,5})?)*\s*$/),
    }).parse(req.body);
    db.prepare(`INSERT INTO groups (name, stealth, peer_scope, port_range) VALUES (?, ?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET stealth = excluded.stealth, peer_scope = excluded.peer_scope, port_range = excluded.port_range`)
      .run(b.name, b.stealth, b.peerScope, b.portRange.replace(/\s+/g, ''));
    audit(db, who(req), 'group.save', b.name, b);
    return db.prepare('SELECT * FROM groups ORDER BY name').all();
  });

  // ───── права и роли ─────
  const roleMustExist = (id: string) => { if (id !== 'owner' && !db.prepare('SELECT 1 FROM roles WHERE id = ?').get(id)) throw new HttpError(400, 'нет такой роли'); };
  const rolesView = () => ({ perms: PERMS, roles: listRoles(db).map((r) => ({ ...r, admins: (db.prepare('SELECT COUNT(*) AS n FROM admins WHERE role = ?').get(r.id) as { n: number }).n })) });
  const scopeBody = z.object({
    templates: z.array(z.string()).nullable(), servers: z.array(z.string()).nullable(),
    modes: z.array(z.enum(['direct', 'via'])).min(1).nullable(), limitGroups: z.array(z.string()).nullable(),
  });
  const roleBody = z.object({ name: z.string().trim().min(2).max(32).regex(/^[\p{L}0-9 ._-]+$/u), perms: z.array(z.enum(PERM_KEYS as [Perm, ...Perm[]])), scope: scopeBody });

  app.get('/api/v1/roles', async () => rolesView());

  /** Новая роль со своими правами и областью; id — из имени (латиница) или случайный. */
  app.post('/api/v1/roles', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const b = roleBody.parse(req.body);
    if (b.name.toLowerCase() === 'owner' || db.prepare('SELECT 1 FROM roles WHERE lower(name) = lower(?)').get(b.name)) throw new HttpError(409, 'роль с таким именем уже есть');
    const slug = b.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const id = slug && slug !== 'owner' && !db.prepare('SELECT 1 FROM roles WHERE id = ?').get(slug) ? slug : 'role-' + randomBytes(3).toString('hex');
    db.prepare('INSERT INTO roles (id, name, perms, scope) VALUES (?, ?, ?, ?)').run(id, b.name, JSON.stringify(b.perms), JSON.stringify(b.scope));
    audit(db, who(req), 'role.create', id, b);
    return rolesView();
  });

  /** Изменить права и область роли; owner не меняется. Встроенные admin и operator переименовать нельзя. */
  app.put<{ Params: { id: string } }>('/api/v1/roles/:id', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const r = db.prepare('SELECT * FROM roles WHERE id = ?').get(req.params.id) as { id: string; builtin: number; name: string } | undefined;
    if (!r) throw new HttpError(404, req.params.id === 'owner' ? 'права owner не настраиваются' : 'нет такой роли');
    const b = roleBody.parse(req.body);
    const name = r.builtin ? r.name : b.name;
    if (name !== r.name && db.prepare('SELECT 1 FROM roles WHERE lower(name) = lower(?) AND id != ?').get(name, r.id)) throw new HttpError(409, 'роль с таким именем уже есть');
    db.prepare('UPDATE roles SET name = ?, perms = ?, scope = ? WHERE id = ?').run(name, JSON.stringify(b.perms), JSON.stringify(b.scope), r.id);
    audit(db, who(req), 'role.update', r.id, b);
    return rolesView();
  });

  app.delete<{ Params: { id: string } }>('/api/v1/roles/:id', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const r = db.prepare('SELECT * FROM roles WHERE id = ?').get(req.params.id) as { id: string; builtin: number } | undefined;
    if (!r) throw new HttpError(404, 'нет такой роли');
    if (r.builtin) throw new HttpError(409, 'встроенную роль удалить нельзя — можно изменить её права');
    const n = (db.prepare('SELECT COUNT(*) AS n FROM admins WHERE role = ?').get(r.id) as { n: number }).n;
    if (n) throw new HttpError(409, `роль назначена администраторам (${n}) — сначала смените им роль`);
    db.prepare('DELETE FROM roles WHERE id = ?').run(r.id);
    audit(db, who(req), 'role.delete', r.id);
    return rolesView();
  });

  const adminView = () => db.prepare('SELECT id, username, role, totp_enabled, tg_id, backup_recipient, last_login_at, created_at FROM admins ORDER BY id').all();

  app.get('/api/v1/admins', async () => adminView());

  app.post('/api/v1/admins', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const b = z.object({ username: z.string().trim().min(3).max(64).regex(/^[a-zA-Z0-9_.-]+$/), role: z.string() }).parse(req.body);
    roleMustExist(b.role);
    if (db.prepare('SELECT 1 FROM admins WHERE username = ?').get(b.username)) throw new HttpError(409, 'такой логин уже есть');
    const password = randomBytes(15).toString('base64url');
    db.prepare('INSERT INTO admins (username, pw_hash, role) VALUES (?, ?, ?)').run(b.username, hashPassword(password), b.role);
    audit(db, who(req), 'admin.create', b.username, { role: b.role });
    return { username: b.username, password, admins: adminView() };
  });

  app.patch<{ Params: { id: string } }>('/api/v1/admins/:id', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const id = Number(req.params.id);
    const b = z.object({ role: z.string().optional(), tgId: z.string().regex(/^\d{3,20}$/).nullable().optional(), backupRecipient: z.boolean().optional() }).parse(req.body);
    const target = db.prepare('SELECT id, role FROM admins WHERE id = ?').get(id) as { id: number; role: string } | undefined;
    if (!target) throw new HttpError(404, 'нет такого администратора');
    if (b.role) roleMustExist(b.role);
    if (b.role && target.role === 'owner' && b.role !== 'owner') {
      const owners = db.prepare(`SELECT COUNT(*) AS n FROM admins WHERE role = 'owner'`).get() as { n: number };
      if (owners.n < 2) throw new HttpError(409, 'нельзя убрать последнего owner');
    }
    if (b.role) db.prepare('UPDATE admins SET role = ? WHERE id = ?').run(b.role, id);
    if (b.tgId !== undefined) db.prepare('UPDATE admins SET tg_id = ? WHERE id = ?').run(b.tgId, id);
    if (b.backupRecipient !== undefined) db.prepare('UPDATE admins SET backup_recipient = ? WHERE id = ?').run(b.backupRecipient ? 1 : 0, id);
    audit(db, who(req), 'admin.update', String(id), b);
    return adminView();
  });

  app.delete<{ Params: { id: string } }>('/api/v1/admins/:id', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const id = Number(req.params.id);
    if (id === req.admin!.id) throw new HttpError(409, 'нельзя удалить себя');
    db.prepare('DELETE FROM admins WHERE id = ?').run(id);
    audit(db, who(req), 'admin.delete', String(id));
    return adminView();
  });

  // Привязка Telegram одноразовой ссылкой: человек открывает её и нажимает «Старт» в боте
  app.post<{ Params: { id: string } }>('/api/v1/admins/:id/tg-link', async (req) => {
    const id = Number(req.params.id);
    if (id !== req.admin!.id && req.admin!.role !== 'owner') throw new HttpError(403, 'привязать чужой Telegram может только owner');
    if (!db.prepare('SELECT 1 FROM admins WHERE id = ?').get(id)) throw new HttpError(404, 'нет такого администратора');
    try { return await deps.bot.bindLink('admin', String(id)); } catch (e) { throw new HttpError(409, (e as Error).message); }
  });

  app.post<{ Params: { id: string } }>('/api/v1/users/:id/tg-link', { preHandler: guard(ctx, 'users.edit') }, async (req) => {
    if (!db.prepare('SELECT 1 FROM users WHERE id = ?').get(req.params.id)) throw new HttpError(404, 'нет такого пользователя');
    try { return await deps.bot.bindLink('user', req.params.id); } catch (e) { throw new HttpError(409, (e as Error).message); }
  });

  app.get<{ Params: { code: string } }>('/api/v1/tg-link/:code', async (req) => ({ state: deps.bot.bindState(req.params.code) }));

  // Свой профиль: Telegram ID, 2FA, пароль, сессии
  app.patch('/api/v1/me', async (req) => {
    const b = z.object({ tgId: z.string().regex(/^\d{3,20}$/).nullable() }).parse(req.body);
    db.prepare('UPDATE admins SET tg_id = ? WHERE id = ?').run(b.tgId, req.admin!.id);
    audit(db, who(req), 'admin.me_update', undefined, b);
    return { ok: true };
  });

  // Какие уведомления присылать мне в Telegram (то же, что /notify в боте)
  app.get('/api/v1/me/notify', async (req) => ({
    categories: NOTIFY,
    off: json<string[]>((db.prepare('SELECT notify_off FROM admins WHERE id = ?').get(req.admin!.id) as { notify_off: string }).notify_off, []),
  }));
  app.put('/api/v1/me/notify', async (req) => {
    const { off } = z.object({ off: z.array(z.enum(Object.keys(NOTIFY) as [string, ...string[]])).max(20) }).parse(req.body);
    db.prepare('UPDATE admins SET notify_off = ? WHERE id = ?').run(JSON.stringify([...new Set(off)]), req.admin!.id);
    return { categories: NOTIFY, off };
  });

  app.post('/api/v1/me/2fa/setup', async (req) => {
    const secret = newTotpSecret();
    db.prepare('UPDATE admins SET totp_sealed = ?, totp_enabled = 0 WHERE id = ?').run(ctx.seal(secret), req.admin!.id);
    return { secret, uri: otpauthUri(secret, req.admin!.username) };
  });

  app.post('/api/v1/me/2fa/enable', async (req) => {
    const { code } = z.object({ code: z.string() }).parse(req.body);
    const row = db.prepare('SELECT totp_sealed FROM admins WHERE id = ?').get(req.admin!.id) as { totp_sealed: string | null };
    if (!row.totp_sealed || !verifyTotp(ctx.open(row.totp_sealed), code)) throw new HttpError(400, 'код не подошёл');
    db.prepare('UPDATE admins SET totp_enabled = 1 WHERE id = ?').run(req.admin!.id);
    audit(db, who(req), 'admin.2fa_enabled');
    return { ok: true };
  });

  app.post('/api/v1/me/password', async (req) => {
    const b = z.object({ current: z.string(), next: z.string().min(12).max(256) }).parse(req.body);
    const row = db.prepare('SELECT pw_hash FROM admins WHERE id = ?').get(req.admin!.id) as { pw_hash: string };
    if (!verifyPassword(b.current, row.pw_hash)) throw new HttpError(400, 'текущий пароль неверен');
    db.prepare('UPDATE admins SET pw_hash = ? WHERE id = ?').run(hashPassword(b.next), req.admin!.id);
    audit(db, who(req), 'admin.password_changed');
    return { ok: true };
  });

  app.get('/api/v1/me/sessions', async (req) => {
    const current = sha256hex(req.cookies[COOKIE] ?? '');
    return (db.prepare('SELECT token_hash, created_at, expires_at, ip FROM sessions WHERE admin_id = ? AND expires_at > datetime(\'now\') ORDER BY created_at DESC').all(req.admin!.id) as Array<{ token_hash: string; created_at: string; expires_at: string; ip: string | null }>)
      .map((s) => ({ id: s.token_hash.slice(0, 12), created_at: s.created_at, expires_at: s.expires_at, ip: s.ip, current: s.token_hash === current }));
  });

  app.post('/api/v1/me/sessions/revoke-others', async (req) => {
    const current = sha256hex(req.cookies[COOKIE] ?? '');
    db.prepare('DELETE FROM sessions WHERE admin_id = ? AND token_hash != ?').run(req.admin!.id, current);
    audit(db, who(req), 'admin.sessions_revoked');
    return { ok: true };
  });

  // ───── настройки ─────
  app.get('/api/v1/version', async () => versionInfo());

  app.get('/api/v1/settings', async () => ({
    lang: getSetting(db, 'ui.lang', 'ru'),
    executorIps: ctx.executorIps(),
    sub: { host: getSetting(db, 'sub.host', ''), port: getSetting(db, 'sub.port', 0), scheme: getSetting(db, 'sub.scheme', 'http') },
    knockTtlHours: getSetting(db, 'knock.ttlHours', 12),
    // белый список IP пользователей — дополнительная опция: включается скрытностью группы S3/S4
    whitelistOn: !!db.prepare(`SELECT 1 FROM groups WHERE stealth IN ('S3','S4')`).get(),
    failThresholdMin: getSetting(db, 'check.failThresholdMin', 120),
    bot: { configured: !!getSetting(db, 'bot.token', '') },
    backup: deps.backups.settings(),
  }));

  // ───── обновление панели из интерфейса (root-помощник eskadra-update.path) ─────
  app.get('/api/v1/update/status', async () => updateStatus());

  app.post('/api/v1/update', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const { version } = z.object({ version: z.string().regex(/^(latest|v?\d+\.\d+\.\d+)$/).default('latest') }).parse(req.body ?? {});
    if (!updateHelperInstalled()) throw new HttpError(409, 'помощник обновления не установлен: один раз обновите панель командой eskadra update на главном сервере — дальше кнопка будет работать');
    const st = updateStatus();
    if (st.running || st.pending) throw new HttpError(409, 'обновление уже идёт');
    // копия данных текущей версии: при откате на неё их можно вернуть
    const snap = snapshotDb(db, (await versionInfo()).version);
    requestUpdate(version);
    audit(db, who(req), 'panel.update', undefined, { version, snapshot: snap?.file ?? null });
    return { ok: true };
  });

  /** Прошлые версии панели (GitHub) и копии данных, снятые при уходе с них. */
  app.get('/api/v1/update/versions', async () => {
    const { version } = await versionInfo();
    const snaps = listSnapshots();
    let releases: Array<{ version: string; published: string; prerelease: boolean }> = [];
    let error: string | null = null;
    try { releases = await panelReleases(); } catch (e) { error = (e as Error).message; }
    return {
      current: version, minWithData: `v${MIN_ROLLBACK_WITH_DATA}`, error,
      versions: releases.filter((r) => version === 'dev' || cmpVersion(r.version, version) < 0).map((r) => {
        const snap = snaps.find((x) => x.version === r.version);
        return { ...r, snapshotAt: snap?.at ?? null, withData: !!snap && cmpVersion(r.version, MIN_ROLLBACK_WITH_DATA) >= 0 };
      }),
    };
  });

  /**
   * Откат на прошлую версию. withData — вернуть и данные на момент, когда с неё обновились (изменения после
   * пропадут, текущие данные сохранятся рядом с суффиксом .before-restore-…). Без него новая база остаётся
   * со старым кодом — годится только для близких версий.
   */
  app.post('/api/v1/update/rollback', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const b = z.object({ version: z.string().regex(/^v?\d+\.\d+\.\d+$/), withData: z.boolean() }).parse(req.body);
    const version = b.version.replace(/^v?/, 'v');
    if (!updateHelperInstalled()) throw new HttpError(409, 'помощник обновления не установлен: один раз выполните eskadra update на главном сервере');
    const st = updateStatus();
    if (st.running || st.pending) throw new HttpError(409, 'обновление уже идёт');
    const cur = (await versionInfo()).version;
    if (cur !== 'dev' && cmpVersion(version, cur) >= 0) throw new HttpError(400, `${version} не старше текущей ${cur} — это обновление, а не откат`);
    if (b.withData) {
      if (cmpVersion(version, MIN_ROLLBACK_WITH_DATA) < 0) throw new HttpError(400, `версии до v${MIN_ROLLBACK_WITH_DATA} не умеют подменять данные при запуске — откат только без данных`);
      try { stageRollbackData(version); } catch (e) { throw new HttpError(409, (e as Error).message); }
    }
    // копия текущих данных — чтобы можно было вернуться вперёд с ними
    const snap = snapshotDb(db, cur);
    requestUpdate(version);
    audit(db, who(req), 'panel.rollback', undefined, { from: cur, to: version, withData: b.withData, snapshot: snap?.file ?? null });
    return { ok: true };
  });

  /** Язык панели: интерфейс у каждого свой (в браузере), а имена профилей в подписках — по этой настройке. */
  app.put('/api/v1/settings/lang', { preHandler: guard(ctx, 'settings.edit') }, async (req) => {
    const { lang } = z.object({ lang: z.enum(['ru', 'en']) }).parse(req.body);
    setSetting(db, 'ui.lang', lang);
    audit(db, who(req), 'settings.lang', undefined, { lang });
    return { lang };
  });

  app.post('/api/v1/settings/executor/detect', async () => ({ ip: await detectEgressIp() }));

  app.put('/api/v1/settings/executor', { preHandler: guard(ctx, 'settings.edit', { otp: true }) }, async (req) => {
    const { ips } = z.object({ ips: z.array(z.string().trim().refine((s) => isIP(s) !== 0, 'invalid IP')).min(1).max(16) }).parse(req.body);
    const uniq = [...new Set(ips)];
    setSetting(db, 'executor.ips', uniq);
    audit(db, who(req), 'executor.ips.set', undefined, { ips: uniq });
    return { ips: uniq };
  });

  app.put('/api/v1/settings/sub', { preHandler: guard(ctx, 'settings.edit') }, async (req) => {
    const b = z.object({
      host: z.string().trim().max(253).regex(/^[a-zA-Z0-9.:-]*$/),
      port: z.number().int().min(1024).max(65535).nullable(),
      scheme: z.enum(['http', 'https']).default('http'),
      randomPort: z.boolean().default(false),
    }).parse(req.body);
    setSetting(db, 'sub.host', b.host);
    setSetting(db, 'sub.scheme', b.scheme);
    if (b.randomPort) setSetting(db, 'sub.port', 0);
    else if (b.port) {
      if ([10085, 51820].includes(b.port)) throw new HttpError(400, 'порт зарезервирован');
      setSetting(db, 'sub.port', b.port);
    }
    const port = await deps.sub.restart();
    audit(db, who(req), 'sub.settings', undefined, { host: b.host, port });
    return { host: b.host, port, scheme: b.scheme };
  });

  app.put('/api/v1/settings/general', { preHandler: guard(ctx, 'settings.edit') }, async (req) => {
    const b = z.object({ failThresholdMin: z.number().int().min(10).max(1440), knockTtlHours: z.number().int().min(1).max(168) }).parse(req.body);
    setSetting(db, 'check.failThresholdMin', b.failThresholdMin);
    setSetting(db, 'knock.ttlHours', b.knockTtlHours);
    audit(db, who(req), 'settings.general', undefined, b);
    return b;
  });

  // ───── блокировки протоколов на всех узлах (blocks.ts) ─────
  app.get('/api/v1/settings/blocks', async () => blocksOf(db));

  app.put('/api/v1/settings/blocks', { preHandler: guard(ctx, 'settings.edit') }, async (req) => {
    const b = z.object({ bittorrent: z.boolean(), smtp: z.boolean(), quic: z.boolean() }).parse(req.body);
    setSetting(db, 'blocks', b);
    // конфиги всех узлов меняются — синхронизация переприменит их сама (Xray и sing-box перезапустятся на секунды)
    new Vpn(ctx).markDirty();
    audit(db, who(req), 'settings.blocks', undefined, b);
    return blocksOf(db);
  });

  // ───── прокси бота: если api.telegram.org с главного сервера недоступен ─────
  app.get('/api/v1/settings/bot-proxy', async () => ({ ...botProxySetting(ctx), options: botProxyOptions(ctx) }));

  app.put('/api/v1/settings/bot-proxy', { preHandler: guard(ctx, 'settings.edit') }, async (req) => {
    const b = z.object({ enabled: z.boolean(), serverId: z.string().default(''), templateId: z.string().default('') }).parse(req.body);
    if (b.enabled && !botProxyOptions(ctx).some((o) => o.serverId === b.serverId && o.templateId === b.templateId))
      throw new HttpError(400, 'выберите конфигурацию: активную, на протоколе Xray, на сервере флота');
    const prev = botProxySetting(ctx);
    const st = saveBotProxy(ctx, b);
    // служебный клиент бота появляется (или пропадает) в inbound выбранного сервера — переприменяем его сразу
    const ops = new Ops(ctx);
    for (const id of new Set([prev.serverId, st.serverId].filter(Boolean))) {
      const s = ctx.servers().find((x) => x.id === id);
      if (s && s.sudo_mode === 'restricted') await ctx.onNode(s, (n) => ops.applyServer(ctx.server(s.id), n, () => undefined));
    }
    await ctx.mgmt?.ensure().catch(() => undefined);
    audit(db, who(req), 'bot.proxy', undefined, b);
    return { ...st, probe: await deps.bot.probe() };
  });

  app.post('/api/v1/settings/bot-proxy/test', { preHandler: guard(ctx, 'settings.edit') }, async () => deps.bot.probe());

  app.put('/api/v1/settings/bot', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const { token } = z.object({ token: z.string().regex(/^\d+:[A-Za-z0-9_-]{30,}$/, 'неверный формат токена').nullable() }).parse(req.body);
    setSetting(db, 'bot.token', token ? ctx.seal(token) : '');
    let username: string | null = null;
    if (token) username = (await deps.bot.getMe()).username;
    deps.bot.restart();
    audit(db, who(req), 'bot.token_set', undefined, { username });
    return { configured: !!token, username };
  });

  app.put('/api/v1/settings/backup', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const b = z.object({
      recipients: z.array(z.string().trim().regex(/^age1[0-9a-z]{58}$/, 'нужен публичный ключ age1…')).max(8),
      time: z.string().regex(/^\d{2}:\d{2}$/),
      enabled: z.boolean(),
    }).parse(req.body);
    setSetting(db, 'backup', b);
    audit(db, who(req), 'backup.settings', undefined, { recipients: b.recipients.map((r) => r.slice(0, 12) + '…'), time: b.time });
    return b;
  });

  // ───── бэкапы ─────
  app.get('/api/v1/backups', async () => db.prepare('SELECT * FROM backups ORDER BY id DESC LIMIT 50').all());
  app.post('/api/v1/backups/run', { preHandler: guard(ctx, 'backups.run') }, async (req) => deps.backups.run('manual', who(req)));

  // Восстановление из бэкапа в панели: загрузить копию и приватный ключ age → проверить → подтвердить → перезапуск
  app.post('/api/v1/backups/restore/check', { preHandler: guard(ctx, 'owner', { otp: true }), bodyLimit: 400 * 1024 * 1024 }, async (req) => {
    const b = z.object({ file: z.string().min(10), identity: z.string().min(20).max(4000) }).parse(req.body);
    let r;
    try { r = await decryptBackup(Buffer.from(b.file, 'base64'), b.identity); } catch (e) { throw new HttpError(400, (e as Error).message); }
    const summary = stageRestore(config.dataDir, r.manifest, r.files);
    audit(db, who(req), 'backup.restore_check', undefined, { created: summary.created });
    return summary;
  });

  app.post('/api/v1/backups/restore/apply', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req, reply) => {
    try { armRestore(config.dataDir); } catch (e) { throw new HttpError(409, (e as Error).message); }
    audit(db, who(req), 'backup.restore_apply');
    await reply.send({ ok: true });
    // перезапуск: systemd поднимает панель снова (Restart=on-failure), при старте данные подменяются копией
    setTimeout(() => process.exit(75), 500);
  });

  // ───── аудит ─────
  app.get('/api/v1/audit', async () => ({
    chain: verifyAuditChain(db),
    items: db.prepare('SELECT id, ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT 300').all(),
  }));
}
