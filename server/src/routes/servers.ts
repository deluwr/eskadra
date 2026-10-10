import type { FastifyInstance } from 'fastify';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import ssh2 from 'ssh2';
import { Ctx, coreMode, expectedPanelIps, guard, HttpError, type Role, type ServerRow } from '../ctx.js';
import { randomToken, sha256hex } from '../lib/crypto.js';
import { audit } from '../lib/audit.js';
import { bootstrapSnippet } from '../bootstrap.js';
import { credsFields, credsOf, newTunnel, xrayPin } from '../mgmt.js';
import { fetchHostKey, mask, withNodeLock, withSession } from '../ssh/executor.js';
import { parseSections, summarize } from '../preflight.js';
import { buildInstallScript, kitVersion, readKitFile, SUDO_DROP_BOOTSTRAP, SUDO_NARROW_WRITE } from '../nodekit.js';
import { Ops, startJob } from '../ops.js';
import { json } from '../vpn.js';
import { CHECKLIST, renderPlan } from '../firewall.js';

const sshUtils = ssh2.utils;
const ROLES = ['entry', 'relay', 'exit', 'control'] as const;

export function publicView(ctx: Ctx, r: ServerRow) {
  const { key_priv_sealed: _secret, fw_plan: _plan, xui_pass_sealed: _xp, mgmt_key_sealed: _mk, mgmt_uuid: _mu, ...rest } = r;
  return {
    ...rest,
    mgmt: { mode: r.mgmt_mode, port: r.mgmt_port, sni: r.mgmt_sni, localPort: r.mgmt_local_port, client: r.mgmt_mode === 'tunnel' ? ctx.mgmt?.status() ?? null : null },
    external_cores: json(r.external_cores, []),
    coreModeEffective: coreMode(r),
    xuiConfigured: !!r.xui_user && !!r.xui_pass_sealed,
    os_info: json(r.os_info, null),
    ssh_ports: json<number[]>(r.ssh_ports, []),
    admin_ips: json<string[]>(r.admin_ips, []),
    cores: json<Record<string, { version: string }>>(r.cores, {}),
    checklist: json<Record<string, boolean>>(r.checklist, {}),
    stage: stageOf(r),
    executorOk: !r.seen_from_ip || expectedPanelIps(r, ctx.executorIps()).includes(r.seen_from_ip),
  };
}

/** Этапы: 0 ждёт bootstrap · 1 подключён · 2 настроен · 3 проверен · 4 защищён. */
export function stageOf(r: ServerRow): number {
  if (r.fw_mode === 'enforced') return 4;
  if (r.checklist_passed_at) return 3;
  if (r.sudo_mode === 'restricted') return 2;
  if (r.status !== 'pending_bootstrap') return 1;
  return 0;
}

const createBody = z.object({
  name: z.string().trim().min(1).max(64).regex(/^[\p{L}0-9 ._-]+$/u),
  host: z.string().trim().min(1).max(253).regex(/^[a-zA-Z0-9.:-]+$/),
  sshPort: z.coerce.number().int().min(1).max(65535).default(22),
  role: z.enum(ROLES).default('entry'),
  group: z.string().trim().min(1).max(32).default('default'),
  /** Канал управления (§5.8): напрямую по SSH или через служебный туннель VLESS-REALITY. */
  mgmtMode: z.enum(['direct', 'tunnel']).default('direct'),
});

const patchBody = z.object({
  name: z.string().trim().min(1).max(64).optional(),
  role: z.enum(ROLES).optional(),
  group: z.string().trim().min(1).max(32).optional(),
  directAccess: z.boolean().optional(),
  peerSsh: z.enum(['off', 'emergency']).optional(),
  protectionTarget: z.enum(['P1', 'P2', 'P3']).optional(),
  mgmtMode: z.enum(['direct', 'tunnel']).optional(),
});

const RANK: Record<Role, number> = { operator: 1, admin: 2, owner: 3 };

export async function serverRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const ops = new Ops(ctx);
  const who = (req: { admin?: { username: string } }) => req.admin!.username;

  /** Root-операция до сужения sudo — скрипт через bootstrap-sudo; после — операция fleet-exec. */
  async function rootScript(r: ServerRow, op: 'preflight' | 'baseline') {
    return withNodeLock(r.id, () =>
      withSession(ctx.target(r), (s) =>
        r.sudo_mode === 'restricted'
          ? s.exec(`sudo -n /usr/local/sbin/fleet-exec ${op}`, { timeoutMs: 60_000 })
          : s.exec(`sudo -n bash -s -- "$SSH_CONNECTION"`, { stdin: readKitFile(`sbin/fleet-${op}`), timeoutMs: 60_000 }),
      ),
    );
  }

  /** Сниппет под канал узла. В режиме туннеля в нём ключ REALITY узла — поэтому только для admin и выше. */
  async function snippetFor(r: ServerRow, role?: Role): Promise<string | null> {
    if (r.mgmt_mode !== 'tunnel') return bootstrapSnippet({ panelIps: ctx.executorIps(), pubkey: r.key_pub });
    if (role && RANK[role] < RANK.admin) return null;
    const creds = credsOf(ctx, r);
    if (!creds) throw new HttpError(409, 'у узла нет данных служебного туннеля — переключите канал заново');
    const xray = await xrayPin(ctx).catch((e: Error) => {
      throw new HttpError(502, `не удалось получить релиз Xray с GitHub для туннеля: ${e.message}`);
    });
    return bootstrapSnippet({ panelIps: ctx.executorIps(), pubkey: r.key_pub, mgmt: { creds, sshPort: r.ssh_port, xray } });
  }

  const tunnelFields = () => credsFields(ctx, newTunnel(ctx.servers().map((x) => x.mgmt_local_port ?? 0)));

  const requireKit = (r: ServerRow) => {
    if (r.sudo_mode !== 'restricted') throw new HttpError(409, 'сначала установите nodekit (шаг 5)');
  };

  app.get('/api/v1/servers', async () => ctx.servers().map((r) => publicView(ctx, r)));

  app.post('/api/v1/servers', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const body = createBody.parse(req.body);
    const ips = ctx.executorIps();
    // для туннеля адрес исполнителя не обязателен: узел пускает панель по ключу туннеля (§5.8)
    if (!ips.length && body.mgmtMode === 'direct') throw new HttpError(400, 'Сначала задайте адрес исполнителя в настройках (executor.ips)');
    if (db.prepare('SELECT 1 FROM servers WHERE host = ? AND ssh_port = ?').get(body.host, body.sshPort))
      throw new HttpError(409, 'сервер с таким адресом и портом уже есть');
    db.prepare('INSERT OR IGNORE INTO groups (name) VALUES (?)').run(body.group);
    const id = 'srv-' + randomToken(4).toLowerCase().replace(/[^a-z0-9]/g, 'x');
    const keys = sshUtils.generateKeyPairSync('ed25519', { comment: `fleet-panel/${id}` });
    // главный сервер — P1 по умолчанию (защита опциональна), ноды — цель P3 сразу (§7.11.2)
    const target = body.role === 'control' ? 'P1' : 'P3';
    db.prepare(
      `INSERT INTO servers (id, name, host, ssh_port, role, group_name, protection_target, direct_access, key_pub, key_priv_sealed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, body.name, body.host, body.sshPort, body.role, body.group, target, body.role === 'exit' ? 0 : 1, keys.public.trim(), ctx.seal(keys.private));
    if (body.mgmtMode === 'tunnel') ctx.updateServer(id, { mgmt_mode: 'tunnel', ...tunnelFields() });
    audit(db, who(req), 'server.create', id, { host: body.host, port: body.sshPort, role: body.role, mgmt: body.mgmtMode });
    const r = ctx.server(id);
    return { server: publicView(ctx, r), snippet: await snippetFor(r) };
  });

  app.get<{ Params: { id: string } }>('/api/v1/servers/:id', async (req) => {
    const r = ctx.server(req.params.id);
    const pre = db.prepare('SELECT id, created_at, summary FROM preflight_reports WHERE server_id = ? ORDER BY id DESC LIMIT 1').get(r.id) as
      | { id: number; created_at: string; summary: string } | undefined;
    const jobs = db.prepare('SELECT id, kind, status, started_at, finished_at FROM jobs WHERE server_id = ? ORDER BY id DESC LIMIT 20').all(r.id);
    const inbounds = db.prepare(
      `SELECT i.id, i.kind, i.port, i.proto, i.state, i.error, i.applied_at, t.name AS template, t.protocol, t.core
       FROM inbounds i JOIN templates t ON t.id = i.template_id WHERE i.server_id = ? ORDER BY i.port`,
    ).all(r.id);
    return {
      server: publicView(ctx, r),
      snippet: await snippetFor(r, req.admin?.role),
      preflight: pre ? { id: pre.id, created_at: pre.created_at, ...JSON.parse(pre.summary) } : null,
      jobs,
      inbounds,
      checklist: checklistView(r),
      nodekitVersion: kitVersion(),
      kvmCommand: kvmCommand(ctx.executorIps()[0]),
    };
  });

  app.get<{ Params: { id: string } }>('/api/v1/servers/:id/bootstrap.sh', async (req, reply) => {
    const r = ctx.server(req.params.id);
    reply.header('Content-Type', 'text/x-shellscript; charset=utf-8');
    const snip = await snippetFor(r, req.admin?.role);
    if (snip === null) throw new HttpError(403, 'сниппет туннеля содержит ключ узла — нужна роль admin');
    reply.header('Content-Disposition', `attachment; filename="bootstrap-${r.id}.sh"`);
    return snip;
  });

  app.get<{ Params: { id: string; jobId: string } }>('/api/v1/servers/:id/jobs/:jobId', async (req) =>
    db.prepare('SELECT * FROM jobs WHERE id = ? AND server_id = ?').get(Number(req.params.jobId), req.params.id));

  app.patch<{ Params: { id: string } }>('/api/v1/servers/:id', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const r = ctx.server(req.params.id);
    const b = patchBody.parse(req.body);
    if (b.group) db.prepare('INSERT OR IGNORE INTO groups (name) VALUES (?)').run(b.group);
    if (b.mgmtMode && b.mgmtMode !== r.mgmt_mode) {
      if (b.mgmtMode === 'direct' && !ctx.executorIps().length) throw new HttpError(400, 'для прямого канала задайте адрес исполнителя (executor.ips)');
      // ключи туннеля сохраняются при переключениях: повторный сниппет не меняет конфиг узла
      ctx.updateServer(r.id, { mgmt_mode: b.mgmtMode, ...(b.mgmtMode === 'tunnel' && !credsOf(ctx, r) ? tunnelFields() : {}) });
    }
    ctx.updateServer(r.id, {
      ...(b.name ? { name: b.name } : {}),
      ...(b.role ? { role: b.role } : {}),
      ...(b.group ? { group_name: b.group } : {}),
      ...(b.directAccess !== undefined ? { direct_access: b.directAccess ? 1 : 0, config_dirty: 1 } : {}),
      ...(b.peerSsh ? { peer_ssh: b.peerSsh } : {}),
      ...(b.protectionTarget ? { protection_target: b.protectionTarget } : {}),
    });
    audit(db, who(req), 'server.update', r.id, b);
    return publicView(ctx, ctx.server(r.id));
  });

  // ───── подключение (шаги 2–5 runbook) ─────

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/host-key/fetch', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const r = ctx.server(req.params.id);
    const t = ctx.target(r);
    const hk = await fetchHostKey(t.host, t.port, 10_000, t);
    ctx.updateServer(r.id, { host_key_pending_fp: hk.fp, host_key_algo: hk.algo });
    return { fingerprint: hk.fp, algo: hk.algo, pinned: r.host_key_fp };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/host-key/trust', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const r = ctx.server(req.params.id);
    const { fingerprint } = z.object({ fingerprint: z.string() }).parse(req.body);
    if (!r.host_key_pending_fp || r.host_key_pending_fp !== fingerprint.trim())
      throw new HttpError(409, 'fingerprint не совпадает с полученным от сервера — получите ключ заново');
    const rebuild = !!r.host_key_fp && r.host_key_fp !== fingerprint.trim();
    // пересборка узла (новый host key): статус и чек-лист сбрасываются (§18.8)
    ctx.updateServer(r.id, {
      host_key_fp: fingerprint.trim(), host_key_pending_fp: null,
      ...(rebuild ? { status: 'pending_bootstrap', sudo_mode: 'bootstrap', checklist: '{}', checklist_passed_at: null, fw_mode: 'observe', cores: '{}', ssh_mode: 'loose' } : {}),
    });
    audit(db, who(req), rebuild ? 'server.host_key_repinned' : 'server.host_key_pinned', r.id, { fingerprint });
    return { ok: true, rebuild };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/check', async (req) => {
    const r = ctx.server(req.params.id);
    const res = await withNodeLock(r.id, () => withSession(ctx.target(r), async (s) => {
      if (r.sudo_mode === 'restricted') {
        const w = await s.exec('sudo -n /usr/local/sbin/fleet-exec whoami');
        if (w.code === 0) return { ok: true, conn: w.stdout.split('\n')[0] ?? '', user: 'fleet', err: '' };
        const p = await s.exec('sudo -n /usr/local/sbin/fleet-exec ping');
        return { ok: p.stdout.trim() === 'pong', conn: '', user: 'fleet', err: p.stderr.trim() };
      }
      const w = await s.exec('echo "$SSH_CONNECTION"; id -un');
      const sudo = await s.exec('sudo -n true && echo sudo_ok');
      const [conn, user] = w.stdout.trim().split('\n');
      return { ok: sudo.code === 0, conn: conn ?? '', user: user ?? '', err: sudo.stderr.trim() };
    }));
    const seen = res.conn.split(' ')[0] || r.seen_from_ip;
    ctx.updateServer(r.id, {
      seen_from_ip: seen, last_seen_at: new Date().toISOString(), fail_since: null,
      status: r.status === 'pending_bootstrap' && res.ok ? 'connected' : r.status,
    });
    audit(db, who(req), 'server.check', r.id, { ok: res.ok, seen });
    return { ok: res.ok, user: res.user, seenFromIp: seen, sudo: res.ok ? 'ok' : res.err };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/preflight', async (req) => {
    const r = ctx.server(req.params.id);
    const job = startJob(ctx, r.id, 'preflight');
    try {
      const pre = await rootScript(r, 'preflight');
      const base = await rootScript(r, 'baseline');
      if (pre.code !== 0) throw new Error(`preflight exit ${pre.code}: ${pre.stderr}`);
      job.log(`baseline: ${base.code === 0 ? base.stdout.trim() : 'FAILED ' + base.stderr.trim()}`);
      const summary = summarize(pre.stdout, expectedPanelIps(r, ctx.executorIps()));
      const kernel = (parseSections(pre.stdout).get('kernel') ?? '').split('\n');
      const arch = /aarch64|arm64/.test(kernel[1] ?? '') ? 'arm64' : 'amd64';
      db.prepare('INSERT INTO preflight_reports (server_id, summary, raw) VALUES (?, ?, ?)').run(
        r.id, JSON.stringify({ ...summary, baselinePath: base.stdout.trim() }), pre.stdout);
      ctx.updateServer(r.id, {
        os_info: JSON.stringify(summary.os), ssh_ports: JSON.stringify(summary.sshPorts), ufw_active: summary.ufwActive ? 1 : 0,
        external_cores: JSON.stringify(summary.externalCores),
        arch, last_seen_at: new Date().toISOString(), ...(summary.clientIp ? { seen_from_ip: summary.clientIp } : {}),
      });
      job.log(`checks: ${summary.checks.map((c) => `${c.id}=${c.status}`).join(' ')}`);
      job.finish('ok');
      audit(db, who(req), 'server.preflight', r.id, { blocking: summary.blocking });
      return { ...summary, baselinePath: base.stdout.trim() };
    } catch (e) {
      job.log(`error: ${(e as Error).message}`);
      job.finish('failed');
      throw e;
    }
  });

  /**
   * Шаг 3: nodekit + сужение sudo + строгий режим ключа.
   * Если узел уже сужен, но nodekit устарел и не умеет kit-install, нужен повторный bootstrap-сниппет:
   * он вернёт временный широкий sudo, и установка пройдёт заново.
   */
  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/nodekit/install', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const r = ctx.server(req.params.id);
    const job = startJob(ctx, r.id, 'nodekit.install');
    const t = ctx.target(r);
    try {
      const wide = await withNodeLock(r.id, () => withSession(t, (s) => s.exec('sudo -n true')));
      if (wide.code !== 0) {
        if (r.sudo_mode !== 'restricted') throw new Error('нет ни bootstrap-sudo, ни fleet-exec: выполните bootstrap-сниппет');
        await ctx.onNode(r, (n) => ops.ensureKit(r, n, job.log));
      } else {
        await withNodeLock(r.id, () => withSession(t, async (s) => {
          const inst = await s.exec('sudo -n bash -s', { stdin: buildInstallScript(), timeoutMs: 600_000 });
          job.log(mask(`install: exit ${inst.code}\n${inst.stdout}${inst.stderr}`, [t.privateKey]));
          if (inst.code !== 0) throw new Error('nodekit install failed');
          const w = await s.exec('sudo -n bash -s', { stdin: SUDO_NARROW_WRITE });
          job.log(`sudoers 90-fleet: exit ${w.code} ${w.stdout.trim()} ${w.stderr.trim()}`);
          if (w.code !== 0) throw new Error('writing 90-fleet failed');
          const ping = await s.exec('sudo -n /usr/local/sbin/fleet-exec ping');
          if (ping.stdout.trim() !== 'pong') throw new Error('fleet-exec ping failed — широкий sudo НЕ удалён');
          const drop = await s.exec('sudo -n bash -s', { stdin: SUDO_DROP_BOOTSTRAP });
          job.log(`drop 90-fleet-bootstrap: ${drop.stdout.trim()} ${drop.stderr.trim()}`);
          if (drop.code !== 0) throw new Error('could not drop bootstrap sudo');
        }));
      }
      // Строгий режим: ключ панели — только через fleet-gate. Проверяем НОВОЙ сессией.
      await ctx.onNode(r, (n) => n.must(['ssh-mode', 'strict']));
      const verify = await withSession(t, async (s) => ({
        wide: await s.exec('sudo -n true'),
        raw: await s.exec('id -un'),
        ping: await s.exec('sudo -n /usr/local/sbin/fleet-exec ping'),
        ver: await s.exec('sudo -n /usr/local/sbin/fleet-exec version'),
      }));
      const ok = verify.wide.code !== 0 && verify.raw.code !== 0 && verify.ping.stdout.trim() === 'pong';
      job.log(`verify: wide sudo ${verify.wide.code === 0 ? 'STILL WORKS' : 'denied'}; raw shell ${verify.raw.code === 0 ? 'STILL WORKS' : 'denied'}; fleet-exec ${verify.ping.stdout.trim()}; version ${verify.ver.stdout.trim()}`);
      if (!ok) throw new Error('строгий режим не подтвердился: широкий sudo или shell всё ещё доступны');
      ctx.updateServer(r.id, {
        sudo_mode: 'restricted', ssh_mode: 'strict', kit_version: verify.ver.stdout.trim(),
        status: r.status === 'connected' ? 'configured' : r.status,
      });
      job.finish('ok');
      audit(db, who(req), 'server.nodekit_installed', r.id, { version: verify.ver.stdout.trim() });
      // новая нода попадает в наборы соседей (§7.12.1)
      void ops.peerSync(() => undefined);
      return { ok: true, version: verify.ver.stdout.trim(), jobId: job.id };
    } catch (e) {
      job.log(`error: ${(e as Error).message}`);
      job.finish('failed');
      throw new HttpError(500, (e as Error).message, { jobId: job.id });
    }
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/status', async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const out = await ctx.onNode(r, async (n) => ({
      status: await n.op(['status']),
      xray: await n.op(['core-status', 'xray']),
      sb: await n.op(['core-status', 'sing-box']),
      fw: await n.op(['fw-state']),
      c3: await n.op(['sshd-harden', 'status']),
    }));
    ctx.updateServer(r.id, { last_seen_at: new Date().toISOString(), key_only: out.c3.stdout.trim() === 'on' ? 1 : 0 });
    return {
      output: out.status.stdout + out.status.stderr,
      xray: out.xray.stdout, singbox: out.sb.stdout,
      fwState: out.fw.stdout.trim(), keyOnly: out.c3.stdout.trim() === 'on',
    };
  });

  // ───── ядра: свой Xray или Xray уже установленного 3x-ui ─────

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/core-mode', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const r = ctx.server(req.params.id);
    const { mode } = z.object({ mode: z.enum(['auto', 'own', 'xui']) }).parse(req.body);
    if (db.prepare(`SELECT 1 FROM inbounds WHERE server_id = ? AND state IN ('active','deploying')`).get(r.id))
      throw new HttpError(409, 'на узле есть активные конфигурации — сначала снимите их, затем меняйте режим ядра');
    ctx.updateServer(r.id, { core_mode: mode });
    audit(db, who(req), 'server.core_mode', r.id, { mode });
    return publicView(ctx, ctx.server(r.id));
  });

  /** Логин и пароль 3x-ui: проверяются входом на самом узле и хранятся зашифрованными. */
  app.put<{ Params: { id: string } }>('/api/v1/servers/:id/xui', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const b = z.object({ user: z.string().min(1).max(128), pass: z.string().min(1).max(256) }).parse(req.body);
    const probe = { ...r, xui_user: b.user, xui_pass_sealed: ctx.seal(b.pass) };
    const info = await ctx.onNode(r, async (n) => {
      const i = await ops.xui<{ port: number; base: string; version: string | null }>(probe, n, 'info');
      await ops.xui(probe, n, 'list'); // проверка входа
      return i;
    });
    const cores = json<Record<string, unknown>>(r.cores, {});
    cores.xui = { version: (info as { xrayVersion?: string }).xrayVersion ?? '?', panel: info.version };
    ctx.updateServer(r.id, { xui_user: b.user, xui_pass_sealed: probe.xui_pass_sealed, cores: JSON.stringify(cores) });
    audit(db, who(req), 'server.xui_credentials', r.id, { user: b.user, version: info.version });
    return { ok: true, info };
  });

  /** «Удалить или дополнить»: удалить 3x-ui с узла (база сохраняется в baseline узла). */
  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/xui-remove', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    if (db.prepare(`SELECT 1 FROM inbounds WHERE server_id = ? AND state IN ('active','deploying')`).get(r.id) && coreMode(r) === 'xui')
      throw new HttpError(409, 'на узле активны inbounds Эскадры внутри 3x-ui — сначала снимите их с узла');
    const out = await ctx.onNode(r, (n) => n.must(['xui-remove'], { timeoutMs: 120_000 }));
    const ext = json<Array<{ name: string }>>(r.external_cores, []).filter((c) => c.name !== '3x-ui');
    const cores = json<Record<string, unknown>>(r.cores, {});
    delete cores.xui;
    ctx.updateServer(r.id, { external_cores: JSON.stringify(ext), core_mode: 'auto', xui_user: null, xui_pass_sealed: null, cores: JSON.stringify(cores) });
    audit(db, who(req), 'server.xui_removed', r.id);
    return { output: out.trim() };
  });

  /** Остановить стороннее ядро (xray/sing-box как отдельный сервис), чтобы Эскадра могла поставить своё. */
  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/foreign-stop', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const { name } = z.object({ name: z.enum(['xray', 'sing-box', 'v2ray', 'hysteria-server']) }).parse(req.body);
    const out = await ctx.onNode(r, (n) => n.must(['foreign-stop', name]));
    const ext = json<Array<{ name: string; active: string }>>(r.external_cores, []).map((c) => (c.name === name ? { ...c, active: 'inactive' } : c));
    ctx.updateServer(r.id, { external_cores: JSON.stringify(ext) });
    audit(db, who(req), 'server.foreign_core_stopped', r.id, { name });
    return { output: out.trim() };
  });

  // ───── доступ и SSH ─────

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/ssh-mode', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const { mode } = z.object({ mode: z.enum(['strict', 'shell']) }).parse(req.body);
    await ctx.onNode(r, (n) => n.must(['ssh-mode', mode]));
    const ping = await withSession(ctx.target(r), (s) => s.exec('sudo -n /usr/local/sbin/fleet-exec ping'));
    if (ping.stdout.trim() !== 'pong') throw new HttpError(500, 'после смены режима панель не может войти — проверьте узел');
    ctx.updateServer(r.id, { ssh_mode: mode });
    audit(db, who(req), 'server.ssh_mode', r.id, { mode });
    return { ok: true, mode };
  });

  /** Терминал (только в режиме shell): одна команда, без PTY, полностью в аудите. */
  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/exec', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    if (r.ssh_mode !== 'shell') throw new HttpError(409, 'терминал выключен: включите shell на сервере');
    const { command } = z.object({ command: z.string().min(1).max(4000) }).parse(req.body);
    const res = await withNodeLock(r.id, () => withSession(ctx.target(r), (s) => s.exec(command, { timeoutMs: 120_000 })));
    audit(db, who(req), 'server.exec', r.id, { command, code: res.code });
    return res;
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/admin-ips', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    const b = z.object({ ip: z.string().refine((s) => isIP(s) !== 0, 'неверный IP'), remove: z.boolean().default(false) }).parse(req.body);
    const list = new Set(json<string[]>(r.admin_ips, []));
    if (r.sudo_mode === 'restricted') await ctx.onNode(r, (n) => n.must([b.remove ? 'admin-del' : 'admin-add', b.ip]));
    if (b.remove) list.delete(b.ip); else list.add(b.ip);
    ctx.updateServer(r.id, { admin_ips: JSON.stringify([...list]) });
    audit(db, who(req), b.remove ? 'server.admin_ip_del' : 'server.admin_ip_add', r.id, { ip: b.ip });
    return { adminIps: [...list] };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/relax', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const { duration } = z.object({ duration: z.enum(['30m', '1h', '2h', 'off']) }).parse(req.body);
    const out = await ctx.onNode(r, (n) => (duration === 'off' ? n.must(['unrelax']) : n.must(['relax', duration])));
    audit(db, who(req), 'server.relax', r.id, { duration });
    return { output: out.trim() };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/emergency-open', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const out = await ctx.onNode(r, (n) => n.must(['fw-open']));
    ctx.updateServer(r.id, { fw_mode: 'observe', protection_current: 'P1', fw_pending_until: null });
    audit(db, who(req), 'server.emergency_open', r.id);
    return { output: out.trim() };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/ufw-disable', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const out = await ctx.onNode(r, (n) => n.must(['ufw-disable']));
    ctx.updateServer(r.id, { ufw_active: 0 });
    audit(db, who(req), 'server.ufw_disabled', r.id);
    return { output: out.trim() };
  });

  /** C3: SSH только по ключам — под таймером отката 180 с, затем подтверждение. */
  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/key-only', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const { action } = z.object({ action: z.enum(['apply', 'confirm', 'rollback']) }).parse(req.body);
    const out = await ctx.onNode(r, (n) => n.must(['sshd-harden', action]));
    if (action === 'apply') {
      const ping = await withSession(ctx.target(r), (s) => s.exec('sudo -n /usr/local/sbin/fleet-exec ping'));
      if (ping.stdout.trim() !== 'pong') throw new HttpError(500, 'новая сессия не открылась — откат сработает сам через 180 с');
    }
    if (action === 'confirm') ctx.updateServer(r.id, { key_only: 1 });
    if (action === 'rollback') ctx.updateServer(r.id, { key_only: 0 });
    audit(db, who(req), `server.key_only_${action}`, r.id);
    return { output: out.trim() };
  });

  /** Break-glass: консольный пользователь fleetadmin, пароль показывается один раз и нигде не хранится. */
  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/fleetadmin', { preHandler: guard(ctx, 'owner', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const password = randomBytes(12).toString('base64').replace(/[+/=]/g, '').slice(0, 16);
    await ctx.onNode(r, (n) => n.must(['fleetadmin-setup'], { stdin: password + '\n' }));
    audit(db, who(req), 'server.fleetadmin_setup', r.id);
    return { username: 'fleetadmin', password };
  });

  // ───── чек-лист (шаг 4) ─────

  function autoChecks(r: ServerRow): Record<string, boolean> {
    const peerFail = db.prepare(`SELECT 1 FROM peer_checks WHERE (from_id = ? OR to_id = ?) AND result = 'fail'`).get(r.id, r.id);
    return {
      panel_ssh: !!r.last_seen_at && !r.fail_since && r.sudo_mode === 'restricted',
      mesh: !peerFail,
      executor: !!r.seen_from_ip && expectedPanelIps(r, ctx.executorIps()).includes(r.seen_from_ip),
    };
  }

  function checklistView(r: ServerRow) {
    const marks = json<Record<string, boolean>>(r.checklist, {});
    const auto = autoChecks(r);
    const items = CHECKLIST.map((c) => ({ ...c, done: c.auto ? !!auto[c.id] : !!marks[c.id] }));
    return { items, passedAt: r.checklist_passed_at, done: items.filter((i) => i.done).length, total: items.length };
  }

  app.put<{ Params: { id: string } }>('/api/v1/servers/:id/checklist', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    const marks = z.record(z.string(), z.boolean()).parse(req.body);
    const clean = Object.fromEntries(Object.entries(marks).filter(([k]) => CHECKLIST.some((c) => c.id === k && !c.auto)));
    ctx.updateServer(r.id, { checklist: JSON.stringify(clean) });
    const view = checklistView(ctx.server(r.id));
    const passed = view.done === view.total;
    ctx.updateServer(r.id, { checklist_passed_at: passed ? r.checklist_passed_at ?? new Date().toISOString() : null });
    if (passed && !r.checklist_passed_at) audit(db, who(req), 'server.checklist_passed', r.id);
    return checklistView(ctx.server(r.id));
  });

  // ───── firewall: план → shadow → применение под таймером → подтверждение (§7) ─────

  const levelOf = (r: ServerRow, b: unknown) => {
    const lvl = z.object({ level: z.enum(['P2', 'P3']).optional() }).parse(b ?? {}).level;
    const target = lvl ?? (r.protection_target === 'P1' ? null : (r.protection_target as 'P2' | 'P3'));
    if (!target) throw new HttpError(409, 'целевой уровень P1 — блокировки не нужны');
    return target;
  };

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/fw/plan', async (req) => {
    const r = ctx.server(req.params.id);
    const plan = renderPlan(ctx, r, levelOf(r, req.body));
    ctx.updateServer(r.id, { fw_plan: plan.text, fw_plan_hash: sha256hex(plan.text) });
    return plan;
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/fw/shadow', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const plan = renderPlan(ctx, r, levelOf(r, req.body));
    if (plan.lint.length) throw new HttpError(409, 'план не прошёл линтер', { lint: plan.lint });
    await ctx.onNode(r, async (n) => {
      const name = `shadow-${Date.now()}.nft`;
      await n.stage(name, plan.shadow);
      await n.must(['fw-plan-check', name]);
      await n.must(['fw-apply', name, 120]);
      await n.must(['fw-confirm']);
    });
    ctx.updateServer(r.id, { fw_mode: 'shadow' });
    audit(db, who(req), 'server.fw_shadow', r.id);
    return { ok: true };
  });

  app.get<{ Params: { id: string }; Querystring: { minutes?: string } }>('/api/v1/servers/:id/fw/shadow-log', async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const minutes = Math.min(10080, Math.max(1, Number(req.query.minutes ?? 60)));
    const out = await ctx.onNode(r, (n) => n.op(['fw-shadow-log', minutes]));
    const hits = new Map<string, number>();
    for (const line of out.stdout.split('\n')) {
      const src = line.match(/SRC=(\S+)/)?.[1];
      const dpt = line.match(/DPT=(\d+)/)?.[1];
      const proto = line.match(/PROTO=(\S+)/)?.[1];
      if (!src) continue;
      const key = `${src} → ${proto ?? '?'}/${dpt ?? '-'}`;
      hits.set(key, (hits.get(key) ?? 0) + 1);
    }
    return { minutes, top: [...hits.entries()].sort((a, b) => b[1] - a[1]).slice(0, 50).map(([k, n]) => ({ flow: k, count: n })) };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/fw/apply', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    if (!r.checklist_passed_at) throw new HttpError(409, 'сначала пройдите ручной чек-лист');
    const b = z.object({ level: z.enum(['P2', 'P3']).optional(), window: z.number().int().min(120).max(600).default(120) }).parse(req.body ?? {});
    const plan = renderPlan(ctx, r, levelOf(r, b));
    if (plan.lint.length) throw new HttpError(409, 'план не прошёл линтер', { lint: plan.lint });
    await ctx.onNode(r, async (n) => {
      const name = `plan-${Date.now()}.nft`;
      await n.stage(name, plan.text);
      await n.must(['fw-plan-check', name]);
      await n.must(['fw-apply', name, b.window]);
    });
    // машинная часть подтверждения: НОВАЯ сессия проходит
    const ping = await withSession(ctx.target(r), (s) => s.exec('sudo -n /usr/local/sbin/fleet-exec ping')).catch(() => null);
    const until = new Date(Date.now() + b.window * 1000).toISOString();
    ctx.updateServer(r.id, { fw_mode: 'pending', fw_pending_until: until, fw_plan: plan.text, fw_plan_hash: sha256hex(plan.text) });
    audit(db, who(req), 'server.fw_apply', r.id, { level: plan.summary.level, window: b.window });
    return { pendingUntil: until, newSessionOk: ping?.stdout.trim() === 'pong', level: plan.summary.level };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/fw/confirm', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const out = await ctx.onNode(r, (n) => n.op(['fw-confirm']));
    if (out.code !== 0) {
      ctx.updateServer(r.id, { fw_mode: 'observe', fw_pending_until: null });
      throw new HttpError(409, 'подтверждать нечего: таймер уже откатил правила');
    }
    const level = /saddr @panel4 tcp dport/.test(r.fw_plan ?? '') ? 'P3' : 'P2';
    ctx.updateServer(r.id, { fw_mode: 'enforced', protection_current: level, fw_pending_until: null, status: 'enforced' });
    audit(db, who(req), 'server.fw_confirmed', r.id, { level });
    return { ok: true, level };
  });

  app.post<{ Params: { id: string } }>('/api/v1/servers/:id/fw/rollback', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const r = ctx.server(req.params.id);
    requireKit(r);
    const out = await ctx.onNode(r, (n) => n.op(['fw-rollback']));
    ctx.updateServer(r.id, { fw_mode: 'observe', fw_pending_until: null });
    audit(db, who(req), 'server.fw_rollback', r.id);
    return { output: out.stdout.trim() };
  });

  app.delete<{ Params: { id: string } }>('/api/v1/servers/:id', { preHandler: guard(ctx, 'admin', { otp: true }) }, async (req) => {
    const r = ctx.server(req.params.id);
    db.prepare('DELETE FROM servers WHERE id = ?').run(r.id);
    audit(db, who(req), 'server.delete', r.id, { host: r.host });
    return { ok: true };
  });
}

export function kvmCommand(ip?: string): string | null {
  if (!ip || isIP(ip) !== 4) return ip ? `sudo fleetctl allow ${ip}` : null;
  return `sudo fleetctl allow ${ip.split('.').join(' ')}`;
}
