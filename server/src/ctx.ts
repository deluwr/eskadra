import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Db } from './db.js';
import { getSetting } from './db.js';
import type { Sealer } from './lib/crypto.js';
import { verifyTotp } from './lib/totp.js';
import { withNodeLock, withSession, type ExecResult, type SshSession, type SshTarget } from './ssh/executor.js';

export type Role = 'owner' | 'admin' | 'operator';

export interface ServerRow {
  id: string; name: string; host: string; ssh_port: number; ssh_user: string; role: string; status: string;
  key_pub: string; key_priv_sealed: string; host_key_fp: string | null; host_key_pending_fp: string | null;
  host_key_algo: string | null; sudo_mode: 'bootstrap' | 'restricted'; protection_target: string; fw_mode: string;
  seen_from_ip: string | null; os_info: string | null; last_seen_at: string | null; created_at: string; updated_at: string;
  group_name: string; direct_access: number; peer_ssh: string; ssh_mode: 'loose' | 'strict' | 'shell'; ssh_ports: string | null;
  protection_current: string; key_only: number; ufw_active: number; checklist: string; checklist_passed_at: string | null;
  fail_since: string | null; cores: string; fw_plan: string | null; fw_plan_hash: string | null; fw_pending_until: string | null;
  admin_ips: string; kit_version: string | null; config_dirty: number; arch: string | null;
  core_mode: 'auto' | 'own' | 'xui'; xui_user: string | null; xui_pass_sealed: string | null; external_cores: string;
}

export interface ExternalCore { name: string; active: string; version: string }

/**
 * Как узел держит Xray: 'xui' — inbounds Эскадры живут в Xray уже установленного 3x-ui (второй Xray не запускается);
 * 'own' — своё ядро eskadra-xray. В режиме auto выбирается xui, если на узле найден 3x-ui.
 */
export function coreMode(s: ServerRow): 'own' | 'xui' {
  if (s.core_mode !== 'auto') return s.core_mode;
  const ext = JSON.parse(s.external_cores || '[]') as ExternalCore[];
  return ext.some((e) => e.name === '3x-ui') ? 'xui' : 'own';
}

/** Чужие ядра того же типа, что не дают запустить своё (конфликт за порты и ресурсы). */
export function foreignCore(s: ServerRow, core: 'xray' | 'sing-box'): ExternalCore | undefined {
  const ext = JSON.parse(s.external_cores || '[]') as ExternalCore[];
  const names = core === 'xray' ? ['xray', 'v2ray', 'marzban-node', 'amnezia-xray', '3x-ui'] : ['sing-box', 'hysteria-server'];
  return ext.find((e) => names.includes(e.name) && e.active === 'active') ?? ext.find((e) => e.name.startsWith('docker:') && new RegExp(core === 'xray' ? 'xray|marzban|x-ui' : 'sing-box|hiddify', 'i').test(e.name));
}

export interface TemplateRow {
  id: string; name: string; core: 'xray' | 'sing-box'; protocol: 'vless-reality' | 'hysteria2'; port: number;
  sni: string; fingerprint: string; ech: number; node_ids: string; entry_id: string | null; entry_port: number | null;
  revision: number; applied_revision: number; created_at: string; updated_at: string;
}

export interface InboundRow {
  id: string; template_id: string; server_id: string; kind: 'direct' | 'relay'; port: number; proto: 'tcp' | 'udp';
  state: string; private_key_sealed: string | null; public_key: string | null; short_id: string | null;
  tls_pin: string | null; error: string | null; applied_at: string | null; ext_id: number | null;
}

export interface UserRow {
  id: string; name: string; tg_id: string | null; status: 'active' | 'disabled'; limit_group: string;
  traffic_limit_gb: number | null; expire_at: string | null; device_limit: number | null; over_action: string;
  modes: string; node_ids: string | null; wl_mode: 'exact' | 'prefix' | 'asn'; sub_token: string; knock_token: string;
  disabled_reason: string | null; created_at: string;
}

export class HttpError extends Error {
  constructor(readonly statusCode: number, message: string, readonly extra?: Record<string, unknown>) {
    super(message);
  }
}

/** Общий контекст: база, шифрование секретов, доступ к узлам. */
export class Ctx {
  constructor(readonly db: Db, readonly sealer: Sealer) {}

  server(id: string): ServerRow {
    const r = this.db.prepare('SELECT * FROM servers WHERE id = ?').get(id) as ServerRow | undefined;
    if (!r) throw new HttpError(404, 'сервер не найден');
    return r;
  }

  servers(): ServerRow[] {
    return this.db.prepare('SELECT * FROM servers ORDER BY created_at').all() as unknown as ServerRow[];
  }

  updateServer(id: string, fields: Partial<ServerRow>) {
    const keys = Object.keys(fields);
    if (!keys.length) return;
    this.db
      .prepare(`UPDATE servers SET ${keys.map((k) => `${k} = ?`).join(', ')}, updated_at = datetime('now') WHERE id = ?`)
      .run(...keys.map((k) => (fields as Record<string, string | number | null>)[k] ?? null), id);
  }

  executorIps = () => getSetting<string[]>(this.db, 'executor.ips', []);

  target(r: ServerRow): SshTarget {
    return {
      host: r.host,
      port: r.ssh_port,
      username: r.ssh_user,
      privateKey: this.sealer.open(r.key_priv_sealed).toString('utf8'),
      hostKeyFp: r.host_key_fp,
    };
  }

  /** Сессия к узлу под блокировкой «одна операция на узел». */
  onNode<T>(r: ServerRow, fn: (s: NodeSession) => Promise<T>): Promise<T> {
    return withNodeLock(r.id, () => withSession(this.target(r), (s) => fn(new NodeSession(s))));
  }

  seal = (s: string) => this.sealer.seal(s);
  open = (s: string) => this.sealer.open(s).toString('utf8');
}

const SAFE_ARG = /^[A-Za-z0-9._:/@=,-]+$/;

/** Вызовы fleet-exec в форме, которую пропускает строгий режим (fleet-gate). */
export class NodeSession {
  constructor(readonly ssh: SshSession) {}

  async op(args: (string | number)[], opts: { stdin?: string | Buffer; timeoutMs?: number } = {}): Promise<ExecResult> {
    const parts = args.map(String);
    for (const a of parts) if (!SAFE_ARG.test(a)) throw new Error(`unsafe fleet-exec argument: ${a}`);
    return this.ssh.exec(`sudo -n /usr/local/sbin/fleet-exec ${parts.join(' ')}`, opts);
  }

  /** Операция, которая должна завершиться успешно; иначе — ошибка с выводом узла. */
  async must(args: (string | number)[], opts: { stdin?: string | Buffer; timeoutMs?: number } = {}): Promise<string> {
    const r = await this.op(args, opts);
    if (r.code !== 0) throw new Error(`${args[0]}: ${(r.stderr || r.stdout).trim() || 'exit ' + r.code}`);
    return r.stdout;
  }

  async stage(name: string, content: string | Buffer): Promise<void> {
    await this.must(['stage', name], { stdin: content });
  }
}

const RANK: Record<Role, number> = { operator: 1, admin: 2, owner: 3 };

declare module 'fastify' {
  interface FastifyRequest {
    admin?: { id: number; username: string; role: Role; totp: boolean; totpSecret: string | null; console?: boolean };
  }
}

/**
 * Проверка роли и, для чувствительных операций, кода 2FA (заголовок X-Fleet-OTP).
 * Если у админа 2FA не включена, операция разрешена, но UI показывает предупреждение (§14.3).
 */
export function guard(ctx: Ctx, min: Role, opts: { otp?: boolean } = {}) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const a = req.admin;
    if (!a) return reply.code(401).send({ error: 'unauthorized' });
    if (RANK[a.role] < RANK[min]) return reply.code(403).send({ error: `нужна роль ${min} или выше` });
    // консольная сессия создаётся root-ом на самом сервере (eskadra) — код 2FA там не спрашиваем
    if (opts.otp && a.totp && !a.console) {
      const code = String(req.headers['x-fleet-otp'] ?? '');
      if (!a.totpSecret || !verifyTotp(a.totpSecret, code)) return reply.code(428).send({ error: 'нужен код 2FA', kind: 'otp' });
    }
  };
}
