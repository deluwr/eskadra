import { randomUUID } from 'node:crypto';
import type { Ctx, InboundRow, ServerRow, TemplateRow, UserRow } from './ctx.js';

export const json = <T>(s: string | null | undefined, fallback: T): T => {
  if (!s) return fallback;
  try { return JSON.parse(s) as T; } catch { return fallback; }
};

export interface Profile {
  key: string;            // стабильный идентификатор профиля
  name: string;           // как видит пользователь в клиенте
  mode: 'direct' | 'via' | 'auto';
  template: TemplateRow;
  host: string;           // куда подключается клиент
  port: number;
  credKey: string;        // ключ учётных данных пользователя
  inbound: InboundRow;    // inbound, к которому подключается клиент
  targetName: string;
}

export class Vpn {
  constructor(private readonly ctx: Ctx) {}

  private get db() { return this.ctx.db; }

  templates(): TemplateRow[] {
    return this.db.prepare('SELECT * FROM templates ORDER BY created_at').all() as unknown as TemplateRow[];
  }

  inbounds(where = '1=1', ...args: string[]): InboundRow[] {
    return this.db.prepare(`SELECT * FROM inbounds WHERE ${where}`).all(...args) as unknown as InboundRow[];
  }

  users(activeOnly = false): UserRow[] {
    return this.db
      .prepare(`SELECT * FROM users ${activeOnly ? "WHERE status = 'active'" : ''} ORDER BY created_at`)
      .all() as unknown as UserRow[];
  }

  /** UUID пользователя для профиля; создаётся при первом обращении, хранится зашифрованным. */
  cred(userId: string, key: string): string {
    const row = this.db.prepare('SELECT secret_sealed FROM user_creds WHERE user_id = ? AND key = ?').get(userId, key) as
      | { secret_sealed: string } | undefined;
    if (row) return this.ctx.open(row.secret_sealed);
    const id = randomUUID();
    this.db.prepare('INSERT INTO user_creds (user_id, key, secret_sealed) VALUES (?, ?, ?)').run(userId, key, this.ctx.seal(id));
    return id;
  }

  /** «Перевыпустить ссылки»: новые UUID, старые ссылки перестают работать. */
  rotateCreds(userId: string) {
    this.db.prepare('DELETE FROM user_creds WHERE user_id = ?').run(userId);
  }

  svcCred(key: string): string {
    const row = this.db.prepare('SELECT secret_sealed FROM service_creds WHERE key = ?').get(key) as { secret_sealed: string } | undefined;
    if (row) return this.ctx.open(row.secret_sealed);
    const id = randomUUID();
    this.db.prepare('INSERT INTO service_creds (key, secret_sealed) VALUES (?, ?)').run(key, this.ctx.seal(id));
    return id;
  }

  userAllows(u: UserRow, serverId: string): boolean {
    const ids = json<string[] | null>(u.node_ids, null);
    return !ids || ids.includes(serverId);
  }

  /** Все профили пользователя: напрямую к каждому узлу и через вход (§12.5). */
  profiles(u: UserRow): Profile[] {
    const modes = json<string[]>(u.modes, ['direct', 'via']);
    const servers = new Map(this.ctx.servers().map((s) => [s.id, s]));
    const out: Profile[] = [];
    const templates = this.templates();
    for (const t of templates) {
      const suffix = templates.length > 1 ? ` · ${t.name}` : '';
      for (const ib of this.inbounds(`template_id = ? AND state = 'active'`, t.id)) {
        const s = servers.get(ib.server_id);
        if (!s) continue;
        if (ib.kind === 'direct' && modes.includes('direct') && s.direct_access && this.userAllows(u, s.id)) {
          out.push({ key: `d:${t.id}:${s.id}`, name: `${s.name} · напрямую${suffix}`, mode: 'direct', template: t,
            host: s.host, port: ib.port, credKey: `t:${t.id}`, inbound: ib, targetName: s.name });
        }
        if (ib.kind === 'relay' && modes.includes('via')) {
          const targets = this.relayTargets(t).filter((x) => this.userAllows(u, x.id));
          if (!targets.length) continue;
          out.push({ key: `v:${t.id}:auto`, name: `Авто · через вход${suffix}`, mode: 'auto', template: t,
            host: s.host, port: ib.port, credKey: `v:${t.id}:auto`, inbound: ib, targetName: 'auto' });
          for (const x of targets)
            out.push({ key: `v:${t.id}:${x.id}`, name: `${x.name} · через вход${suffix}`, mode: 'via', template: t,
              host: s.host, port: ib.port, credKey: `v:${t.id}:${x.id}`, inbound: ib, targetName: x.name });
        }
      }
    }
    return out;
  }

  /** Узлы, на которые ведёт вход шаблона: его direct-узлы с активным inbound, кроме самого входа. */
  relayTargets(t: TemplateRow): ServerRow[] {
    const active = new Set(this.inbounds(`template_id = ? AND kind = 'direct' AND state = 'active'`, t.id).map((i) => i.server_id));
    return this.ctx.servers().filter((s) => s.id !== t.entry_id && active.has(s.id));
  }

  link(u: UserRow, p: Profile): string {
    const t = p.template;
    const sni = json<string[]>(t.sni, [])[0] ?? '';
    const secret = this.cred(u.id, p.credKey);
    const tag = encodeURIComponent(p.name);
    if (t.protocol === 'hysteria2') {
      const q = new URLSearchParams({ sni, insecure: '1', ...(p.inbound.tls_pin ? { pinSHA256: p.inbound.tls_pin } : {}) });
      return `hysteria2://${secret}@${hostForUri(p.host)}:${p.port}/?${q}#${tag}`;
    }
    const q = new URLSearchParams({
      encryption: 'none', flow: 'xtls-rprx-vision', security: 'reality', sni, fp: t.fingerprint,
      pbk: p.inbound.public_key ?? '', sid: p.inbound.short_id ?? '', type: 'tcp',
    });
    return `vless://${secret}@${hostForUri(p.host)}:${p.port}?${q}#${tag}`;
  }

  // ───── рендер конфигов узла ─────

  /** Конфиг Xray для узла: все xray-inbounds узла (direct и relay), клиенты, маршруты входа. */
  renderXray(server: ServerRow): object | null {
    const ibs = this.inbounds(`server_id = ? AND state IN ('active','deploying')`, server.id)
      .filter((i) => this.template(i.template_id)?.core === 'xray');
    if (!ibs.length) return null;
    const users = this.users(true);
    const inbounds: object[] = [
      { tag: 'api', listen: '127.0.0.1', port: 10085, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' } },
    ];
    const outbounds: object[] = [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }];
    const rules: object[] = [{ type: 'field', inboundTag: ['api'], outboundTag: 'api' }, { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' }];
    const balancers: object[] = [];

    for (const ib of ibs) {
      const t = this.template(ib.template_id)!;
      const sni = json<string[]>(t.sni, []);
      let clients: Array<{ id: string; email: string; flow: string }> = [];
      if (ib.kind === 'direct') {
        clients = this.directClients(server, t, users);
      } else {
        const targets = this.relayTargets(t);
        for (const x of targets) {
          const outTag = `to-${t.id}-${x.id}`;
          const xi = this.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct'`, t.id, x.id)[0];
          if (!xi?.public_key) continue;
          outbounds.push({
            tag: outTag, protocol: 'vless',
            settings: { vnext: [{ address: x.host, port: xi.port, users: [{ id: this.svcCred(`relay:${t.id}:${server.id}:${x.id}`), encryption: 'none', flow: 'xtls-rprx-vision' }] }] },
            streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: sni[0] ?? '', fingerprint: t.fingerprint, publicKey: xi.public_key, shortId: xi.short_id ?? '' } },
          });
          const emails: string[] = [];
          for (const u of users)
            if (json<string[]>(u.modes, []).includes('via') && this.userAllows(u, x.id)) {
              const email = `${u.id}.v-${x.id}`;
              clients.push({ id: this.cred(u.id, `v:${t.id}:${x.id}`), email, flow: 'xtls-rprx-vision' });
              emails.push(email);
            }
          if (emails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: emails, outboundTag: outTag });
        }
        if (targets.length) {
          const autoEmails: string[] = [];
          for (const u of users)
            if (json<string[]>(u.modes, []).includes('via')) {
              const email = `${u.id}.a-${t.id}`;
              clients.push({ id: this.cred(u.id, `v:${t.id}:auto`), email, flow: 'xtls-rprx-vision' });
              autoEmails.push(email);
            }
          balancers.push({ tag: `bal-${t.id}`, selector: [`to-${t.id}-`], strategy: { type: 'random' } });
          if (autoEmails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: autoEmails, balancerTag: `bal-${t.id}` });
        }
        // всё прочее с входа, не попавшее в правила, не выпускаем наружу с самого входа
        rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], outboundTag: 'block' });
      }
      inbounds.push({
        tag: `in-${ib.id}`, listen: '0.0.0.0', port: ib.port, protocol: 'vless',
        settings: { clients, decryption: 'none' },
        streamSettings: {
          network: 'tcp', security: 'reality',
          realitySettings: { show: false, target: `${sni[0] ?? 'www.microsoft.com'}:443`, serverNames: sni, privateKey: ib.private_key_sealed ? this.ctx.open(ib.private_key_sealed) : '', shortIds: [ib.short_id ?? ''] },
        },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
      });
    }
    return {
      log: { loglevel: 'warning' },
      api: { tag: 'api', services: ['StatsService'] },
      stats: {},
      policy: { levels: { '0': { statsUserUplink: true, statsUserDownlink: true } }, system: { statsInboundUplink: false } },
      inbounds,
      outbounds,
      routing: { domainStrategy: 'AsIs', rules, balancers },
    };
  }

  /** Клиенты direct-inbound: пользователи с прямым доступом к узлу + служебный клиент входа, ведущего сюда. */
  directClients(server: ServerRow, t: TemplateRow, users = this.users(true)) {
    const clients: Array<{ id: string; email: string; flow: string }> = [];
    for (const u of users)
      if (json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id))
        clients.push({ id: this.cred(u.id, `t:${t.id}`), email: `${u.id}.d-${t.id}`, flow: 'xtls-rprx-vision' });
    if (t.entry_id && t.entry_id !== server.id)
      clients.push({ id: this.svcCred(`relay:${t.id}:${t.entry_id}:${server.id}`), email: `svc.relay-${t.entry_id}-${t.id}`, flow: 'xtls-rprx-vision' });
    return clients;
  }

  /**
   * Inbound в формате API 3x-ui (узел в режиме xui): живёт в Xray 3x-ui, виден в его интерфейсе
   * с пометкой eskadra-…, клиентами управляет Эскадра.
   */
  xuiInbound(server: ServerRow, ib: InboundRow): Record<string, unknown> {
    const t = this.template(ib.template_id)!;
    const sni = json<string[]>(t.sni, []);
    const clients = this.directClients(server, t).map((c) => ({
      id: c.id, flow: c.flow, email: c.email, limitIp: 0, totalGB: 0, expiryTime: 0, enable: true, tgId: '', subId: '', reset: 0,
    }));
    return {
      up: 0, down: 0, total: 0, remark: `eskadra-${t.name}-${ib.id}`, enable: true, expiryTime: 0, listen: '', port: ib.port, protocol: 'vless',
      settings: JSON.stringify({ clients, decryption: 'none', fallbacks: [] }),
      streamSettings: JSON.stringify({
        network: 'tcp', security: 'reality', externalProxy: [],
        realitySettings: {
          show: false, xver: 0, dest: `${sni[0] ?? 'www.microsoft.com'}:443`, serverNames: sni,
          privateKey: ib.private_key_sealed ? this.ctx.open(ib.private_key_sealed) : '', minClient: '', maxClient: '', maxTimediff: 0,
          shortIds: [ib.short_id ?? ''], settings: { publicKey: ib.public_key ?? '', fingerprint: t.fingerprint, serverName: '', spiderX: '/' },
        },
        tcpSettings: { acceptProxyProtocol: false, header: { type: 'none' } },
      }),
      sniffing: JSON.stringify({ enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false, routeOnly: false }),
      allocate: JSON.stringify({ strategy: 'always', refresh: 5, concurrency: 3 }),
    };
  }

  /** Конфиг sing-box (Hysteria2) для узла. */
  renderSingbox(server: ServerRow): object | null {
    const ibs = this.inbounds(`server_id = ? AND state IN ('active','deploying') AND kind = 'direct'`, server.id)
      .filter((i) => this.template(i.template_id)?.core === 'sing-box');
    if (!ibs.length) return null;
    const users = this.users(true);
    return {
      log: { level: 'warn' },
      inbounds: ibs.map((ib) => {
        const t = this.template(ib.template_id)!;
        const sni = json<string[]>(t.sni, [])[0] ?? 'localhost';
        return {
          type: 'hysteria2', tag: `in-${ib.id}`, listen: '::', listen_port: ib.port,
          users: users
            .filter((u) => json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id))
            .map((u) => ({ name: `${u.id}.d-${t.id}`, password: this.cred(u.id, `t:${t.id}`) })),
          tls: { enabled: true, server_name: sni, certificate_path: `/etc/eskadra/sing-box/tls/${sni}.crt`, key_path: `/etc/eskadra/sing-box/tls/${sni}.key` },
        };
      }),
      outbounds: [{ type: 'direct', tag: 'direct' }],
    };
  }

  template(id: string): TemplateRow | undefined {
    return this.db.prepare('SELECT * FROM templates WHERE id = ?').get(id) as TemplateRow | undefined;
  }

  /** Отметить узлы, чей конфиг надо переприменить (пользователи/шаблоны изменились). */
  markDirty(serverIds?: string[]) {
    if (!serverIds) this.db.prepare(`UPDATE servers SET config_dirty = 1 WHERE id IN (SELECT DISTINCT server_id FROM inbounds)`).run();
    else for (const id of serverIds) this.db.prepare('UPDATE servers SET config_dirty = 1 WHERE id = ?').run(id);
  }
}

const hostForUri = (h: string) => (h.includes(':') && !h.startsWith('[') ? `[${h}]` : h);

/** Эффективные лимиты пользователя: свои значения поверх группы лимитов. */
export function effectiveLimits(ctx: Ctx, u: UserRow) {
  const g = ctx.db.prepare('SELECT * FROM limit_groups WHERE name = ?').get(u.limit_group) as
    | { traffic_gb: number | null; days: number | null; devices: number | null } | undefined;
  return {
    trafficGb: u.traffic_limit_gb ?? g?.traffic_gb ?? null,
    devices: u.device_limit ?? g?.devices ?? null,
    expireAt: u.expire_at,
  };
}

export const period = (d = new Date()) => d.toISOString().slice(0, 7);
