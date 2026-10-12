import { randomUUID } from 'node:crypto';
import type { Ctx, InboundRow, ServerRow, TemplateRow, UserRow } from './ctx.js';
import { getSetting } from './db.js';
import { activeBotProxy, botCredKey, mgmtCredKey } from './botproxy.js';
import { blockedDevices, limitRules } from './devices.js';
import { certName, link as protoLink, probePort, specOf, telemtConfig, tlsServerName, xrayClient, xrayInbound, xrayOutbound, type Spec } from './protocols.js';

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

/**
 * Локальные и частные адреса: пользовательский трафик туда не выпускается. Иначе VPN-пользователь мог бы
 * открыть через своё подключение API ядра (127.0.0.1:10085), SSH узла «с самого узла» (from=127.0.0.1, §5.8)
 * или сервисы внутренней сети хостера.
 */
export const PRIVATE_NETS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
  '::1/128', '::/128', 'fc00::/7', 'fe80::/10',
];

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

  /** Пользователю доступен сервер (node_ids) и конфигурация (template_ids); null — без ограничения. */
  userAllows(u: UserRow, serverId: string, templateId?: string): boolean {
    const tpls = json<string[] | null>(u.template_ids, null);
    if (templateId && tpls && !tpls.includes(templateId)) return false;
    const ids = json<string[] | null>(u.node_ids, null);
    return !ids || ids.includes(serverId);
  }

  /** Все профили пользователя: напрямую к каждому узлу и через вход (§12.5). */
  profiles(u: UserRow): Profile[] {
    const modes = json<string[]>(u.modes, ['direct', 'via']);
    const servers = new Map(this.ctx.servers().map((s) => [s.id, s]));
    const out: Profile[] = [];
    const templates = this.templates();
    // имена профилей — на языке панели и с маршрутом: «de-1 · напрямую», «relay → de-1», «relay → авто»
    const L = getSetting<string>(this.db, 'ui.lang', 'ru') === 'en' ? { direct: 'direct', auto: 'auto' } : { direct: 'напрямую', auto: 'авто' };
    for (const t of templates) {
      const suffix = templates.length > 1 ? ` · ${t.name}` : '';
      for (const ib of this.inbounds(`template_id = ? AND state = 'active'`, t.id)) {
        const s = servers.get(ib.server_id);
        if (!s) continue;
        if (ib.kind === 'direct' && modes.includes('direct') && s.direct_access && this.userAllows(u, s.id, t.id)) {
          out.push({ key: `d:${t.id}:${s.id}`, name: `${s.name} · ${L.direct}${suffix}`, mode: 'direct', template: t,
            host: s.host, port: ib.port, credKey: `t:${t.id}`, inbound: ib, targetName: s.name });
        }
        if (ib.kind === 'relay' && modes.includes('via')) {
          const targets = this.relayTargets(t).filter((x) => this.userAllows(u, x.id, t.id));
          if (!targets.length) continue;
          out.push({ key: `v:${t.id}:auto`, name: `${s.name} → ${L.auto}${suffix}`, mode: 'auto', template: t,
            host: s.host, port: ib.port, credKey: `v:${t.id}:auto`, inbound: ib, targetName: 'auto' });
          for (const x of targets)
            out.push({ key: `v:${t.id}:${x.id}`, name: `${s.name} → ${x.name}${suffix}`, mode: 'via', template: t,
              host: s.host, port: ib.port, credKey: `v:${t.id}:${x.id}`, inbound: ib, targetName: x.name });
        }
      }
    }
    return out;
  }

  /** Узлы, на которые ведёт вход шаблона: его direct-узлы с активным inbound, кроме самого входа. */
  relayTargets(t: TemplateRow): ServerRow[] {
    const active = new Set(this.inbounds(`template_id = ? AND kind = 'direct' AND state = 'active'`, t.id).map((i) => i.server_id));
    const order = specOf(t).exitOrder;
    const rank = (id: string) => (order.includes(id) ? order.indexOf(id) : order.length);
    // в порядке, заданном для «Авто» (не упомянутые — в конце, как были)
    return this.ctx.servers().filter((s) => s.id !== t.entry_id && active.has(s.id)).sort((a, b) => rank(a.id) - rank(b.id));
  }

  spec = (t: TemplateRow): Spec => specOf(t);

  link(u: UserRow, p: Profile): string {
    const sp = this.spec(p.template);
    return protoLink(sp, this.cred(u.id, p.credKey), { host: p.host, port: p.port, name: p.name, serverId: p.inbound.server_id, inbound: p.inbound });
  }

  // ───── рендер конфигов узла ─────

  /**
   * Конфиг Xray для узла: все xray-inbounds узла (direct и relay), клиенты, маршруты входа.
   * limits — включить текущие блокировки лишних устройств (для отпечатка конфига — без них: они меняются на ходу).
   */
  renderXray(server: ServerRow, opts: { limits?: boolean } = {}): object | null {
    const ibs = this.inbounds(`server_id = ? AND state IN ('active','deploying')`, server.id)
      .filter((i) => this.template(i.template_id)?.core === 'xray');
    if (!ibs.length) return null;
    const users = this.users(true);
    const inbounds: object[] = [
      { tag: 'api', listen: '127.0.0.1', port: 10085, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' } },
    ];
    const outbounds: object[] = [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }];
    const head: object[] = [
      { type: 'field', inboundTag: ['api'], outboundTag: 'api' },
      // раньше правил пользователей; домены резолвятся для этой проверки (domainStrategy IPOnDemand)
      { type: 'field', ip: PRIVATE_NETS, outboundTag: 'block' },
      { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
    ];
    const rules: object[] = [];
    const balancers: object[] = [];
    const observed: string[] = [];   // префиксы outbound'ов выходов, за которыми следит Xray (умный «Авто»)
    let observeRtt = 0;
    let fastObserve = false;   // есть «по порядку» — вход проверяет выходы часто (≈ 8 с на переключение)

    for (const ib of ibs) {
      const t = this.template(ib.template_id)!;
      const sp = this.spec(t);
      let clients = ib.kind === 'direct' ? this.directClients(server, t, users) : [];
      if (ib.kind === 'relay') {
        const targets = this.relayTargets(t);
        const ready: ServerRow[] = [];   // выходы, для которых собран outbound: на них ссылаются балансировщики
        for (const x of targets) {
          const outTag = `to-${t.id}-${x.id}`;
          const xi = this.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct'`, t.id, x.id)[0];
          if (!xi || (sp.security === 'reality' && !xi.public_key)) continue;
          ready.push(x);
          outbounds.push(xrayOutbound(sp, xi, outTag, x.host, this.svcCred(`relay:${t.id}:${server.id}:${x.id}`), x.id));
          if (sp.autoMode !== 'random') {
            // локальный SOCKS для проб: панель меряет задержку и скорость именно этого выхода
            inbounds.push({ tag: `probe-${t.id}-${x.id}`, listen: '127.0.0.1', port: probePort(t.id, x.id), protocol: 'socks', settings: { udp: false } });
            rules.push({ type: 'field', inboundTag: [`probe-${t.id}-${x.id}`], outboundTag: outTag });
          }
          const emails: string[] = [];
          for (const u of users)
            if (json<string[]>(u.modes, []).includes('via') && this.userAllows(u, x.id, t.id)) {
              const email = `${u.id}.v-${x.id}`;
              clients.push(xrayClient(sp, this.cred(u.id, `v:${t.id}:${x.id}`), email));
              emails.push(email);
            }
          if (emails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: emails, outboundTag: outTag });
        }
        if (ready.length) {
          const autoEmails: string[] = [];
          for (const u of users)
            if (json<string[]>(u.modes, []).includes('via')) {
              const email = `${u.id}.a-${t.id}`;
              clients.push(xrayClient(sp, this.cred(u.id, `v:${t.id}:auto`), email));
              autoEmails.push(email);
            }
          if (sp.autoMode !== 'random') {
            // по качеству и по порядку (fallback — первый в порядке): Xray выбирает выход с наименьшей задержкой и не берёт выходы с задержкой выше порога;
            // если все выше порога — первый выход (fallback). Скорость меряет панель и переключает через API (ops.checkExits)
            observed.push(`to-${t.id}-`);
            observeRtt = Math.max(observeRtt, sp.maxRttMs);
            const order = sp.autoMode === 'order';
            if (order) {
              fastObserve = true;
              // по порядку: цепочка уровней. Уровень k видит только k-й выход; жив (хоть одна из двух последних проверок
              // прошла) — трафик через него, нет — loopback возвращает соединение в маршрутизацию на уровень k+1.
              // Так любой резервный выход включается за секунды без участия панели; вернулся вышестоящий — снова через него.
              // Все не отвечают — через первый. Веса leastLoad для порядка не годятся: Xray умножает на них разброс задержки.
              ready.forEach((x, i) => {
                const last = i === ready.length - 1;
                balancers.push({
                  tag: orderBalancer(t.id, i), selector: [`to-${t.id}-${x.id}`],
                  fallbackTag: last ? `to-${t.id}-${ready[0]!.id}` : `lb-${t.id}-${i + 2}`,
                  strategy: { type: 'leastLoad', settings: { expected: 1, tolerance: 0.5 } },
                });
                if (i) {
                  outbounds.push({ tag: `lb-${t.id}-${i + 1}`, protocol: 'loopback', settings: { inboundTag: `lvl-${t.id}-${i + 1}` } });
                  rules.push({ type: 'field', inboundTag: [`lvl-${t.id}-${i + 1}`], balancerTag: orderBalancer(t.id, i) });
                }
              });
            } else balancers.push({
              tag: `bal-${t.id}`, selector: [`to-${t.id}-`], fallbackTag: `to-${t.id}-${ready[0]!.id}`,
              strategy: { type: 'leastLoad', settings: { expected: 1, tolerance: 0.01, maxRTT: `${sp.maxRttMs}ms` } },
            });
          } else {
            balancers.push({ tag: `bal-${t.id}`, selector: [`to-${t.id}-`], strategy: { type: 'random' } });
          }
          if (autoEmails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: autoEmails, balancerTag: `bal-${t.id}` });
        }
        // всё прочее с входа, не попавшее в правила, не выпускаем наружу с самого входа
        rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], outboundTag: 'block' });
      }
      inbounds.push(xrayInbound(sp, ib, `in-${ib.id}`, clients, {
        privateKey: ib.private_key_sealed ? this.ctx.open(ib.private_key_sealed) : undefined,
        cert: certName(sp, t.id, server.id, server.host),
        ssServerKey: ib.public_key ?? undefined,
      }));
    }
    return {
      log: { loglevel: 'warning' },
      api: { tag: 'api', services: ['StatsService', 'RoutingService'] },
      ...(observed.length ? {
        burstObservatory: {
          subjectSelector: observed,
          // «по порядку»: проверка каждые 5 с (≈ 8 с до переключения, ~5 КБ на выход за проверку); иначе раз в минуту
          pingConfig: fastObserve
            ? { destination: 'https://www.gstatic.com/generate_204', interval: '5s', sampling: 2, timeout: '3s' }
            : { destination: 'https://www.gstatic.com/generate_204', interval: '1m', sampling: 3, timeout: `${Math.max(5, Math.ceil(observeRtt * 5 / 1000))}s` },
        },
      } : {}),
      stats: {},
      // statsUserOnline — IP с открытыми соединениями по каждому пользователю: по ним считается лимит устройств (devices.ts)
      policy: { levels: { '0': { statsUserUplink: true, statsUserDownlink: true, statsUserOnline: true } }, system: { statsInboundUplink: false } },
      inbounds,
      outbounds,
      routing: { domainStrategy: 'IPOnDemand', rules: [...head, ...tagRules([...(opts.limits === false ? [] : limitRules(blockedDevices(this.ctx))), ...rules], 'r0')], balancers },
    };
  }

  /**
   * Правила после служебных (лимит устройств + маршруты) с тегами поколения gen — для замены на работающем
   * Xray без перезапуска (fleet-core rules): новые дописываются, затем старые удаляются по тегам.
   */
  routingTail(server: ServerRow, gen: string): object[] | null {
    const cfg = this.renderXray(server) as { routing: { rules: Array<Record<string, unknown>> } } | null;
    if (!cfg) return null;
    return cfg.routing.rules.filter((r) => typeof r.ruleTag === 'string').map((r, i) => ({ ...r, ruleTag: `${gen}-${i}` }));
  }

  /** Клиенты direct-inbound: пользователи с прямым доступом к узлу + служебный клиент входа, ведущего сюда. */
  directClients(server: ServerRow, t: TemplateRow, users = this.users(true)) {
    const sp = this.spec(t);
    const clients = [];
    for (const u of users)
      if (json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id))
        clients.push(xrayClient(sp, this.cred(u.id, `t:${t.id}`), `${u.id}.d-${t.id}`));
    if (t.entry_id && t.entry_id !== server.id)
      clients.push(xrayClient(sp, this.svcCred(`relay:${t.id}:${t.entry_id}:${server.id}`), `svc.relay-${t.entry_id}-${t.id}`));
    // Telegram-бот панели ходит через эту конфигурацию (прокси бота, botproxy.ts)
    const bot = activeBotProxy(this.ctx);
    if (bot && bot.template.id === t.id && bot.server.id === server.id)
      clients.push(xrayClient(sp, this.svcCred(botCredKey(t.id, server.id)), 'svc.bot'));
    // через эту конфигурацию панель может зайти на SSH нового сервера при первичном доступе (onboard.ts, «через прокси»)
    if (server.mgmt_mode !== 'local') clients.push(xrayClient(sp, this.svcCred(mgmtCredKey(t.id, server.id)), 'svc.mgmt'));
    return clients;
  }

  /**
   * Inbound в формате API 3x-ui (узел в режиме xui): живёт в Xray 3x-ui, виден в его интерфейсе
   * с пометкой eskadra-…, клиентами управляет Эскадра.
   */
  xuiInbound(server: ServerRow, ib: InboundRow): Record<string, unknown> {
    const t = this.template(ib.template_id)!;
    const sp = this.spec(t);
    const clients = this.directClients(server, t).map((c) => ({
      ...c, limitIp: 0, totalGB: 0, expiryTime: 0, enable: true, tgId: '', subId: '', reset: 0,
    }));
    const x = xrayInbound(sp, ib, `in-${ib.id}`, clients, {
      privateKey: ib.private_key_sealed ? this.ctx.open(ib.private_key_sealed) : undefined,
      cert: certName(sp, t.id, server.id, server.host),
      ssServerKey: ib.public_key ?? undefined,
    }) as { settings: Record<string, unknown>; streamSettings?: Record<string, unknown> };
    const stream = { ...(x.streamSettings ?? { network: 'tcp', security: 'none' }) } as Record<string, unknown>;
    // 3x-ui хранит REALITY с полем dest и публичным ключом для своих ссылок
    if (stream.realitySettings) {
      const r = stream.realitySettings as Record<string, unknown>;
      stream.realitySettings = { ...r, dest: r.target, xver: 0, minClient: '', maxClient: '', maxTimediff: 0,
        settings: { publicKey: ib.public_key ?? '', fingerprint: sp.fingerprint, serverName: '', spiderX: '/' } };
    }
    return {
      up: 0, down: 0, total: 0, remark: `eskadra-${t.name}-${ib.id}`, enable: true, expiryTime: 0, listen: '', port: ib.port, protocol: sp.protocol,
      settings: JSON.stringify({ ...x.settings, ...(sp.protocol === 'vless' ? { fallbacks: [] } : {}) }),
      streamSettings: JSON.stringify(stream),
      sniffing: JSON.stringify({ enabled: sp.sniffing, destOverride: ['http', 'tls', 'quic'], metadataOnly: false, routeOnly: false }),
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
        const sp = this.spec(t);
        const cert = certName(sp, t.id, server.id, server.host);
        const self = sp.sni[0] ?? 'localhost';
        return {
          type: 'hysteria2', tag: `in-${ib.id}`, listen: '::', listen_port: ib.port,
          users: users
            .filter((u) => json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id))
            .map((u) => ({ name: `${u.id}.d-${t.id}`, password: this.cred(u.id, `t:${t.id}`) })),
          ...(sp.hy2Obfs ? { obfs: { type: 'salamander', password: sp.hy2Obfs } } : {}),
          tls: {
            enabled: true, server_name: tlsServerName(sp, server.id) || self, alpn: ['h3'],
            ...(cert
              ? { certificate_path: `/etc/eskadra/tls/${cert}/fullchain.pem`, key_path: `/etc/eskadra/tls/${cert}/privkey.pem` }
              : { certificate_path: `/etc/eskadra/sing-box/tls/${self}.crt`, key_path: `/etc/eskadra/sing-box/tls/${self}.key` }),
          },
        };
      }),
      outbounds: [{ type: 'direct', tag: 'direct' }],
      // домен сначала резолвится, затем локальные и частные адреса отклоняются (sing-box ≥ 1.11)
      route: { rules: [{ action: 'resolve' }, { ip_cidr: PRIVATE_NETS, action: 'reject' }] },
    };
  }

  /** config.toml telemt (MTProto) для узла: на узле — одна MTProto-конфигурация (у неё свой домен маскировки). */
  renderTelemt(server: ServerRow): string | null {
    const ibs = this.inbounds(`server_id = ? AND state IN ('active','deploying') AND kind = 'direct'`, server.id)
      .filter((i) => this.template(i.template_id)?.core === 'telemt');
    if (!ibs.length) return null;
    if (ibs.length > 1) throw new Error(`${server.name}: на узле может быть только одна конфигурация MTProto`);
    const ib = ibs[0]!;
    const t = this.template(ib.template_id)!;
    const users = this.users(true)
      .filter((u) => json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id))
      .map((u) => ({ name: `${u.id}.d-${t.id}`, secret: this.cred(u.id, `t:${t.id}`), maxIps: effectiveLimits(this.ctx, u).devices }));
    return telemtConfig(this.spec(t), ib.port, users, server.host);
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

/** Балансировщик уровня i цепочки «по порядку»: первый — bal-<t> (его назначение и состояние смотрит панель), дальше bal-<t>-<i+1>. */
export const orderBalancer = (templateId: string, i: number) => (i ? `bal-${templateId}-${i + 1}` : `bal-${templateId}`);

/** Теги правил поколения gen: по ним fleet-core rules убирает прежний набор после того, как добавлен новый. */
const tagRules = (rules: object[], gen: string) => rules.map((r, i) => ({ ...r, ruleTag: `${gen}-${i}` }));

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
