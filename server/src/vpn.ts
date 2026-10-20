import { randomUUID } from 'node:crypto';
import type { Ctx, InboundRow, ServerRow, TemplateRow, UserRow } from './ctx.js';
import { getSetting } from './db.js';
import { activeBotProxy, botCredKey, mgmtCredKey } from './botproxy.js';
import { blockedDevices, limitRules } from './devices.js';
import { blocksOf, needsSniff, singboxBlockRules, xrayBlockRules } from './blocks.js';
import { spreadBal, spreadCaps, spreadChain, spreadGroupOf, spreadHomes, spreadLoop, spreadLoopIn } from './spread.js';
import { certName, hopRange, hy2InboundExtra, link as protoLink, PROTOCOLS, type LinkTarget, probePort, specOf, telemtConfig, tlsServerName, xrayClient, xrayInbound, xrayOutbound, type Spec } from './protocols.js';

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
  /** пересылка ядром ОС (Hysteria2 через вход): сертификат, ключи и пароли — у inbound'а выхода */
  exit?: { server: ServerRow; inbound: InboundRow };
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

  /** Вариант подключения выключен у пользователя (галочка в его карточке). */
  profileOff(u: UserRow, key: string): boolean {
    return json<string[]>(u.excluded_profiles, []).includes(key);
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
        if (ib.kind === 'relay' && modes.includes('via') && PROTOCOLS[this.spec(t).protocol].natRelay) {
          // пересылка ядром ОС: один выход, клиент договаривается с его inbound'ом (пароль «вход → выход» знает выход)
          const x = this.natExit(t);
          if (x && this.userAllows(u, x.server.id, t.id))
            out.push({ key: `v:${t.id}:${x.server.id}`, name: `${s.name} → ${x.server.name}${suffix}`, mode: 'via', template: t,
              host: s.host, port: ib.port, credKey: `v:${t.id}:${x.server.id}`, inbound: ib, targetName: x.server.name, exit: x });
          continue;
        }
        if (ib.kind === 'relay' && modes.includes('via')) {
          const targets = this.relayTargets(t).filter((x) => this.userAllows(u, x.id, t.id));
          if (!targets.length) continue;
          // «вход → авто» — только если авто-выбор выхода у конфигурации включён
          if (this.spec(t).autoEnabled) out.push({ key: `v:${t.id}:auto`, name: `${s.name} → ${L.auto}${suffix}`, mode: 'auto', template: t,
            host: s.host, port: ib.port, credKey: `v:${t.id}:auto`, inbound: ib, targetName: 'auto' });
          for (const x of targets)
            out.push({ key: `v:${t.id}:${x.id}`, name: `${s.name} → ${x.name}${suffix}`, mode: 'via', template: t,
              host: s.host, port: ib.port, credKey: `v:${t.id}:${x.id}`, inbound: ib, targetName: x.name });
        }
      }
    }
    return out.filter((p) => !this.profileOff(u, p.key));
  }

  /** Узлы, на которые ведёт вход шаблона: его direct-узлы с активным inbound, кроме самого входа. */
  relayTargets(t: TemplateRow): ServerRow[] {
    const active = new Set(this.inbounds(`template_id = ? AND kind = 'direct' AND state = 'active'`, t.id).map((i) => i.server_id));
    const order = specOf(t).exitOrder;
    const rank = (id: string) => (order.includes(id) ? order.indexOf(id) : order.length);
    // в порядке, заданном для «Авто» (не упомянутые — в конце, как были)
    return this.ctx.servers().filter((s) => s.id !== t.entry_id && active.has(s.id)).sort((a, b) => rank(a.id) - rank(b.id));
  }

  /** Выход пересылки ядром ОС (Hysteria2 через вход): единственный direct-узел шаблона, кроме входа, с активным inbound'ом. */
  natExit(t: TemplateRow): { server: ServerRow; inbound: InboundRow } | null {
    const x = this.relayTargets(t)[0];
    const xi = x && this.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct' AND state = 'active'`, t.id, x.id)[0];
    return x && xi ? { server: x, inbound: xi } : null;
  }

  spec = (t: TemplateRow): Spec => specOf(t);

  /** Адрес подключения профиля и чей inbound проверяет клиент (у пересылки ядром — выхода). */
  target(p: Profile): LinkTarget {
    return { host: p.host, port: p.port, name: p.name, serverId: (p.exit?.inbound ?? p.inbound).server_id, inbound: p.exit?.inbound ?? p.inbound, tlsHost: p.exit?.server.host };
  }

  link(u: UserRow, p: Profile): string {
    return protoLink(this.spec(p.template), this.cred(u.id, p.credKey), this.target(p));
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
    const blocks = blocksOf(this.db);
    const inbounds: object[] = [
      { tag: 'api', listen: '127.0.0.1', port: 10085, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' } },
    ];
    const outbounds: object[] = [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }];
    const head: object[] = [
      { type: 'field', inboundTag: ['api'], outboundTag: 'api' },
      // раньше правил пользователей; домены резолвятся для этой проверки (domainStrategy IPOnDemand)
      { type: 'field', ip: PRIVATE_NETS, outboundTag: 'block' },
      // блокировки протоколов (настройка «Блокировки»): BitTorrent, почта, QUIC — на входе и на выходах
      ...xrayBlockRules(blocks),
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
          outbounds.push(relayLive(xrayOutbound(sp, xi, outTag, x.host, this.svcCred(`relay:${t.id}:${server.id}:${x.id}`), x.id)));
          if (sp.autoEnabled && sp.autoMode !== 'random') {
            // локальный SOCKS для проб: панель меряет задержку и скорость именно этого выхода
            inbounds.push({ tag: `probe-${t.id}-${x.id}`, listen: '127.0.0.1', port: probePort(t.id, x.id), protocol: 'socks', settings: { udp: false } });
            rules.push({ type: 'field', inboundTag: [`probe-${t.id}-${x.id}`], outboundTag: outTag });
          }
          const emails: string[] = [];
          for (const u of users)
            if (json<string[]>(u.modes, []).includes('via') && this.userAllows(u, x.id, t.id) && !this.profileOff(u, `v:${t.id}:${x.id}`)) {
              const email = `${u.id}.v-${x.id}`;
              clients.push(xrayClient(sp, this.cred(u.id, `v:${t.id}:${x.id}`), email));
              emails.push(email);
            }
          if (emails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: emails, outboundTag: outTag });
        }
        // авто-выбор выхода выключен — ни клиентов «авто», ни балансировщиков, ни проверок выходов
        if (ready.length && sp.autoEnabled) {
          const autoEmails: string[] = [];
          const autoUsers: string[] = [];
          for (const u of users)
            // «авто» — только если конфигурация пользователю выдана (есть хоть один доступный выход) и вариант не выключен
            if (json<string[]>(u.modes, []).includes('via') && ready.some((x) => this.userAllows(u, x.id, t.id)) && !this.profileOff(u, `v:${t.id}:auto`)) {
              const email = `${u.id}.a-${t.id}`;
              clients.push(xrayClient(sp, this.cred(u.id, `v:${t.id}:auto`), email));
              autoEmails.push(email);
              autoUsers.push(u.id);
            }
          if (sp.autoMode === 'spread') {
            // по нагрузке (spread.ts): у каждой группы пользователей своя цепочка уровней — домашний выход, затем остальные.
            // Уровни всех групп ведут на общие outbound'ы выходов (to-…): вход проверяет каждый выход один раз, а не
            // по разу на группу — при 6 группах это в 6 раз меньше проверок и ложных «выход не отвечает» под нагрузкой.
            // Нагрузку группы панель считает по счётчикам её пользователей.
            observed.push(`to-${t.id}-`);
            fastObserve = true;
            const ids = ready.map((x) => x.id);
            const homes = spreadHomes(ids, spreadCaps(this.db, sp.exitCapMbps, ids), sp.spreadGroups);
            homes.forEach((home, g) => {
              const chain = spreadChain(home, ids);
              chain.forEach((x, i) => {
                balancers.push({
                  tag: spreadBal(t.id, g, i), selector: [`to-${t.id}-${x}`],
                  fallbackTag: i === chain.length - 1 ? `to-${t.id}-${chain[0]!}` : spreadLoop(t.id, g, i + 1),
                  strategy: { type: 'leastLoad', settings: { expected: 1, tolerance: 0.5 } },
                });
                if (i) {
                  outbounds.push({ tag: spreadLoop(t.id, g, i), protocol: 'loopback', settings: { inboundTag: spreadLoopIn(t.id, g, i) } });
                  rules.push({ type: 'field', inboundTag: [spreadLoopIn(t.id, g, i)], balancerTag: spreadBal(t.id, g, i) });
                }
              });
              const emails = autoEmails.filter((_, k) => spreadGroupOf(autoUsers[k]!, homes.length) === g);
              if (emails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: emails, balancerTag: spreadBal(t.id, g, 0) });
            });
          } else if (sp.autoMode !== 'random') {
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
          if (autoEmails.length && sp.autoMode !== 'spread') rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: autoEmails, balancerTag: `bal-${t.id}` });
        }
        // всё прочее с входа, не попавшее в правила, не выпускаем наружу с самого входа
        rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], outboundTag: 'block' });
      }
      inbounds.push(xrayInbound(sp, ib, `in-${ib.id}`, clients, {
        privateKey: ib.private_key_sealed ? this.ctx.open(ib.private_key_sealed) : undefined,
        cert: certName(sp, t.id, server.id, server.host),
        ssServerKey: ib.public_key ?? undefined,
        forceSniff: needsSniff(blocks),
      }));
    }
    return {
      // журнал каждого соединения Xray по умолчанию пишет в stdout (journald): тысячи строк в час на узел — диск, процессор и
      // адреса сайтов пользователей. Выключен; предупреждения и ошибки остаются
      log: { loglevel: 'warning', access: 'none' },
      api: { tag: 'api', services: ['StatsService', 'RoutingService'] },
      ...(observed.length ? {
        burstObservatory: {
          subjectSelector: observed,
          // «по порядку» и «по нагрузке»: проверка каждые 5 с (≈ 10 с до переключения, ~5 КБ на выход за проверку); таймаут 5 с —
          // при 3 с выход под нагрузкой (или нагруженный вход) ложно считался мёртвым и группы метались; иначе раз в минуту
          pingConfig: fastObserve
            ? { destination: 'https://www.gstatic.com/generate_204', interval: '5s', sampling: 2, timeout: '5s' }
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
      if (json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id) && !this.profileOff(u, `d:${t.id}:${server.id}`))
        clients.push(xrayClient(sp, this.cred(u.id, `t:${t.id}`), `${u.id}.d-${t.id}`));
    if (t.entry_id && t.entry_id !== server.id)
      clients.push(xrayClient(sp, this.svcCred(`relay:${t.id}:${t.entry_id}:${server.id}`), `svc.relay-${t.entry_id}-${t.id}`));
    // Telegram-бот панели ходит через эту конфигурацию (прокси бота, botproxy.ts)
    const bot = activeBotProxy(this.ctx);
    if (bot && !bot.fallback && bot.template.id === t.id && bot.server.id === server.id)
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
      // маршрутизация на узле — своя у 3x-ui (BitTorrent он режет по умолчанию, но только при sniffing): для блокировок sniffing включаем
      sniffing: JSON.stringify({ enabled: sp.sniffing || needsSniff(blocksOf(this.db)), destOverride: ['http', 'tls', 'quic'], metadataOnly: false, routeOnly: !sp.sniffing }),
      allocate: JSON.stringify({ strategy: 'always', refresh: 5, concurrency: 3 }),
    };
  }

  /** Конфиг sing-box (Hysteria2) для узла. */
  renderSingbox(server: ServerRow): object | null {
    const blocks = blocksOf(this.db);
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
          users: [
            ...users
              .filter((u) => json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id) && !this.profileOff(u, `d:${t.id}:${server.id}`))
              .map((u) => ({ name: `${u.id}.d-${t.id}`, password: this.cred(u.id, `t:${t.id}`) })),
            // «вход → этот выход»: вход пересылает UDP ядром ОС, пароль профиля проверяет сам выход
            ...(t.entry_id && json<string[]>(t.node_ids, []).filter((id) => id !== t.entry_id)[0] === server.id ? users
              .filter((u) => json<string[]>(u.modes, []).includes('via') && this.userAllows(u, server.id, t.id) && !this.profileOff(u, `v:${t.id}:${server.id}`))
              .map((u) => ({ name: `${u.id}.v-${server.id}`, password: this.cred(u.id, `v:${t.id}:${server.id}`) })) : []),
          ],
          ...hy2InboundExtra(sp),
          tls: {
            enabled: true, server_name: tlsServerName(sp, server.id) || self, alpn: ['h3'],
            ...(cert
              ? { certificate_path: `/etc/eskadra/tls/${cert}/fullchain.pem`, key_path: `/etc/eskadra/tls/${cert}/privkey.pem` }
              : { certificate_path: `/etc/eskadra/sing-box/tls/${self}.crt`, key_path: `/etc/eskadra/sing-box/tls/${self}.key` }),
          },
        };
      }),
      outbounds: [{ type: 'direct', tag: 'direct' }],
      // распознать протокол (BitTorrent: TCP, uTP, UDP-трекеры), затем домен резолвится, локальные и частные адреса
      // отклоняются, затем блокировки протоколов (sing-box ≥ 1.11)
      route: { rules: [
        ...(needsSniff(blocks) ? [{ action: 'sniff' }] : []),
        { action: 'resolve' }, { ip_cidr: PRIVATE_NETS, action: 'reject' },
        ...singboxBlockRules(blocks),
      ] },
    };
  }

  /** Смена портов Hysteria2 на узле: «порт:начало-конец» через запятую (UDP с диапазона перенаправляется на порт inbound'а); '-' — нет. */
  hy2Hops(server: ServerRow): string {
    const hops = this.inbounds(`server_id = ? AND state IN ('active','deploying') AND kind = 'direct'`, server.id)
      .flatMap((ib) => {
        const t = this.template(ib.template_id);
        const r = t?.core === 'sing-box' ? hopRange(this.spec(t).hy2Hop) : null;
        return r ? [`${ib.port}:${r[0]}-${r[1]}`] : [];
      });
    return hops.join(',') || '-';
  }

  /**
   * Пересылка ядром ОС на входе (Hysteria2 через вход): «порт[-конец]=IP выхода:порт inbound'а» через запятую;
   * диапазон смены портов шаблона тоже ведёт на выход. '-' — пересылок нет.
   */
  hy2Relays(server: ServerRow): string {
    const out: string[] = [];
    for (const ib of this.inbounds(`server_id = ? AND state IN ('active','deploying') AND kind = 'relay'`, server.id)) {
      const t = this.template(ib.template_id);
      if (!t || !PROTOCOLS[this.spec(t).protocol].natRelay) continue;
      const x = this.natExit(t);
      if (!x) continue;
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(x.server.host)) throw new Error(`${x.server.name}: для пересылки через вход нужен IPv4-адрес выхода, а не «${x.server.host}»`);
      const to = `${x.server.host}:${x.inbound.port}`;
      out.push(`${ib.port}=${to}`);
      const r = hopRange(this.spec(t).hy2Hop);
      if (r) out.push(`${r[0]}-${r[1]}=${to}`);
    }
    return out.join(',') || '-';
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
      .filter((u) => json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id) && !this.profileOff(u, `d:${t.id}:${server.id}`))
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
/**
 * Соединения вход → выход следят за живостью TCP: keepalive после 15 с тишины (каждые 5 с) и обрыв, если отправленное
 * не подтверждено 20 с. Выход пропал по сети (а не остановился с RST) — зависшие соединения закрываются за ~20–60 с,
 * а не через 5 минут простоя; приложение переподключается и попадает на выход, который выбрал балансировщик.
 */
export function relayLive<T extends Record<string, unknown>>(o: T): T {
  const stream = (o.streamSettings as Record<string, unknown> | undefined) ?? {};
  return { ...o, streamSettings: { ...stream, sockopt: { ...(stream.sockopt as object | undefined), tcpKeepAliveIdle: 15, tcpKeepAliveInterval: 5, tcpUserTimeout: 20000 } } };
}

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
