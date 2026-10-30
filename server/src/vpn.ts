import { randomUUID } from 'node:crypto';
import type { Ctx, InboundRow, ServerRow, TemplateRow, UserRow } from './ctx.js';
import { getSetting } from './db.js';
import { activeBotProxy, botCredKey, mgmtCredKey } from './botproxy.js';
import { blockedDevices, limitRules } from './devices.js';
import { blocksOf, needsSniff, singboxBlockRules, xrayBlockRules } from './blocks.js';
import { spreadBal, spreadCaps, spreadChain, spreadGroupOf, spreadHomes, spreadLoop, spreadLoopIn } from './spread.js';
import { certName, entrySpec, hinPort, hopRange, hy2Entry, hy2InboundExtra, legPort, link as protoLink, natRelayOf, type LinkTarget, probePort, singboxOutbound, specOf, telemtConfig, tlsServerName, xrayClient, xrayInbound, xrayOutbound, type Spec } from './protocols.js';

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

  /** Конфигурации, которые выдаются пользователям: без служебной Hysteria2 «eskadra» (она — часть своей конфигурации). */
  userTemplates(): TemplateRow[] {
    return this.templates().filter((t) => !this.spec(t).companionOf);
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
    // служебная Hysteria2 «eskadra» — только плечи входа, своих профилей у неё нет
    const templates = this.userTemplates();
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
        if (ib.kind === 'relay' && modes.includes('via') && natRelayOf(this.spec(t))) {
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

  /** Кто ходит через вход шаблона: пользователи на каждый готовый выход и пользователи «вход → авто». */
  viaUsers(t: TemplateRow, ready: ServerRow[], users: UserRow[]): { perExit: Map<string, UserRow[]>; auto: UserRow[] } {
    const via = users.filter((u) => json<string[]>(u.modes, []).includes('via'));
    return {
      perExit: new Map(ready.map((x) => [x.id, via.filter((u) => this.userAllows(u, x.id, t.id) && !this.profileOff(u, `v:${t.id}:${x.id}`))])),
      // «авто» — только если авто-выбор включён, конфигурация пользователю выдана (есть хоть один доступный выход) и вариант не выключен
      auto: this.spec(t).autoEnabled && ready.length ? via.filter((u) => ready.some((x) => this.userAllows(u, x.id, t.id)) && !this.profileOff(u, `v:${t.id}:auto`)) : [],
    };
  }

  /**
   * Плечо Hysteria2 вход → выход x: у Hysteria2 через вход (core) — inbound самой конфигурации на выходе, у Xray-конфигурации
   * с резервом hy2Leg — inbound той Hysteria2-конфигурации на выходе. key — служебный пароль плеча (его знает inbound выхода).
   */
  legTarget(t: TemplateRow, x: ServerRow): { tpl: TemplateRow; inbound: InboundRow; key: string } | null {
    const sp = this.spec(t);
    if (!t.entry_id) return null;
    const tpl = sp.protocol === 'hysteria2' ? (natRelayOf(sp) ? undefined : t) : sp.hy2Leg ? this.template(sp.hy2Leg) : undefined;
    if (!tpl || this.spec(tpl).protocol !== 'hysteria2') return null;
    const inbound = this.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct' AND state = 'active'`, tpl.id, x.id)[0];
    return inbound ? { tpl, inbound, key: `${tpl.id === t.id ? 'relay' : 'leg'}:${t.id}:${t.entry_id}:${x.id}` } : null;
  }

  /** Плечи Hysteria2, которые держит sing-box входа: локальный SOCKS (для Xray входа) → Hysteria2 на inbound выхода. */
  entryLegs(server: ServerRow): Array<{ tag: string; port: number; out: Record<string, unknown> }> {
    const out: Array<{ tag: string; port: number; out: Record<string, unknown> }> = [];
    for (const t of this.templates().filter((x) => x.entry_id === server.id)) {
      if (!this.inbounds(`template_id = ? AND server_id = ? AND kind = 'relay' AND state IN ('active','deploying')`, t.id, server.id).length) continue;
      for (const x of this.relayTargets(t)) {
        const leg = this.legTarget(t, x);
        if (!leg) continue;
        const tag = `hy-${t.id}-${x.id}`;
        const o = singboxOutbound(this.spec(leg.tpl), this.svcCred(leg.key), { host: x.host, port: leg.inbound.port, name: tag, serverId: x.id, inbound: leg.inbound });
        if (o) out.push({ tag, port: legPort(t.id, x.id), out: o });
      }
    }
    return out;
  }

  /**
   * Служебные пользователи inbound'а Hysteria2 на узле: панель (sing-box не любит inbound без пользователей — новая
   * конфигурация, ещё никому не выданная), плечо входа этой конфигурации (core) и резервные плечи Xray-конфигураций.
   */
  private hy2SvcUsers(t: TemplateRow, server: ServerRow): Array<{ name: string; password: string }> {
    const out = [{ name: 'svc.panel', password: this.svcCred(`hy:${t.id}:${server.id}`) }];
    if (t.entry_id && t.entry_id !== server.id && !natRelayOf(this.spec(t)))
      out.push({ name: `svc.relay-${t.entry_id}-${t.id}`, password: this.svcCred(`relay:${t.id}:${t.entry_id}:${server.id}`) });
    for (const v of this.templates())
      if (v.entry_id && v.entry_id !== server.id && this.spec(v).hy2Leg === t.id && json<string[]>(v.node_ids, []).includes(server.id))
        out.push({ name: `svc.leg-${v.id}`, password: this.svcCred(`leg:${v.id}:${v.entry_id}:${server.id}`) });
    return out;
  }

  /** Адрес подключения профиля и чей inbound проверяет клиент (у пересылки ядром — выхода). */
  target(p: Profile): LinkTarget {
    return { host: p.host, port: p.port, name: p.name, serverId: (p.exit?.inbound ?? p.inbound).server_id, inbound: p.exit?.inbound ?? p.inbound, tlsHost: p.exit?.server.host };
  }

  /** Настройки, по которым клиент подключается: через вход — настройки inbound'а входа (у eskadra это может быть Hysteria2). */
  profileSpec(p: Profile): Spec {
    return p.mode === 'direct' ? this.spec(p.template) : entrySpec(this.spec(p.template));
  }

  link(u: UserRow, p: Profile): string {
    return protoLink(this.profileSpec(p), this.cred(u.id, p.credKey), this.target(p));
  }

  // ───── рендер конфигов узла ─────

  /**
   * Конфиг Xray для узла: все xray-inbounds узла (direct и relay), клиенты, маршруты входа.
   * limits — включить текущие блокировки лишних устройств (для отпечатка конфига — без них: они меняются на ходу).
   */
  renderXray(server: ServerRow, opts: { limits?: boolean } = {}): object | null {
    // Hysteria2 через вход (core): клиентов принимает sing-box входа, а выход выбирает Xray входа — как у Xray-конфигураций
    const ibs = this.inbounds(`server_id = ? AND state IN ('active','deploying')`, server.id)
      .filter((i) => { const t = this.template(i.template_id); return t?.core === 'xray' || (!!t && i.kind === 'relay' && t.core === 'sing-box' && !natRelayOf(this.spec(t))); });
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
      // inbound входа: свой транспорт (XHTTP только для клиентов или только между серверами) или вход за CDN
      const isp = ib.kind === 'relay' ? entrySpec(sp) : sp;
      // Hysteria2 через вход (core): sing-box входа отдаёт трафик сюда по локальным SOCKS — порт на выход и на «авто»;
      // пользователей различает sing-box, плечи к выходам — Hysteria2 через sing-box входа (entryLegs)
      // то же у eskadra со входом по Hysteria2
      const hy = ib.kind === 'relay' && (sp.protocol === 'hysteria2' || hy2Entry(sp));
      const hin = (route: string) => {
        const tag = `hin-${ib.id}-${route}`;
        inbounds.push({ tag, listen: '127.0.0.1', port: hinPort(ib.id, route), protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
          ...(needsSniff(blocks) ? { sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true } } : {}) });
        return tag;
      };
      let clients = ib.kind === 'direct' ? this.directClients(server, t, users) : [];
      if (ib.kind === 'relay') {
        const targets = this.relayTargets(t);
        // выходы, для которых собран outbound: на них ссылаются балансировщики
        const pairs = targets.flatMap((x) => {
          const xi = this.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct'`, t.id, x.id)[0];
          return !xi || (sp.security === 'reality' && !xi.public_key) ? [] : [{ x, xi }];
        });
        const ready = pairs.map((p) => p.x);
        const via = this.viaUsers(t, ready, users);
        let failover = false;
        for (const { x, xi } of pairs) {
          const outTag = `to-${t.id}-${x.id}`;
          const leg = this.legTarget(t, x);
          if (sp.protocol === 'hysteria2') outbounds.push(socksOut(outTag, legPort(t.id, x.id)));
          else if (!leg) outbounds.push(relayLive(xrayOutbound(sp, xi, outTag, x.host, this.svcCred(`relay:${t.id}:${server.id}:${x.id}`), x.id)));
          else {
            // два плеча: выход — это loopback в балансировщик «основное плечо, если отвечает, иначе резервное». Основное —
            // протокол конфигурации, у eskadra — её входной протокол (VLESS или Hysteria2), резервное — другой.
            // Для «Авто», проб и явных «вход → выход» выход один (to-…) и жив, пока отвечает хоть одно плечо
            failover = true;
            const vl = `vl-${t.id}-${x.id}`, hyLeg = `hy-${t.id}-${x.id}`, lvl = `lg-${t.id}-${x.id}`, fo = `fo-${t.id}-${x.id}`;
            const [main, back] = hy2Entry(sp) ? [hyLeg, vl] : [vl, hyLeg];
            outbounds.push(relayLive(xrayOutbound(sp, xi, vl, x.host, this.svcCred(`relay:${t.id}:${server.id}:${x.id}`), x.id)),
              socksOut(hyLeg, legPort(t.id, x.id)), { tag: outTag, protocol: 'loopback', settings: { inboundTag: lvl } });
            balancers.push({ tag: fo, selector: [main], fallbackTag: back, strategy: { type: 'leastLoad', settings: { expected: 1, tolerance: 0.5 } } });
            rules.push({ type: 'field', inboundTag: [lvl], balancerTag: fo });
          }
          if (sp.autoEnabled && sp.autoMode !== 'random') {
            // локальный SOCKS для проб: панель меряет задержку и скорость именно этого выхода
            inbounds.push({ tag: `probe-${t.id}-${x.id}`, listen: '127.0.0.1', port: probePort(t.id, x.id), protocol: 'socks', settings: { udp: false } });
            rules.push({ type: 'field', inboundTag: [`probe-${t.id}-${x.id}`], outboundTag: outTag });
          }
          const us = via.perExit.get(x.id)!;
          if (hy) { if (us.length) rules.push({ type: 'field', inboundTag: [hin(x.id)], outboundTag: outTag }); continue; }
          const emails = us.map((u) => `${u.id}.v-${x.id}`);
          us.forEach((u, k) => clients.push(xrayClient(isp, this.cred(u.id, `v:${t.id}:${x.id}`), emails[k]!)));
          if (emails.length) rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], user: emails, outboundTag: outTag });
        }
        // основное плечо проверяется часто: не отвечает — трафик выхода за ~10 с уходит на резервное и возвращается сам
        if (failover) { observed.push(hy2Entry(sp) ? `hy-${t.id}-` : `vl-${t.id}-`); fastObserve = true; }
        // авто-выбор выхода выключен — ни клиентов «авто», ни балансировщиков, ни проверок выходов
        if (ready.length && sp.autoEnabled) {
          const autoUsers = via.auto.map((u) => u.id);
          const autoEmails = hy ? [] : autoUsers.map((id) => `${id}.a-${t.id}`);
          via.auto.forEach((u, k) => { if (!hy) clients.push(xrayClient(isp, this.cred(u.id, `v:${t.id}:auto`), autoEmails[k]!)); });
          const autoMatch = hy ? (autoUsers.length ? { inboundTag: [hin('auto')] } : null) : autoEmails.length ? { inboundTag: [`in-${ib.id}`], user: autoEmails } : null;
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
          if (autoMatch && sp.autoMode !== 'spread') rules.push({ type: 'field', ...autoMatch, balancerTag: `bal-${t.id}` });
        }
        // Hysteria2: inbound'а в Xray нет — его держит sing-box входа
        if (hy) continue;
        // всё прочее с входа, не попавшее в правила, не выпускаем наружу с самого входа
        rules.push({ type: 'field', inboundTag: [`in-${ib.id}`], outboundTag: 'block' });
      }
      inbounds.push(xrayInbound(isp, ib, `in-${ib.id}`, clients, {
        privateKey: ib.private_key_sealed ? this.ctx.open(ib.private_key_sealed) : undefined,
        cert: certName(isp, t.id, server.id, server.host),
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
    // relay — Hysteria2 через вход в режиме core (у пересылки ядром ОС на входе ядра нет) и вход eskadra по Hysteria2
    const ibs = this.inbounds(`server_id = ? AND state IN ('active','deploying')`, server.id)
      .filter((i) => {
        const t = this.template(i.template_id);
        if (!t) return false;
        return t.core === 'sing-box' ? i.kind === 'direct' || !natRelayOf(this.spec(t)) : i.kind === 'relay' && hy2Entry(this.spec(t));
      });
    const legs = this.entryLegs(server);
    if (!ibs.length && !legs.length) return null;
    const users = this.users(true);
    const outbounds: object[] = [{ type: 'direct', tag: 'direct' }];
    // маршруты входа — раньше общих правил: трафик уходит в Xray входа или по плечу на выход, частные адреса и блокировки
    // уже проверил Xray входа (и проверит выход), резолвить домены на входе незачем
    const relayRules: object[] = [];
    const inbounds: object[] = ibs.map((ib) => {
      const t = this.template(ib.template_id)!;
      const sp = ib.kind === 'relay' ? entrySpec(this.spec(t)) : this.spec(t);
      const cert = certName(sp, t.id, server.id, server.host);
      const self = sp.sni[0] ?? 'localhost';
      let list: Array<{ name: string; password: string }>;
      if (ib.kind === 'relay') {
        // пользователи «вход → выход» и «вход → авто» — в свой локальный SOCKS Xray входа, а выход выбирает Xray
        const ready = this.relayTargets(t);
        const via = this.viaUsers(t, ready, users);
        const routes: Array<[string, UserRow[], string]> = [...ready.map((x) => [x.id, via.perExit.get(x.id)!, `v-${x.id}`] as [string, UserRow[], string]), ['auto', via.auto, `a-${t.id}`]];
        list = [];
        for (const [route, us, suffix] of routes) {
          if (!us.length) continue;
          const names = us.map((u) => `${u.id}.${suffix}`);
          us.forEach((u, k) => list.push({ name: names[k]!, password: this.cred(u.id, `v:${t.id}:${route}`) }));
          const tag = `hin-${ib.id}-${route}`;
          outbounds.push({ type: 'socks', tag, server: '127.0.0.1', server_port: hinPort(ib.id, route), version: '5' });
          relayRules.push({ inbound: [`in-${ib.id}`], auth_user: names, outbound: tag });
        }
        relayRules.push({ inbound: [`in-${ib.id}`], action: 'reject' });
        list.push({ name: 'svc.panel', password: this.svcCred(`hy:${t.id}:${server.id}`) });
      } else if (sp.companionOf) {
        // служебная Hysteria2 «eskadra»: пользователи сюда не подключаются, только плечи входа
        list = this.hy2SvcUsers(t, server);
      } else {
        list = [
          ...users
            .filter((u) => json<string[]>(u.modes, []).includes('direct') && server.direct_access && this.userAllows(u, server.id, t.id) && !this.profileOff(u, `d:${t.id}:${server.id}`))
            .map((u) => ({ name: `${u.id}.d-${t.id}`, password: this.cred(u.id, `t:${t.id}`) })),
          // «вход → этот выход»: вход пересылает UDP ядром ОС, пароль профиля проверяет сам выход
          ...(t.entry_id && natRelayOf(sp) && json<string[]>(t.node_ids, []).filter((id) => id !== t.entry_id)[0] === server.id ? users
            .filter((u) => json<string[]>(u.modes, []).includes('via') && this.userAllows(u, server.id, t.id) && !this.profileOff(u, `v:${t.id}:${server.id}`))
            .map((u) => ({ name: `${u.id}.v-${server.id}`, password: this.cred(u.id, `v:${t.id}:${server.id}`) })) : []),
          ...this.hy2SvcUsers(t, server),
        ];
      }
      return {
        type: 'hysteria2', tag: `in-${ib.id}`, listen: '::', listen_port: ib.port,
        users: list,
        ...hy2InboundExtra(sp),
        tls: {
          enabled: true, server_name: tlsServerName(sp, server.id) || self, alpn: ['h3'],
          ...(cert
            ? { certificate_path: `/etc/eskadra/tls/${cert}/fullchain.pem`, key_path: `/etc/eskadra/tls/${cert}/privkey.pem` }
            : { certificate_path: `/etc/eskadra/sing-box/tls/${self}.crt`, key_path: `/etc/eskadra/sing-box/tls/${self}.key` }),
        },
      };
    });
    // плечи Hysteria2 к выходам: локальный SOCKS для Xray входа → Hysteria2 на inbound выхода
    for (const l of legs) {
      inbounds.push({ type: 'socks', tag: `leg-${l.tag}`, listen: '127.0.0.1', listen_port: l.port });
      outbounds.push(l.out);
      relayRules.push({ inbound: [`leg-${l.tag}`], outbound: l.tag });
    }
    return {
      log: { level: 'warn' },
      inbounds,
      outbounds,
      // распознать протокол (BitTorrent: TCP, uTP, UDP-трекеры), затем домен резолвится, локальные и частные адреса
      // отклоняются, затем блокировки протоколов (sing-box ≥ 1.11)
      route: { rules: [
        ...relayRules,
        ...(needsSniff(blocks) ? [{ action: 'sniff' }] : []),
        { action: 'resolve' }, { ip_cidr: PRIVATE_NETS, action: 'reject' },
        ...singboxBlockRules(blocks),
      ] },
    };
  }

  /** Смена портов Hysteria2 на узле: «порт:начало-конец» через запятую (UDP с диапазона перенаправляется на порт inbound'а); '-' — нет. */
  hy2Hops(server: ServerRow): string {
    // inbound входа есть только у Hysteria2 через вход в режиме core (пересылка ядром ОС ведёт диапазон на выход сама)
    const hops = this.inbounds(`server_id = ? AND state IN ('active','deploying')`, server.id)
      .flatMap((ib) => {
        const t = this.template(ib.template_id);
        // inbound Hysteria2 на узле: direct, вход Hysteria2 в режиме core и вход eskadra по Hysteria2
        const sp = t && (ib.kind === 'relay' ? entrySpec(this.spec(t)) : this.spec(t));
        const r = sp?.protocol === 'hysteria2' && (ib.kind === 'direct' || !natRelayOf(sp)) ? hopRange(sp.hy2Hop) : null;
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
      if (!t || !natRelayOf(this.spec(t))) continue;
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
      .map((u) => ({ name: `${u.id}.d-${t.id}`, secret: this.cred(u.id, `t:${t.id}`), maxIps: effectiveLimits(this.ctx, u).devices as number | null }));
    // telemt без единого пользователя не запускается («No users configured»): новая конфигурация, которую ещё никому
    // не выдали, иначе падает при выкате. Служебный пользователь панели держит ядро запущенным
    users.push({ name: 'svc.panel', secret: this.svcCred(`mt:${t.id}:${server.id}`), maxIps: null });
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

/** Outbound Xray в локальный SOCKS (плечо Hysteria2 через sing-box входа). */
const socksOut = (tag: string, port: number) => ({ tag, protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port }] } });

export const orderBalancer =(templateId: string, i: number) => (i ? `bal-${templateId}-${i + 1}` : `bal-${templateId}`);

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
