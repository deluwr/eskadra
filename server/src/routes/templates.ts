import type { FastifyInstance } from 'fastify';
import { createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { getSetting, setSetting } from '../db.js';
import { z } from 'zod';
import { Ctx, guard, HttpError, type TemplateRow } from '../ctx.js';
import { audit } from '../lib/audit.js';
import { medianSpeed, Ops, startJob } from '../ops.js';
import { json, Vpn } from '../vpn.js';
import { checkTemplateQuota, checkTemplateServers, roleOf, ScopeError } from '../roles.js';
import { hopRange, hy2Entry, natRelayOf, PROTOCOLS, SS_METHODS, specOf, usesXhttp, xhttpPath, type Protocol } from '../protocols.js';

/** Число или диапазон «16-32» для тонкой настройки XHTTP; пусто — по умолчанию Xray. */
const xRange = z.string().max(24).regex(/^(\d{1,9}(-\d{1,9})?)?$/, 'XHTTP: число или диапазон вида 16-32').optional();

const settingsBody = z.object({
  security: z.enum(['reality', 'tls', 'none']).optional(),
  transport: z.enum(['tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade']).optional(),
  flow: z.enum(['', 'xtls-rprx-vision']).optional(),
  path: z.string().max(256).regex(/^\/[\x21-\x7e]*$/, 'путь начинается с /').optional(),
  host: z.string().max(253).regex(/^[A-Za-z0-9.-]*$/).optional(),
  serviceName: z.string().max(64).regex(/^[A-Za-z0-9._-]*$/).optional(),
  xhttpMode: z.enum(['auto', 'packet-up', 'stream-up', 'stream-one']).optional(),
  alpn: z.array(z.enum(['h3', 'h2', 'http/1.1'])).max(3).optional(),
  certMode: z.enum(['ip', 'domain', 'custom', 'self']).optional(),
  domain: z.string().max(253).regex(/^[A-Za-z0-9.*-]*$/).optional(),
  domains: z.record(z.string(), z.string().max(253).regex(/^[A-Za-z0-9.-]+$/)).optional(),
  ssMethod: z.enum(SS_METHODS).optional(),
  hy2Obfs: z.string().max(128).optional(),
  hy2UpMbps: z.number().int().min(0).max(100000).optional(),
  hy2DownMbps: z.number().int().min(0).max(100000).optional(),
  hy2ServerUpMbps: z.number().int().min(0).max(100000).optional(),
  hy2ServerDownMbps: z.number().int().min(0).max(100000).optional(),
  hy2IgnoreClientBw: z.boolean().optional(),
  hy2Masquerade: z.union([z.literal(''), z.string().max(512).regex(/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[!-~]*)?$/, 'сайт маскировки: адрес вида https://www.bing.com/')]).optional(),
  hy2Hop: z.string().max(16).regex(/^(\d{1,5}-\d{1,5})?$/, 'диапазон портов: вида 20000-30000').optional(),
  hy2HopInterval: z.number().int().min(5).max(3600).optional(),
  mtDomain: z.string().max(253).regex(/^[A-Za-z0-9.-]*$/).optional(),
  sniffing: z.boolean().optional(),
  autoEnabled: z.boolean().optional(),
  autoMode: z.enum(['random', 'smart', 'order', 'spread']).optional(),
  exitOrder: z.array(z.string().max(64)).max(64).optional(),
  maxRttMs: z.number().int().min(20).max(2000).optional(),
  minMbps: z.number().min(0.5).max(10000).optional(),
  checkMin: z.number().int().min(5).max(1440).optional(),
  testMB: z.number().int().min(1).max(100).optional(),
  orderMinMbps: z.number().min(0).max(10000).optional(),
  speedEveryMin: z.number().int().min(1).max(1440).optional(),
  decideMin: z.number().int().min(1).max(1440).optional(),
  spreadGroups: z.number().int().min(2).max(16).optional(),
  exitCapMbps: z.record(z.string().max(64), z.number().min(0).max(100000)).optional(),
  spreadHighPct: z.number().int().min(30).max(95).optional(),
  spreadFair: z.boolean().optional(),
  hy2Relay: z.enum(['nat', 'core']).optional(),
  hy2Leg: z.string().max(64).optional(),
  bundle: z.boolean().optional(),
  hy2Port: z.number().int().min(0).max(65535).optional(),
  entryProto: z.enum(['vless', 'hysteria2']).optional(),
  entryTransport: z.enum(['', 'tcp', 'xhttp']).optional(),
  cdnMode: z.enum(['packet-up', 'stream-up', 'stream-one']).optional(),
  cdnH3: z.boolean().optional(),
  xhttpExtra: z.object({
    xPaddingBytes: xRange, noGRPCHeader: z.boolean().optional(), noSSEHeader: z.boolean().optional(),
    scMaxEachPostBytes: xRange, scMinPostsIntervalMs: xRange, scMaxBufferedPosts: xRange, scStreamUpServerSecs: xRange,
    xmux: z.object({ maxConcurrency: xRange, maxConnections: xRange, cMaxReuseTimes: xRange, hMaxRequestTimes: xRange, hMaxReusableSecs: xRange, hKeepAlivePeriod: xRange }).optional(),
  }).optional(),
  cdn: z.union([z.literal(''), z.string().max(253).regex(/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/, 'домен CDN: вида cdn.example.com')]).optional(),
}).default({});

const TRANSLIT: Record<string, string> = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya' };
/** Имя конфигурации: строчная латиница, цифры и дефис — регистр и пробелы исправляются сами, кириллица транслитерируется. */
export const slugName = (v: string) => v.toLowerCase().split('').map((c) => TRANSLIT[c] ?? c).join('')
  .replace(/[\s_.]+/g, '-').replace(/[^a-z0-9-]/g, '').replace(/-+/g, '-').replace(/^-/, '').slice(0, 48);

const body = z.object({
  name: z.preprocess((v) => (typeof v === 'string' ? slugName(v).replace(/-$/, '') : v), z.string().min(1, 'имя: укажите латиницей или цифрами').max(48)),
  protocol: z.enum(['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'mtproto']),
  port: z.number().int().min(1).max(65535),
  sni: z.array(z.string().trim().regex(/^[A-Za-z0-9.-]{1,253}$/)).max(16).default([]),
  fingerprint: z.enum(['chrome', 'firefox', 'safari', 'edge', 'random']).default('chrome'),
  ech: z.boolean().default(false),
  nodeIds: z.array(z.string()).default([]),
  entryId: z.string().nullable().default(null),
  entryPort: z.number().int().min(1).max(65535).nullable().default(null),
  settings: settingsBody,
  /** загруженный сертификат (режим custom): полная цепочка и ключ в PEM; хранится зашифрованным */
  customCert: z.object({ fullchain: z.string().max(65536), privkey: z.string().max(16384) }).optional(),
});

let ctx_hasCert: (t: TemplateRow) => boolean = () => false;

export function templateView(vpn: Vpn, t: TemplateRow) {
  return {
    ...t,
    core: t.core,
    sni: json<string[]>(t.sni, []),
    spec: specOf(t),
    hasCustomCert: !!ctx_hasCert(t),
    node_ids: json<string[]>(t.node_ids, []),
    ech: !!t.ech,
    // у «eskadra» — и inbounds её Hysteria2 на выходах (kind hy2): их состояние и ошибки видны в той же карточке
    inbounds: [...vpn.inbounds('template_id = ?', t.id), ...(specOf(t).bundle ? companionOf(vpn, t.id).flatMap((c) => vpn.inbounds('template_id = ?', c.id).map((i) => ({ ...i, kind: 'hy2' as const }))) : [])]
      .map((i) => ({ id: i.id, server_id: i.server_id, kind: i.kind, port: i.port, proto: i.proto, state: i.state, error: i.error })),
  };
}

/** Служебная Hysteria2 «eskadra» (0 или 1 шт.). */
const companionOf = (vpn: Vpn, ownerId: string) => vpn.templates().filter((c) => specOf(c).companionOf === ownerId);

/**
 * Hysteria2 «eskadra» на выходах: создать или обновить служебную конфигурацию по настройкам владельца и сослаться на
 * неё резервным плечом (hy2Leg). Выходы, убранные из «eskadra», теряют её inbound при следующем выкате.
 */
export function syncCompanion(db: Ctx['db'], vpn: Vpn, t: TemplateRow): TemplateRow | null {
  const sp = specOf(t);
  const old = companionOf(vpn, t.id)[0];
  if (!sp.bundle) return old ?? null;
  const exits = json<string[]>(t.node_ids, []).filter((id) => id !== t.entry_id);
  const settings = JSON.stringify({
    certMode: 'self', companionOf: t.id, hy2Obfs: sp.hy2Obfs, hy2Hop: sp.hy2Hop, hy2HopInterval: sp.hy2HopInterval,
    hy2UpMbps: sp.hy2UpMbps, hy2DownMbps: sp.hy2DownMbps, hy2ServerUpMbps: sp.hy2ServerUpMbps, hy2ServerDownMbps: sp.hy2ServerDownMbps,
    hy2IgnoreClientBw: sp.hy2IgnoreClientBw, hy2Masquerade: sp.hy2Masquerade,
  });
  // самоподписанный сертификат на выходе: плечо — служебный канал входа, имя в сертификате — сайт маскировки VLESS
  const sni = JSON.stringify([sp.sni[0] || 'www.bing.com']);
  const port = sp.hy2Port || t.port;
  const nodes = JSON.stringify(exits);
  // имя — «<имя>-hy2»; занято другой конфигурацией — с хвостом
  const free = (n: string) => !db.prepare('SELECT 1 FROM templates WHERE name = ? AND id != ?').get(n, old?.id ?? '');
  const want = `${t.name.slice(0, 44)}-hy2`;
  const name = free(want) ? want : old?.name ?? `${t.name.slice(0, 39)}-hy2-${randomBytes(2).toString('hex')}`;
  const id = old?.id ?? 'tpl-' + randomBytes(3).toString('hex');
  if (!old) {
    db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES (?, ?, 'sing-box', 'hysteria2', ?, ?, ?, ?)`)
      .run(id, name, port, sni, nodes, settings);
  } else if (old.name !== name || old.port !== port || old.sni !== sni || old.node_ids !== nodes || old.settings !== settings) {
    db.prepare(`UPDATE templates SET name = ?, port = ?, sni = ?, node_ids = ?, settings = ?, revision = revision + 1, updated_at = datetime('now') WHERE id = ?`)
      .run(name, port, sni, nodes, settings, id);
    for (const ib of vpn.inbounds('template_id = ?', id))
      if (!exits.includes(ib.server_id)) db.prepare(`UPDATE inbounds SET state = 'removed' WHERE id = ?`).run(ib.id);
  }
  if (sp.hy2Leg !== id) db.prepare('UPDATE templates SET settings = ? WHERE id = ?').run(JSON.stringify({ ...json<Record<string, unknown>>(t.settings, {}), hy2Leg: id }), t.id);
  return vpn.template(id)!;
}

export async function templateRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const ops = new Ops(ctx);
  const vpn = ops.vpn;
  ctx_hasCert = (t) => !!getSetting(db, `cert.${t.id}`, null);
  const running = new Set<string>();
  /** Загруженный сертификат шаблона (режим custom): проверяем, что ключ подходит к сертификату, храним зашифрованным. */
  const saveCert = (id: string, c?: { fullchain: string; privkey: string }) => {
    if (!c) return;
    try {
      const cert = new X509Certificate(c.fullchain);
      if (!cert.checkPrivateKey(createPrivateKey(c.privkey))) throw new Error('ключ не подходит к сертификату');
      if (new Date(cert.validTo) < new Date()) throw new Error(`сертификат истёк ${cert.validTo}`);
    } catch (e) {
      throw new HttpError(400, `сертификат: ${(e as Error).message}`);
    }
    setSetting(db, `cert.${id}`, { fullchain: c.fullchain, privkey: ctx.seal(c.privkey) });
  };

  const validate = (b: z.infer<typeof body>, selfId?: string) => {
    const missing = [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])].filter((id) => !ctx.servers().some((s) => s.id === id));
    if (missing.length) throw new HttpError(400, `в конфигурации серверы, которых уже нет в панели (${missing.join(', ')}) — обновите страницу`);
    const info = PROTOCOLS[b.protocol as Protocol];
    const sp = specOf({ protocol: b.protocol, sni: JSON.stringify(b.sni), fingerprint: b.fingerprint, settings: JSON.stringify(b.settings) });
    const nat = natRelayOf(sp);
    if (b.entryId) {
      if (!info.relay) throw new HttpError(400, `режим «через вход» не поддерживается для ${info.name}`);
      if (!b.entryPort) throw new HttpError(400, 'укажите порт входа');
      if (nat) {
        // вход пересылает UDP ядром ОС на один адрес — выход ровно один, и это не сам вход
        if (b.nodeIds.includes(b.entryId)) throw new HttpError(400, `${info.name} через вход: вход только пересылает трафик на выход — уберите «и сам принимает напрямую»`);
        if (b.nodeIds.length !== 1) throw new HttpError(400, `${info.name} через вход: выберите один выход`);
        const x = ctx.server(b.nodeIds[0]!);
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(x.host)) throw new HttpError(400, `${info.name} через вход: у выхода ${x.name} адрес должен быть IPv4 (сейчас «${x.host}»)`);
      }
      if (sp.protocol === 'hysteria2' && !nat && b.settings.autoMode === 'spread')
        throw new HttpError(400, 'Hysteria2 через вход: «по нагрузке» недоступно (пользователей на входе различает sing-box, а не Xray) — выберите «по порядку» или «по качеству»');
    }
    // своя Hysteria2 «eskadra» — служебная, её id сюда вписывает панель (syncCompanion)
    const own = new Set([selfId ?? '', ...(selfId ? companionOf(vpn, selfId).map((c) => c.id) : [])]);
    if (b.settings.bundle) {
      if (b.protocol !== 'vless') throw new HttpError(400, '«eskadra» строится на VLESS');
      if (!b.entryId) throw new HttpError(400, '«eskadra»: выберите сервер-вход');
      if (!b.nodeIds.some((id) => id !== b.entryId)) throw new HttpError(400, '«eskadra»: выберите хотя бы один выход');
      if (sp.entryProto === 'hysteria2' && b.settings.autoMode === 'spread')
        throw new HttpError(400, '«eskadra» со входом по Hysteria2: «по нагрузке» недоступно (пользователей на входе различает sing-box, а не Xray) — выберите «по порядку» или «по качеству»');
    } else if (sp.hy2Leg) {
      // резервное плечо Hysteria2: inbounds той конфигурации на выходах этой
      const h = vpn.template(sp.hy2Leg);
      if (!b.entryId) throw new HttpError(400, 'резервное плечо Hysteria2 — только для конфигурации через вход');
      if (!h || specOf(h).protocol !== 'hysteria2' || (specOf(h).companionOf && !own.has(h.id))) throw new HttpError(400, 'резервное плечо: выберите существующую конфигурацию Hysteria2');
      const hNodes = json<string[]>(h.node_ids, []);
      if (!b.nodeIds.some((id) => id !== b.entryId && hNodes.includes(id)))
        throw new HttpError(400, `резервное плечо: у конфигурации «${h.name}» нет ни одного из выходов этой — добавьте их туда`);
    }
    if (sp.security === 'reality' && !b.sni.length) throw new HttpError(400, 'для REALITY укажите сайт маскировки (SNI)');
    if (sp.transport === 'xhttp' && sp.protocol !== 'vless') throw new HttpError(400, 'XHTTP — только для VLESS');
    // свой транспорт входа и CDN — у VLESS через вход (вход eskadra по Hysteria2 принимает не VLESS)
    const entryOnly = (what: string) => {
      if (b.protocol !== 'vless' || !b.entryId) throw new HttpError(400, `${what} — только для VLESS через вход`);
      if (b.settings.bundle && b.settings.entryProto === 'hysteria2') throw new HttpError(400, `${what}: вход принимает Hysteria2 — выберите вход по VLESS`);
    };
    if (b.settings.entryTransport) {
      entryOnly('XHTTP только для клиентов или только между серверами');
      if (!['tcp', 'xhttp'].includes(sp.transport)) throw new HttpError(400, 'разный транспорт у входа и выходов — только TCP и XHTTP');
    }
    if (b.settings.cdn) entryOnly('вход за CDN');
    const xe = b.settings.xhttpExtra;
    if (xe?.xmux?.maxConcurrency && xe.xmux.maxConnections) throw new HttpError(400, 'XMUX: «потоков на соединение» и «соединений» вместе не задаются — Xray принимает одно из двух');
    for (const v of [xe?.xPaddingBytes, xe?.scMaxEachPostBytes, xe?.scMinPostsIntervalMs, xe?.scMaxBufferedPosts, xe?.scStreamUpServerSecs, ...Object.values(xe?.xmux ?? {})]) {
      const [lo, hi] = String(v ?? '').split('-').map(Number);
      if (hi !== undefined && hi < lo!) throw new HttpError(400, `XHTTP: в диапазоне ${v} начало больше конца`);
    }
    // у пересылки ядром ОС сертификат только на выходе; у входа за CDN — свой самоподписанный под домен CDN
    const certIds = [...b.nodeIds, ...(b.entryId && !nat && !sp.cdn ? [b.entryId] : [])];
    if ((sp.security === 'tls' || sp.protocol === 'hysteria2') && sp.certMode === 'domain')
      for (const id of certIds)
        if (!sp.domains[id]) throw new HttpError(400, `укажите домен для сервера ${ctx.server(id).name}`);
    if ((sp.security === 'tls' || sp.protocol === 'hysteria2') && sp.certMode === 'ip')
      for (const id of certIds)
        if (!/^[0-9.]+$|:/.test(ctx.server(id).host)) throw new HttpError(400, `сертификат на IP: у сервера ${ctx.server(id).name} адрес — домен; выберите «свой домен»`);
    // у «eskadra» Hysteria2 — на выходах (вход принимает VLESS)
    if (sp.protocol === 'hysteria2' || sp.bundle) {
      if (!sp.hy2UpMbps !== !sp.hy2DownMbps) throw new HttpError(400, 'полоса клиента: укажите и отдачу, и загрузку (или обе 0)');
      if (sp.hy2IgnoreClientBw && (sp.hy2ServerUpMbps || sp.hy2ServerDownMbps)) throw new HttpError(400, 'BBR на сервере несовместим с потолком полосы — уберите одно из двух');
      if (sp.hy2Hop) {
        const r = hopRange(sp.hy2Hop);
        if (!r) throw new HttpError(400, 'диапазон портов: от 1024 до 65535, начало меньше конца');
        if (r[1] - r[0] > 20000) throw new HttpError(400, 'диапазон портов: не больше 20000 портов');
        // UDP с диапазона уходит в этот inbound (через вход — и с входа на выход): порты других конфигураций и SSH внутри диапазона перестанут работать
        // у eskadra диапазон — на выходах, а при входе по Hysteria2 и на входе
        for (const id of sp.bundle && !hy2Entry(sp) ? b.nodeIds.filter((x) => x !== b.entryId) : [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])]) {
          const s = ctx.server(id);
          const ssh = json<number[]>(s.ssh_ports, []).find((p) => p >= r[0] && p <= r[1]);
          if (ssh) throw new HttpError(400, `диапазон портов задевает SSH ${ssh} на сервере ${s.name}`);
          const clash = vpn.inbounds(`server_id = ? AND proto = 'udp' AND state IN ('active','deploying')`, id)
            .find((i) => !own.has(i.template_id) && i.port >= r[0] && i.port <= r[1]);
          if (clash) throw new HttpError(400, `диапазон портов задевает UDP-порт ${clash.port} другой конфигурации на сервере ${s.name}`);
          const other = vpn.templates().filter((t) => !own.has(t.id) && (json<string[]>(t.node_ids, []).includes(id) || t.entry_id === id)).map((t) => [t, hopRange(vpn.spec(t).hy2Hop)] as const)
            .find(([, o]) => o && o[0] <= r[1] && r[0] <= o[1]);
          if (other) throw new HttpError(400, `диапазон портов пересекается с диапазоном «${other[0].name}» на сервере ${s.name}`);
        }
      }
    }
  };

  /**
   * XHTTP одной опцией: путь панель подставляет сама — прежний у этой конфигурации или случайный, «/» сканеры
   * проверяют первым. Режим (auto) и выключение Vision у XHTTP — в specOf, порт CDN — в интерфейсе.
   */
  const autoFill = (b: z.infer<typeof body>, old?: TemplateRow) => {
    const sp = specOf({ protocol: b.protocol, sni: JSON.stringify(b.sni), fingerprint: b.fingerprint, settings: JSON.stringify(b.settings) });
    if (!usesXhttp(sp) || (b.settings.path && b.settings.path !== '/')) return;
    const prev = old && specOf(old).path;
    b.settings.path = prev && prev !== '/' ? prev : xhttpPath();
  };

  /** Служебную Hysteria2 «eskadra» меняют, выкатывают и снимают только вместе с её конфигурацией. */
  const notCompanion = (t: TemplateRow) => {
    const owner = specOf(t).companionOf;
    if (owner) throw new HttpError(409, `«${t.name}» — часть конфигурации «${vpn.template(owner)?.name ?? owner}»: меняйте и выкатывайте её`);
  };

  const scoped = (f: () => void) => { try { f(); } catch (e) { if (e instanceof ScopeError) throw new HttpError(403, e.message); throw e; } };

  // служебная Hysteria2 «eskadra» — часть своей конфигурации, отдельно не показывается
  app.get('/api/v1/templates', async () => vpn.userTemplates().map((t) => templateView(vpn, t)));

  /**
   * Случайные свободные порты для новой конфигурации: на каждом из серверов проходят ту же проверку, что при выкате
   * (не SSH, не резерв, не занят шаблоном или процессом по последнему preflight, в диапазоне группы), и не совпадают
   * с портами других конфигураций — чтобы их можно было добавить на любой сервер позже. Нет серверов — все подключённые.
   */
  app.get<{ Querystring: { proto?: string; servers?: string; count?: string; avoid?: string } }>('/api/v1/free-ports', async (req) => {
    const proto = req.query.proto === 'udp' ? 'udp' : 'tcp';
    const count = Math.min(4, Math.max(1, Number(req.query.count) || 1));
    const ids = (req.query.servers ?? '').split(',').filter(Boolean);
    const all = ctx.servers().filter((s) => s.sudo_mode === 'restricted');
    const servers = ids.length ? all.filter((s) => ids.includes(s.id)) : all;
    const taken = new Set<number>([
      ...vpn.templates().flatMap((t) => [t.port, t.entry_port ?? 0]),
      ...(req.query.avoid ?? '').split(',').map(Number).filter(Boolean),
      10085, 51820, 54321, 2053, 2096, 8443,
    ]);
    // кандидаты — из разрешённого диапазона группы первого сервера (остальные проверит lintPort); без группы — 1024–65535
    const g = servers[0] && (db.prepare('SELECT port_range FROM groups WHERE name = ?').get(servers[0].group_name) as { port_range: string } | undefined);
    const spans = (g?.port_range ?? '1024-65535').split(',').map((x) => x.trim().split('-').map(Number))
      .map(([a, b]) => [a!, b ?? a!] as [number, number]).filter(([a, b]) => a >= 1 && b <= 65535 && a <= b);
    // предпочтительно — высокие порты (реже заняты и реже сканируются), если диапазон их включает
    const high = spans.map(([a, b]) => [Math.max(a, 20000), Math.min(b, 60000)] as [number, number]).filter(([a, b]) => a <= b);
    const pick = (list: Array<[number, number]>) => {
      const total = list.reduce((n, [a, b]) => n + b - a + 1, 0);
      let k = Math.floor(Math.random() * total);
      for (const [a, b] of list) { if (k <= b - a) return a + k; k -= b - a + 1; }
      return list[0]![0];
    };
    const ports: number[] = [];
    const tryPort = (p: number) => {
      if (ports.length >= count || taken.has(p) || servers.some((s) => ops.lintPort(s, p, proto))) return;
      ports.push(p);
      taken.add(p);
    };
    for (const list of [high, spans]) if (list.length) for (let i = 0; i < 300 && ports.length < count; i++) tryPort(pick(list));
    // узкий или почти занятый диапазон — перебором с случайного места
    if (ports.length < count && spans.length) {
      const all = spans.flatMap(([a, b]) => (b - a < 70000 ? Array.from({ length: b - a + 1 }, (_, i) => a + i) : []));
      const start = Math.floor(Math.random() * all.length);
      for (let i = 0; i < all.length && ports.length < count; i++) tryPort(all[(start + i) % all.length]!);
    }
    if (ports.length < count) throw new HttpError(409, 'не нашёл свободный порт — проверьте диапазоны портов групп серверов');
    return { ports };
  });

  app.post('/api/v1/templates', { preHandler: guard(ctx, 'configs.edit') }, async (req) => {
    const b = body.parse(req.body);
    const role = roleOf(db, req.admin!.role);
    // роль с ограниченным списком конфигураций новую не создаёт: она оказалась бы вне её области
    if (!role.owner && role.scope.templates) throw new HttpError(403, `роль «${role.name}» работает только со своими конфигурациями — новую создаёт owner или роль без ограничения`);
    scoped(() => checkTemplateServers(role, [], [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])]));
    validate(b);
    autoFill(b);
    // лимит роли на число конфигураций, которые создаёт её администратор
    scoped(() => checkTemplateQuota(db, role, req.admin!.id));
    const id = 'tpl-' + randomBytes(3).toString('hex');
    db.prepare(
      `INSERT INTO templates (id, name, core, protocol, port, sni, fingerprint, ech, node_ids, entry_id, entry_port, settings, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, b.name, PROTOCOLS[b.protocol as Protocol].core, b.protocol, b.port, JSON.stringify(b.sni), b.fingerprint,
      b.ech ? 1 : 0, JSON.stringify(b.nodeIds), b.entryId, b.entryPort, JSON.stringify(b.settings), req.admin!.id);
    saveCert(id, b.customCert);
    syncCompanion(db, vpn, vpn.template(id)!);
    audit(db, req.admin!.username, 'template.create', id, b);
    return templateView(vpn, vpn.template(id)!);
  });

  app.put<{ Params: { id: string } }>('/api/v1/templates/:id', { preHandler: guard(ctx, 'configs.edit') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    notCompanion(t);
    const b = body.parse(req.body);
    validate(b, t.id);
    autoFill(b, t);
    if (b.protocol !== specOf(t).protocol) throw new HttpError(400, 'протокол шаблона менять нельзя — создайте новый');
    scoped(() => checkTemplateServers(roleOf(db, req.admin!.role), [...json<string[]>(t.node_ids, []), ...(t.entry_id ? [t.entry_id] : [])], [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])]));
    db.prepare(
      `UPDATE templates SET name = ?, port = ?, sni = ?, fingerprint = ?, ech = ?, node_ids = ?, entry_id = ?, entry_port = ?, settings = ?,
       revision = revision + 1, updated_at = datetime('now') WHERE id = ?`,
    ).run(b.name, b.port, JSON.stringify(b.sni), b.fingerprint, b.ech ? 1 : 0, JSON.stringify(b.nodeIds), b.entryId, b.entryPort, JSON.stringify(b.settings), t.id);
    saveCert(t.id, b.customCert);
    syncCompanion(db, vpn, vpn.template(t.id)!);
    // узлы, убранные из шаблона, теряют inbound при следующем выкате
    const keep = new Set([...b.nodeIds.map((id) => `${id}:direct`), ...(b.entryId ? [`${b.entryId}:relay`] : [])]);
    for (const ib of vpn.inbounds('template_id = ?', t.id))
      if (!keep.has(`${ib.server_id}:${ib.kind}`)) db.prepare(`UPDATE inbounds SET state = 'removed' WHERE id = ?`).run(ib.id);
    audit(db, req.admin!.username, 'template.update', t.id, b);
    return templateView(vpn, vpn.template(t.id)!);
  });

  /** Состояние выходов «Авто через вход»: последние замеры и выбранный выход. */
  app.get<{ Params: { id: string } }>('/api/v1/templates/:id/health', async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const rows = db.prepare(`SELECT h.exit_id, s.name, s.host, h.rtt_ms, h.mbps, h.ok, h.error, h.exit_ip, h.exit_loc, h.checked_at, h.checked_at >= datetime('now', '-30 minutes') AS fresh FROM exit_health h JOIN servers s ON s.id = h.exit_id WHERE h.template_id = ? ORDER BY s.name`).all(t.id);
    const ov = getSetting<string | null>(db, `auto.override.${t.id}`, null);
    const act = getSetting<string | null>(db, `auto.actual.${t.id}`, null);
    const id = (tag: string | null) => (tag ? tag.slice(`to-${t.id}-`.length) : null);
    // selected — что назначила панель; actual — через какой выход вход реально ведёт трафик (по данным Xray входа)
    return { rows, selected: id(ov), actual: id(act), checkedAt: getSetting<string>(db, `auto.checked.${t.id}`, '') || null,
      slow: getSetting<string[]>(db, `auto.slow.${t.id}`, []), speedAt: getSetting<string>(db, `auto.speedAt.${t.id}`, '') || null,
      decideAt: getSetting<string>(db, `auto.decideAt.${t.id}`, '') || null,
      // медиана скорости за окно решения — то, по чему выход пропускается
      median: Object.fromEntries(vpn.relayTargets(t).map((x) => [x.id, medianSpeed(ctx, t.id, x.id, specOf(t).decideMin)])),
      // «по нагрузке»: загрузка каналов выходов и где сейчас каждая группа (последняя проверка)
      spread: specOf(t).autoMode === 'spread' ? getSetting<unknown>(db, `spread.state.${t.id}`, null) : null };
  });

  app.post<{ Params: { id: string } }>('/api/v1/templates/:id/health/check', { preHandler: guard(ctx, 'configs.rollout') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const lines: string[] = [];
    const r = await ops.checkExits(t, (l) => lines.push(l), { force: true });   // по кнопке — и замер скорости
    if (!r) throw new HttpError(409, 'проверка выходов работает для конфигурации со входом и включённым авто-выбором выхода (кроме режима «случайно»)');
    audit(db, req.admin!.username, 'template.exits_check', t.id, { switched: r.switched });
    return { ...r, log: lines };
  });

  app.get<{ Params: { id: string }; Querystring: { server?: string } }>('/api/v1/templates/:id/preview', async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const sid = req.query.server ?? json<string[]>(t.node_ids, [])[0] ?? t.entry_id;
    if (!sid) return { config: null };
    const s = ctx.server(sid);
    const cfg = t.core === 'xray' ? vpn.renderXray(s) : t.core === 'sing-box' ? vpn.renderSingbox(s) : vpn.renderTelemt(s);
    if (!cfg) return { server: sid, config: null };
    // приватные ключи, UUID, пароли и секреты MTProto в предпросмотре скрываем
    const text = (typeof cfg === 'string' ? cfg : JSON.stringify(cfg, null, 2))
      .replace(/("privateKey": ")[^"]+/g, '$1‹на узле›')
      .replace(/("(?:id|password)": ")[^"]+/g, '$1‹секрет›')
      .replace(/^(".+" = ")[0-9a-f]{32}"/gm, '$1‹секрет›"');
    return { server: sid, config: text };
  });

  app.post<{ Params: { id: string } }>('/api/v1/templates/:id/rollout', { preHandler: guard(ctx, 'configs.rollout') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    notCompanion(t);
    if (running.has(t.id)) throw new HttpError(409, 'выкат этого шаблона уже идёт');
    const job = startJob(ctx, null, `rollout:${t.name}`);
    running.add(t.id);
    audit(db, req.admin!.username, 'template.rollout', t.id, { revision: t.revision });
    // снять inbounds, убранные из шаблона
    const dropRemoved = async (tid: string) => {
      const removed = vpn.inbounds(`template_id = ? AND state = 'removed'`, tid);
      for (const sid of [...new Set(removed.map((i) => i.server_id))]) {
        const s = ctx.server(sid);
        await ctx.onNode(s, async (n) => {
          await ops.applyServer(s, n, job.log);
          for (const ib of removed.filter((i) => i.server_id === sid))
            if (!ops.portUsed(sid, ib.port, ib.proto)) await n.op(['port-close', ib.proto, ib.port]);
        });
        db.prepare(`DELETE FROM inbounds WHERE template_id = ? AND server_id = ? AND state = 'removed'`).run(tid, sid);
      }
    };
    // выкат идёт в фоне; UI опрашивает задачу
    void (async () => {
      try {
        // «eskadra»: сначала Hysteria2 на выходах (резервные плечи), затем VLESS на выходах и вход
        const hy2 = syncCompanion(db, vpn, vpn.template(t.id)!);
        if (hy2 && specOf(vpn.template(t.id)!).bundle) {
          job.log(`Hysteria2 на выходах («${hy2.name}»)`);
          await dropRemoved(hy2.id);
          await ops.rollout(vpn.template(hy2.id)!, job.log);
          job.log('VLESS: выходы и вход');
        }
        await dropRemoved(t.id);
        await ops.rollout(vpn.template(t.id)!, job.log);
        job.log('готово');
        job.finish('ok');
      } catch (e) {
        job.log(`остановлено: ${(e as Error).message}`);
        job.finish('failed');
      } finally {
        running.delete(t.id);
      }
    })();
    return { jobId: job.id };
  });

  app.get<{ Params: { jobId: string } }>('/api/v1/jobs/:jobId', async (req) =>
    db.prepare('SELECT * FROM jobs WHERE id = ?').get(Number(req.params.jobId)));

  app.delete<{ Params: { id: string } }>('/api/v1/templates/:id', { preHandler: guard(ctx, 'configs.delete') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    notCompanion(t);
    const job = startJob(ctx, null, `remove:${t.name}`);
    await ops.removeTemplate(t, job.log);
    // вместе с «eskadra» снимается её Hysteria2 (после VLESS: плечи входа уже убраны)
    for (const c of companionOf(vpn, t.id)) await ops.removeTemplate(c, job.log);
    job.finish('ok');
    audit(db, req.admin!.username, 'template.delete', t.id);
    return { ok: true };
  });
}
