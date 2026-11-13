import { useEffect, useRef, useState, type ReactNode } from 'react';
import { api, ago, can, inScope, quota, refreshMe, type Job, type Server, type Template, type User } from '../api';
import { exitView, type MapExit } from '../RouteMap';
import { CopyBlock, ErrorBox, Info, Modal, Seg, Switch, Tag, toast, useAsync, usePoll, ask } from '../ui';
import { getLang } from '../i18n';

const TRANSLIT: Record<string, string> = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya' };
/** Имя конфигурации: строчная латиница, цифры и дефис — регистр и пробелы исправляются сами, кириллица транслитерируется. */
export const slugName = (v: string) => v.toLowerCase().split('').map((c) => TRANSLIT[c] ?? c).join('')
  .replace(/[\s_.]+/g, '-').replace(/[^a-z0-9-]/g, '').replace(/-+/g, '-').replace(/^-/, '').slice(0, 48);

/** eskadra — только в интерфейсе: VLESS-конфигурация с bundle (вход, VLESS и Hysteria2 на выходах, авто-выбор и резерв) */
type Protocol = 'eskadra' | 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'mtproto';
type Security = 'reality' | 'tls' | 'none';
type Transport = 'tcp' | 'ws' | 'grpc' | 'xhttp' | 'httpupgrade';
type CertMode = 'ip' | 'domain' | 'custom' | 'self';

/** Что поддерживает протокол (как в protocols.ts на сервере). */
const PROTO: Record<Protocol, { name: string; hint: string; core: string; sec: Security[]; tr: Transport[]; udp?: boolean; relay: boolean; natRelay?: boolean; cert: CertMode[]; port: string }> = {
  eskadra: { name: 'Eskadra', hint: 'всё в одной конфигурации: пользователи подключаются ко входу по VLESS, на выходах VLESS и Hysteria2, вход сам выбирает выход по порядку и переходит на Hysteria2, если VLESS до выхода не отвечает', core: 'Xray + sing-box', sec: ['reality', 'tls'], tr: ['tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  vless: { name: 'VLESS', hint: 'основной вариант: REALITY без своего сертификата, или TLS', core: 'Xray', sec: ['reality', 'tls', 'none'], tr: ['tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  vmess: { name: 'VMess', hint: 'для старых клиентов; обычно поверх WebSocket + TLS', core: 'Xray', sec: ['tls', 'none'], tr: ['tcp', 'ws', 'grpc', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  trojan: { name: 'Trojan', hint: 'похож на обычный HTTPS; TLS или REALITY', core: 'Xray', sec: ['tls', 'reality'], tr: ['tcp', 'ws', 'grpc', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  shadowsocks: { name: 'Shadowsocks-2022', hint: 'простой и быстрый, без TLS', core: 'Xray', sec: ['none'], tr: ['tcp'], relay: true, cert: [], port: '8388' },
  hysteria2: { name: 'Hysteria2', hint: 'QUIC (UDP), быстрый на плохих сетях', core: 'sing-box', sec: ['tls'], tr: [], udp: true, relay: true, natRelay: true, cert: ['ip', 'self', 'domain', 'custom'], port: '8444' },
  mtproto: { name: 'MTProto (Telegram)', hint: 'прокси только для Telegram, маскировка под HTTPS (fake-TLS)', core: 'telemt', sec: ['none'], tr: [], relay: false, cert: [], port: '443' },
};
const STATE_LABEL: Record<string, string> = { active: 'работает', error: 'ошибка', pending: 'выкатывается', deploying: 'выкатывается' };
const SEC_LABEL: Record<Security, string> = { reality: 'REALITY', tls: 'TLS', none: 'без шифрования' };
const TR_LABEL: Record<Transport, string> = { tcp: 'TCP', ws: 'WebSocket', grpc: 'gRPC', xhttp: 'XHTTP', httpupgrade: 'HTTPUpgrade' };
/** Где включён XHTTP: on — у конфигурации без входа; clients — у входа; leg — между серверами; all — везде; cdn — вход за CDN. */
type XMode = 'off' | 'on' | 'clients' | 'leg' | 'all' | 'cdn';
const X_HINT: Record<XMode, string> = {
  off: 'Транспорт TCP (или выбранный в «Дополнительно»).',
  on: 'Клиенты подключаются по XHTTP. Путь и режим (auto) панель подставит сама, Vision у XHTTP не используется.',
  clients: 'XHTTP — от клиентов до входа: так соединение к входу похоже на обычный HTTPS-сайт. Между входом и выходами — TCP с Vision, быстрее всего.',
  leg: 'XHTTP — между входом и выходами: трафик через границу разбит на HTTP-запросы. Клиенты подключаются к входу как раньше.',
  all: 'XHTTP — и от клиентов до входа, и между входом и выходами.',
  cdn: 'Клиенты подключаются к домену на CDN (например, Cloudflare), CDN — к входу. Адрес входа клиенту не виден, а заблокировать CDN целиком дорого. Между входом и выходами — без изменений.',
};
/** Карточки выбора протокола в мастере: короткое описание и пометка. */
/** Карточки выбора защиты, транспорта и сертификата в мастере. */
const SEC_PICK: Record<Security, { desc: string; tag?: string; kind?: string }> = {
  reality: { desc: 'Маскировка под чужой сайт. Домен и сертификат не нужны.', tag: 'rec', kind: 'ok' },
  tls: { desc: 'Свой сертификат. Для CDN и клиентов, которым важен домен.' },
  none: { desc: 'Трафик открыт. Когда TLS даёт CDN или прокси.', tag: 'только за CDN', kind: 'warn' },
};
const TR_PICK: Record<Transport, { desc: string; tag?: string; kind?: string }> = {
  tcp: { desc: 'Быстрее всего. С VLESS — вместе с Vision.', tag: 'rec', kind: 'ok' },
  xhttp: { desc: 'Похож на HTTP-запросы. Когда соединение «замерзает» после первых КБ. Только Xray-клиенты.', tag: 'если режут', kind: 'acc' },
  grpc: { desc: 'Через CDN и прокси с gRPC. Медленнее TCP.' },
  ws: { desc: 'Напрямую легко распознаётся. Для старых клиентов через CDN.', tag: 'за CDN', kind: 'warn' },
  httpupgrade: { desc: 'Как WebSocket, но легче. Для CDN.', tag: 'за CDN', kind: 'warn' },
};
const CERT_PICK: Record<CertMode, { label: string; desc: string }> = {
  ip: { label: "let's encrypt на ip", desc: 'Выпуск и продление сами. Домен не нужен.' },
  domain: { label: 'свой домен на сервер', desc: 'Для каждого сервера — его домен, A-запись указывает на сервер.' },
  custom: { label: 'загрузить свой', desc: 'Общий домен или wildcard: fullchain.pem и privkey.pem.' },
  self: { label: 'самоподписанный', desc: 'Без домена; клиенты подключаются с insecure.' },
};

/** Строка тонкой настройки (ADVANCED): свёрнута, в заголовке — текущие значения. */
function Adv({ title, sum, children }: { title: string; sum: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="adv">
      <button type="button" className="adv-h" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="adv-chev" aria-hidden="true">{open ? '▾' : '▸'}</span>
        <span className="adv-t">{title}</span>
        <span className="adv-sum">{sum}</span>
      </button>
      {open && <div className="adv-b">{children}</div>}
    </div>
  );
}

const PICK_ORDER: Protocol[] = ['vless', 'eskadra', 'hysteria2', 'trojan', 'vmess', 'shadowsocks', 'mtproto'];
const PICK: Record<Protocol, { desc: string; tag?: string; kind?: string }> = {
  vless: { desc: 'Основной выбор. С REALITY — без домена и сертификата.', tag: 'rec', kind: 'ok' },
  eskadra: { desc: 'VLESS + Hysteria2 с взаимным резервом. Через входной сервер.', tag: 'связка', kind: 'acc' },
  hysteria2: { desc: 'Быстрее всех на дальних и плохих каналах, если UDP не режут.', tag: 'udp' },
  trojan: { desc: 'Похож на HTTPS-сайт. Нужен сертификат или REALITY.' },
  vmess: { desc: 'Для старых клиентов. Обычно WebSocket за CDN.' },
  shadowsocks: { desc: 'Shadowsocks-2022. Лёгкий, но без маскировки под сайт.', tag: 'запасной', kind: 'warn' },
  mtproto: { desc: 'Прокси только для Telegram.' },
};
const X_LABEL: Record<XMode, string> = { off: 'выкл', on: 'вкл', clients: 'для клиентов', leg: 'между серверами', all: 'везде', cdn: 'через CDN' };
/** Крупные сайты на чужих адресах: REALITY с ними работает, но имя и адрес сервера не совпадают. */
const WEAK_SNI = ['www.apple.com', 'apple.com', 'www.google.com', 'www.microsoft.com', 'www.cloudflare.com', 'www.bing.com'];
/** Тонкая настройка XHTTP (extra Xray): число или диапазон «a-b» строкой; пусто — по умолчанию Xray. */
type XRange = 'xPaddingBytes' | 'scMaxEachPostBytes' | 'scMinPostsIntervalMs' | 'scMaxBufferedPosts' | 'scStreamUpServerSecs';
type XmuxKey = 'maxConcurrency' | 'maxConnections' | 'cMaxReuseTimes' | 'hMaxRequestTimes' | 'hMaxReusableSecs' | 'hKeepAlivePeriod';
type XhttpExtra = Partial<Record<XRange, string>> & { noGRPCHeader?: boolean; noSSEHeader?: boolean; xmux?: Partial<Record<XmuxKey, string>> };
/** Без пустых полей: сервер пишет в конфиг только заданное. */
const cleanExtra = (e: XhttpExtra): XhttpExtra => {
  const xmux = Object.fromEntries(Object.entries(e.xmux ?? {}).filter(([, v]) => v));
  return { ...Object.fromEntries(Object.entries(e).filter(([k, v]) => k !== 'xmux' && v)), ...(Object.keys(xmux).length ? { xmux } : {}) };
};
/** Поля тонкой настройки: ключ, подпись, значение Xray по умолчанию, подсказка. */
const X_FIELDS: Array<{ group: string; fields: Array<[XRange, string, string, string]> }> = [
  { group: 'Маскировка', fields: [
    ['xPaddingBytes', 'Добавка к запросам, байт', '100-1000', 'Случайная добавка к каждому запросу и ответу — прячет размеры пакетов. Сервер проверяет её длину у клиента, поэтому панель ставит одно значение на обе стороны.'],
  ] },
  { group: 'Режим packet-up', fields: [
    ['scMaxEachPostBytes', 'Наибольший POST, байт', '1000000', 'Наибольший размер одного POST от клиента. Уменьшите, если CDN ограничивает размер запроса. Действует на обе стороны.'],
    ['scMinPostsIntervalMs', 'Пауза между POST, мс', '30', 'Наименьшая пауза между POST клиента. Больше — меньше запросов в секунду (CDN не примет их за атаку), но медленнее отдача от клиента.'],
    ['scMaxBufferedPosts', 'Очередь POST на сервере', '30', 'Сколько POST сервер держит, пока ждёт пропущенный. Больше — терпимее к перестановке запросов в CDN, но больше памяти.'],
  ] },
  { group: 'Режим stream-up', fields: [
    ['scStreamUpServerSecs', 'Пустой ответ раз в, с', '20-80', 'Сервер раз в столько секунд шлёт пустой ответ в поток от клиента, чтобы CDN не закрыл его как молчащий.'],
  ] },
];
const XMUX_FIELDS: Array<[XmuxKey, string, string, string]> = [
  ['maxConcurrency', 'Потоков на соединение', '16-32', 'Сколько соединений пользователя идёт внутри одного HTTP-соединения; заполнено — открывается новое. Не задаётся вместе с «Соединений».'],
  ['maxConnections', 'Соединений', '0', 'Сколько HTTP-соединений держать сразу; соединения пользователя раскладываются по ним. 0 — без ограничения. Не задаётся вместе с «Потоков на соединение».'],
  ['cMaxReuseTimes', 'Повторных занятий', '0', 'Сколько раз одно HTTP-соединение можно занять заново, потом оно закрывается. 0 — без ограничения.'],
  ['hMaxRequestTimes', 'Запросов на соединение', '600-900', 'Сколько HTTP-запросов отправить по одному соединению, потом открыть новое. По умолчанию меньше, чем терпит nginx (1000).'],
  ['hMaxReusableSecs', 'Срок соединения, с', '1800-3000', 'Сколько секунд соединение можно брать для новых запросов.'],
  ['hKeepAlivePeriod', 'Keep-alive раз в, с', '0', 'Раз в столько секунд клиент проверяет простаивающее соединение. 0 — по умолчанию Xray (HTTP/2 — 45 с, HTTP/3 — 10 с).'],
];
/** Порты HTTPS, которые проксирует Cloudflare. */
const CDN_PORTS = ['443', '2053', '2083', '2087', '2096', '8443'];
const CERT_LABEL: Record<CertMode, string> = {
  ip: 'Let\'s Encrypt на IP сервера (рекомендуется)', domain: 'Свой домен на каждом сервере', custom: 'Загрузить свой (общий домен или wildcard)', self: 'Самоподписанный (без домена, с привязкой отпечатка)',
};

type AutoMode = 'smart' | 'order' | 'spread' | 'random';
const AUTO_HINT: Record<AutoMode, string> = {
  smart: 'Трафик идёт через выход, который проходит пороги задержки и скорости. Пока он их проходит — не меняется; перестал — вход переключается на самый быстрый из подходящих.',
  order: 'Трафик идёт через первый отвечающий выход в списке. Выход не отвечает — вход сам переводит трафик на следующий по списку примерно за 10 секунд, на любом уровне: второй, третий и дальше. Вышестоящий снова отвечает — трафик возвращается к нему. Не отвечает никто — через первый. Вход проверяет выходы каждые 5 секунд, без замера скорости.',
  spread: 'Пользователи делятся на группы, у каждой свой выход: групп на выходе — по ёмкости его канала. У пользователя постоянный выход и IP. Канал выхода загружен выше порога — самая тяжёлая группа, которая поместится, переводится на выход с запасом; нагрузка спала — возвращается. Выход не отвечает — группа сама уходит на следующий по порядку за ~10 секунд.',
  random: 'Каждое соединение — через любой выход наугад. Без проверок задержки и скорости.',
};

interface Settings {
  security: Security; transport: Transport; flow: string; path: string; host: string; serviceName: string; xhttpMode: string;
  alpn: string[]; certMode: CertMode; domain: string; domains: Record<string, string>; ssMethod: string; hy2Obfs: string; mtDomain: string; sniffing: boolean;
  hy2UpMbps: number; hy2DownMbps: number; hy2ServerUpMbps: number; hy2ServerDownMbps: number; hy2IgnoreClientBw: boolean; hy2Masquerade: string; hy2Hop: string; hy2HopInterval: number;
  autoEnabled: boolean; autoMode: AutoMode; exitOrder: string[]; maxRttMs: number; minMbps: number; checkMin: number; testMB: number; orderMinMbps: number; speedEveryMin: number; decideMin: number;
  spreadGroups: number; exitCapMbps: Record<string, number>; spreadHighPct: number; spreadFair: boolean;
  hy2Relay: 'nat' | 'core'; hy2Leg: string; hy2Port: number; entryProto: 'vless' | 'hysteria2';
  // XHTTP через вход: транспорт входа ('' — как у выходов) и домен CDN перед входом
  entryTransport: '' | 'tcp' | 'xhttp'; cdn: string; cdnMode: 'packet-up' | 'stream-up' | 'stream-one'; cdnH3: boolean; xhttpExtra: XhttpExtra;
}

interface Draft {
  id: string | null; name: string; protocol: Protocol; port: string; sni: string; fingerprint: string;
  ech: boolean; nodeIds: string[]; entryId: string; entryPort: string; st: Settings;
  certPem: string; keyPem: string;
}

/** Случайная hex-строка из n байт (пароль obfs). */
const randomHex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');

const defaults = (p: Protocol): Settings => ({
  security: PROTO[p].sec[0]!, transport: p === 'vmess' ? 'ws' : 'tcp', flow: p === 'vless' || p === 'eskadra' ? 'xtls-rprx-vision' : '', path: '/', host: '', serviceName: 'grpc',
  xhttpMode: 'auto', alpn: ['h2', 'http/1.1'], certMode: PROTO[p].cert[0] ?? 'self', domain: '', domains: {}, ssMethod: '2022-blake3-aes-128-gcm',
  hy2Obfs: '', mtDomain: 'www.apple.com', sniffing: true,
  hy2UpMbps: 0, hy2DownMbps: 0, hy2ServerUpMbps: 0, hy2ServerDownMbps: 0, hy2IgnoreClientBw: false, hy2Masquerade: '', hy2Hop: '', hy2HopInterval: 30,
  autoEnabled: !PROTO[p].natRelay, autoMode: p === 'eskadra' ? 'order' : 'smart', exitOrder: [], maxRttMs: 100, minMbps: 10, checkMin: 15, testMB: 5, orderMinMbps: 0, speedEveryMin: 1, decideMin: 1,
  spreadGroups: 6, exitCapMbps: {}, spreadHighPct: 80, spreadFair: false, hy2Relay: 'nat', hy2Leg: '', hy2Port: 0, entryProto: 'vless',
  entryTransport: '', cdn: '', cdnMode: 'packet-up', cdnH3: false, xhttpExtra: {},
});

const empty = (p: Protocol = 'vless'): Draft => ({
  id: null, name: '', protocol: p, port: PROTO[p].port, sni: 'www.apple.com', fingerprint: 'chrome', ech: false, nodeIds: [], entryId: '', entryPort: '9443',
  st: defaults(p), certPem: '', keyPem: '',
});

const protoOf = (t: Template): Protocol => (t.spec.bundle ? 'eskadra' : t.spec.protocol);

const toDraft = (t: Template): Draft => ({
  id: t.id, name: t.name, protocol: protoOf(t), port: String(t.port), sni: t.sni.join(' '), fingerprint: t.fingerprint, ech: t.ech,
  nodeIds: t.node_ids, entryId: t.entry_id ?? '', entryPort: String(t.entry_port ?? 9443),
  // flow в форме — выбор Vision для звеньев по TCP (у XHTTP сервер его снимает сам)
  st: { ...defaults(protoOf(t)), ...t.spec, flow: String(t.spec.tcpFlow ?? t.spec.flow ?? '') } as Settings, certPem: '', keyPem: '',
});

/** Краткое описание шаблона для списка: «VLESS · REALITY · TCP». */
const describe = (t: Template) => {
  const sp = t.spec;
  const p = protoOf(t);
  const parts = [p === 'eskadra' ? 'Eskadra · VLESS + Hysteria2' : PROTO[p]?.name ?? p];
  if (PROTO[p]?.sec.length > 1 || sp.security === 'tls') parts.push(SEC_LABEL[sp.security]);
  if (PROTO[p]?.tr.length > 1) parts.push(TR_LABEL[sp.transport]);
  return parts.join(' · ');
};

type CfgState = 'ok' | 'draft' | 'new' | 'fail';
/** Состояние конфигурации в списке: ошибка выката на каком-то сервере, черновик, ещё не выкатывалась или работает. */
const stateOf = (t: Template): CfgState =>
  t.inbounds.some((i) => i.state === 'error') ? 'fail' : !t.applied_revision ? 'new' : t.applied_revision < t.revision ? 'draft' : 'ok';
/** Метки состояния в списке — как в консоли. */
const ST_MARK: Record<CfgState, string> = { ok: '[ OK ]', draft: '[DRAFT]', new: '[ NEW ]', fail: '[FAIL]' };
/** Выкат, запущенный из списка: его журнал показывает страница конфигурации, куда переходит список. */
let handoff: { id: string; job: number } | null = null;
const passJob = (id: string, job: number) => { handoff = { id, job }; dispatchEvent(new CustomEvent("cfg-job", { detail: handoff })); };

/** Раздел «Конфигурации»: список (#/configs), мастер новой (#/configs/new), страница конфигурации (#/configs/<id>). */
export function ConfigsPage({ id }: { id?: string }) {
  return id ? <ConfigPage key={id} id={id} /> : <ConfigList />;
}

function NewButton() {
  // новую создаёт роль с правом и без ограничения списка конфигураций; лимит роли — «создано N из M»
  if (!can('configs.edit') || !inScope('templates', '')) return null;
  const q = quota('templates');
  const full = !!q && q.made >= q.max;
  return (
    <span className="flex" style={{ gap: 8 }}>
      {q && <span className="k">создано {q.made} из {q.max}</span>}
      {full ? <button className="btn pri" disabled title="лимит конфигураций роли исчерпан">+ Новая конфигурация</button>
        : <a className="btn pri" href="#/configs/new">+ Новая конфигурация</a>}
    </span>
  );
}

function ConfigList() {
  const { data: templates, reload } = usePoll(() => api.get<Template[]>('/api/v1/templates'), 20_000);
  const { data: servers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  // сколько пользователей получают конфигурацию; без права смотреть пользователей столбца нет
  const { data: users } = usePoll(() => api.get<User[]>('/api/v1/users').catch(() => null), 60_000);
  const [filter, setFilter] = useState<'all' | 'att' | 'draft' | 'fail'>('all');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState<string[]>([]);
  const { busy, error, run } = useAsync();
  const name = (sid: string) => servers?.find((s) => s.id === sid)?.name ?? sid;
  const route = (t: Template) => {
    const exits = t.node_ids.filter((x) => x !== t.entry_id).map(name).join(', ') || '—';
    return t.entry_id ? `${name(t.entry_id)} → ${exits}` : exits;
  };
  // протокол / защита / транспорт — строчными, как в ссылках клиентов
  const how = (t: Template) => describe(t).replace(/ · /g, ' / ').toLowerCase().replace('eskadra / vless + hysteria2', 'Eskadra / vless + hy2');
  const warn = (t: Template) => {
    const err = t.inbounds.find((i) => i.error);
    if (err) return `${name(err.server_id)}: ${err.error}`;
    if (t.spec.security === 'reality' && WEAK_SNI.includes(t.sni[0] ?? '')) return `sni ${t.sni[0]} не из сети серверов`;
    return '';
  };
  const userCount = (t: Template) => users?.filter((u) => u.configs.some((c) => c.id === t.id && c.allowed)).length;
  const all = templates ?? [];
  const att = (t: Template) => stateOf(t) !== 'ok' || !!warn(t);
  const count = { all: all.length, att: all.filter(att).length, draft: all.filter((t) => ['draft', 'new'].includes(stateOf(t))).length, fail: all.filter((t) => stateOf(t) === 'fail').length };
  const needle = q.trim().toLowerCase();
  const rows = all
    .filter((t) => filter === 'all' || (filter === 'att' ? att(t) : filter === 'draft' ? ['draft', 'new'].includes(stateOf(t)) : stateOf(t) === 'fail'))
    .filter((t) => !needle || [t.name, t.core, how(t), route(t), `:${t.port}`].join(' ').toLowerCase().includes(needle));
  const picked = rows.filter((t) => sel.includes(t.id));
  const allPicked = rows.length > 0 && picked.length === rows.length;
  const toggle = (id: string) => setSel(sel.includes(id) ? sel.filter((x) => x !== id) : [...sel, id]);
  const rollout = (t: Template) => run(async () => {
    const r = await api.post<{ jobId: number }>(`/api/v1/templates/${t.id}/rollout`);
    passJob(t.id, r.jobId);
    toast(`«${t.name}»: выкат начался`, 'info');
    location.hash = `#/configs/${t.id}`;
  });
  // по одной, как и с одной страницы: первая ошибка останавливает
  const rolloutPicked = async () => {
    if (!(await ask(`Выкатить по очереди: ${picked.map((t) => t.name).join(', ')}?`))) return;
    void run(async () => {
      for (const t of picked) {
        const { jobId } = await api.post<{ jobId: number }>(`/api/v1/templates/${t.id}/rollout`);
        let job: Job;
        do { await new Promise((r) => setTimeout(r, 2000)); job = await api.get<Job>(`/api/v1/jobs/${jobId}`); } while (job.status === 'running');
        if (job.status !== 'ok') throw new Error(`«${t.name}»: выкат не удался — журнал на странице конфигурации`);
        toast(`«${t.name}» выкачена`);
      }
      setSel([]);
      void reload();
    });
  };
  const deletePicked = async () => {
    if (!(await ask(`Снять со всех серверов и удалить: ${picked.map((t) => t.name).join(', ')}? Профили этих конфигураций пропадут из подписок.`))) return;
    void run(async () => {
      for (const t of picked) await api.del(`/api/v1/templates/${t.id}`);
      toast(`Удалено: ${picked.length}`);
      setSel([]);
      void reload();
    });
  };
  const q2 = quota('templates');
  return (
    <>
      <div className="cl-head">
        <h1>Конфигурации</h1>
        <span className="cl-count">{`${count.all} всего · ${count.all - all.filter((t) => stateOf(t) !== 'ok').length} работают · ${count.att} требуют внимания${q2 ? ` · создано ${q2.made} из ${q2.max}` : ''}`}</span>
        <NewButton />
      </div>
      <div className="list-tools">
        <Seg value={filter} label="Какие конфигурации показать" onChange={(v) => { setFilter(v); setSel([]); }}
          options={[['all', `все ${count.all}`], ['att', `внимание ${count.att}`], ['draft', `черновики ${count.draft}`], ['fail', `ошибки ${count.fail}`]]} />
        <label className="list-search"><span aria-hidden="true">/</span><input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="имя, протокол, сервер" aria-label="Поиск конфигураций" /></label>
      </div>
      {picked.length > 0 && (
        <div className="bulk" role="region" aria-label="Действия с отмеченными">
          <span className="bulk-n">выбрано: {picked.length}</span>
          {can('configs.rollout') && <button className="btn sm" disabled={busy} onClick={() => void rolloutPicked()}>Выкатить</button>}
          {can('configs.delete') && <button className="btn sm danger" disabled={busy} onClick={() => void deletePicked()}>Удалить</button>}
          <button className="btn ghost sm bulk-off" onClick={() => setSel([])}>Снять выбор</button>
        </div>
      )}
      <ErrorBox error={error} />
      <section className="card cl-table">
        <div className="table-wrap">
          <table>
            <thead><tr>
              <th className="cl-cb"><input type="checkbox" aria-label="Отметить все" checked={allPicked} onChange={() => setSel(allPicked ? [] : rows.map((t) => t.id))} /></th>
              <th>Статус</th><th>Имя</th><th>Протокол / защита / транспорт</th><th>Порт</th><th>Маршрут</th>{users && <th>Польз.</th>}<th><span className="sr">Действия</span></th>
            </tr></thead>
            <tbody>
              {rows.map((t) => {
                const s = stateOf(t);
                const w = warn(t);
                return (
                  <tr key={t.id} className={sel.includes(t.id) ? 'sel' : ''}>
                    <td className="cl-cb"><input type="checkbox" aria-label={`Отметить ${t.name}`} checked={sel.includes(t.id)} onChange={() => toggle(t.id)} /></td>
                    <td><span className={`st st-${s}`}>{ST_MARK[s]}</span></td>
                    <td><a className="cfg-name" href={`#/configs/${t.id}`}>{t.name}</a><div className="k mono">{t.core.toLowerCase()}</div></td>
                    <td className="mono">{how(t)}{w && <div className="cl-warn">!! {w}</div>}</td>
                    <td className="mono muted">:{t.port}{t.entry_id ? <div className="k">вход :{t.entry_port}</div> : null}</td>
                    <td className="mono muted">{route(t)}</td>
                    {users && <td className="mono muted">{userCount(t)}</td>}
                    <td className="cfg-acts">
                      {(s === 'draft' || s === 'new') && can('configs.rollout') && <button className="btn sm acc" disabled={busy || (!t.node_ids.length && !t.entry_id)} onClick={() => void rollout(t)}>Выкатить</button>}
                      {s === 'fail' && <a className="btn sm danger" href={`#/configs/${t.id}`}>Журнал</a>}
                      <a className="btn sm" href={`#/configs/${t.id}`}>Открыть</a>
                    </td>
                  </tr>
                );
              })}
              {!rows.length && <tr><td colSpan={users ? 8 : 7} className="empty">{all.length ? 'Ничего не нашлось — измените поиск или фильтр.' : 'Конфигураций пока нет. Создайте первую — мастер проведёт по шагам.'}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <div className="cl-legend">
        <span><b className="st st-ok">{ST_MARK.ok}</b> выкачена и работает</span>
        <span><b className="st st-draft">{ST_MARK.draft}</b> изменения сохранены, серверы на старой версии</span>
        <span><b className="st st-new">{ST_MARK.new}</b> ещё не выкатывалась</span>
        <span><b className="st st-fail">{ST_MARK.fail}</b> выкат упал — смотрите журнал</span>
      </div>
    </>
  );
}

/** Страница одной конфигурации или мастер новой. */
function ConfigPage({ id }: { id: string }) {
  const isNew = id === 'new';
  const { data: templates, reload } = usePoll(() => api.get<Template[]>('/api/v1/templates'), 20_000);
  const { data: servers, reload: reloadServers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  const [draft, setDraft] = useState<Draft | null>(isNew ? empty() : null);
  const [jobId, setJobId] = useState<number | null>(() => (handoff?.id === id ? handoff.job : null));
  useEffect(() => {
    if (handoff?.id === id) handoff = null;
    const on = (e: Event) => { const x = (e as CustomEvent<{ id: string; job: number }>).detail; if (x.id === id) { setJobId(x.job); handoff = null; } };
    addEventListener("cfg-job", on);
    return () => removeEventListener("cfg-job", on);
  }, [id]);
  // новая: после сохранения страница переходит на свой адрес, а выкат стартует чуть позже — журнал передаётся туда
  const savedId = useRef<string | null>(null);
  const current = isNew ? null : templates?.find((t) => t.id === id) ?? null;
  useEffect(() => { if (!isNew && current && !draft) setDraft(toDraft(current)); }, [isNew, current, draft]);
  const missing = !isNew && templates && !current;
  return (
    <>
      <div className="page-head">
        <div>
          <a className="back" href="#/configs">{'< '}Конфигурации</a>
          <h1 className={isNew ? undefined : 'as-is'}>{isNew ? 'Новая конфигурация' : current?.name ?? '…'}</h1>
          {current && <p className="mono">{describe(current)} · :{current.port}</p>}
        </div>
      </div>
      {missing && <div className="card pad stack"><h2>Конфигурации нет</h2><p className="k">Её удалили или ссылка неверная. <a href="#/configs">К списку</a></p></div>}
      <div className="stack" style={{ gap: 20 }}>
        {draft && servers && <Editor key={draft.id ?? 'new'} draft={draft} servers={servers} current={current} templates={templates ?? []} onServers={() => void reloadServers()}
          onSaved={(t) => { void reload(); setDraft(toDraft(t)); if (isNew) { savedId.current = t.id; location.hash = `#/configs/${t.id}`; } }}
          onRollout={(job) => (isNew && savedId.current ? passJob(savedId.current, job) : setJobId(job))} onDeleted={() => { location.hash = '#/configs'; }} />}
        {jobId && <JobLog id={jobId} onDone={() => void reload()} />}
        {current?.entry_id && current.spec.autoEnabled !== false && current.spec.autoMode !== 'random' && <ExitHealth t={current} />}
        {current && <Preview t={current} servers={servers ?? []} />}
      </div>
    </>
  );
}

interface CoresInfo {
  latest: Record<string, string | null>;
  releases: Record<string, Array<{ version: string; published: string; prerelease: boolean }>>;
  pins: Record<string, string>;
  errors: string[];
  servers: Array<{ id: string; name: string; mode: 'own' | 'xui'; xray: { version: string; previous?: string } | null; singbox: { version: string; previous?: string } | null; xui: { version: string; panel?: string } | null; outdated: string[] }>;
}

export function CoresPanel() {
  const { data, reload } = usePoll(() => api.get<CoresInfo>('/api/v1/cores'), null);
  const [core, setCore] = useState<'xray' | 'sing-box'>('xray');
  const [version, setVersion] = useState('latest');
  const [pre, setPre] = useState(false);
  const [jobId, setJobId] = useState<number | null>(null);
  // серверы, на которых обновлять: по умолчанию ни одного — обновление касается только отмеченных
  const [picked, setPicked] = useState<string[]>([]);
  const { busy, error, run } = useAsync();
  if (!data) return null;
  // Xray серверов с 3x-ui обновляется в самом 3x-ui — их не отмечаем
  const eligible = data.servers.filter((s) => !(core === 'xray' && s.mode === 'xui'));
  const sel = eligible.filter((s) => picked.includes(s.id));
  const toggle = (id: string) => setPicked(picked.includes(id) ? picked.filter((x) => x !== id) : [...picked, id]);
  const rels = (data.releases[core] ?? []).filter((r) => pre || !r.prerelease);
  const ver = (c: { version: string; previous?: string } | null, k: string, s: CoresInfo['servers'][number]) => {
    if (!c) return (
      <span className="stack" style={{ gap: 4 }}>
        <span className="k">не установлено</span>
        {can('cores.manage') && <span><button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/update`, { version: data.pins[k] ?? 'latest' }); void reload(); })}>Установить</button></span>}
      </span>
    );
    const old = s.outdated.includes(k);
    return (
      <span className="stack" style={{ gap: 4 }}>
        <span className="flex" style={{ gap: 8 }}><span className="mono small">{c.version}</span>{old && <Tag kind="warn">устарел</Tag>}</span>
        <span className="flex" style={{ gap: 8 }}>
          {old && can('cores.manage') && <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/update`, { version: data.pins[k] ?? 'latest' }); void reload(); })}>Обновить</button>}
          {c.previous && can('cores.manage') && <button className="btn ghost sm" disabled={busy} onClick={async () => { if (await ask(`Вернуть ${k} ${c.previous} на ${s.name}?`)) void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/rollback`); void reload(); }); }}>Откат на {c.previous}</button>}
        </span>
      </span>
    );
  };
  return (
    <section className="card">
      <div className="card-head">
        <h2>Ядра <Info>Ядра ставятся при подключении сервера; здесь их можно установить, обновить или откатить. Новая версия ставится рядом со старой и проверяется текущим конфигом — при неудаче сервер сам возвращает прежнюю. Xray серверов с 3x-ui обновляется в самом 3x-ui.</Info></h2>
        <span className="k">последние стабильные: Xray {data.latest.xray ?? '?'} · sing-box {data.latest['sing-box'] ?? '?'}</span>
      </div>
      {data.errors.map((e) => <div key={e} className="alert warn" style={{ margin: '0 20px' }}>GitHub недоступен: {e}</div>)}
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table>
          <thead><tr><th style={{ width: 36 }}><input type="checkbox" aria-label="Отметить все серверы" checked={!!eligible.length && sel.length === eligible.length} onChange={(e) => setPicked(e.target.checked ? eligible.map((s) => s.id) : [])} /></th><th>Узел</th><th>Режим</th><th>Xray</th><th>sing-box</th></tr></thead>
          <tbody>
            {data.servers.map((s) => (
              <tr key={s.id}>
                <td><input type="checkbox" aria-label={`Обновлять ${s.name}`} disabled={!eligible.some((x) => x.id === s.id)} checked={picked.includes(s.id) && eligible.some((x) => x.id === s.id)} onChange={() => toggle(s.id)} /></td>
                <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a></td>
                <td>{s.mode === 'xui' ? <Tag kind="info">через 3x-ui</Tag> : <Tag>своё ядро</Tag>}</td>
                <td>{s.mode === 'xui' ? <span className="stack" style={{ gap: 2 }}><span className="mono small">{s.xui?.version ?? '?'}</span><span className="k">3x-ui {s.xui?.panel ?? ''}</span></span> : ver(s.xray, 'xray', s)}</td>
                <td>{ver(s.singbox, 'sing-box', s)}</td>
              </tr>
            ))}
            {!data.servers.length && <tr><td colSpan={5} className="k">Узлов с nodekit нет.</td></tr>}
          </tbody>
        </table>
      </div>
      {/* установка, обновление и откат ядер — право cores.manage */}
      {can('cores.manage') && <div className="row stack" style={{ alignItems: 'stretch' }}>
        <h3>Обновление <Info>Отметьте серверы в таблице — ядро ставится или обновляется только на них, по одному: первая ошибка останавливает, сервер с ошибкой сам возвращает прежнюю версию. Так новую версию можно сначала проверить на одном сервере, а потом раскатить на остальные.</Info></h3>
        <div className="flex">
          <Seg value={core} label="Ядро" onChange={(c) => { setCore(c); setVersion('latest'); }} options={[['xray', 'Xray'], ['sing-box', 'sing-box']]} />
          <select className="inp" style={{ width: 'auto' }} value={version} onChange={(e) => setVersion(e.target.value)} aria-label="Версия">
            <option value="latest">последняя стабильная ({data.latest[core] ?? '?'})</option>
            {rels.map((r) => <option key={r.version} value={r.version}>{r.version}{r.prerelease ? ' · предрелиз' : ''} · {r.published.slice(0, 10)}</option>)}
          </select>
          <label className="cb small"><input type="checkbox" checked={pre} onChange={(e) => setPre(e.target.checked)} />показывать предрелизы</label>
        </div>
        <div className="flex">
          <button className="btn pri" disabled={busy || !sel.length} onClick={async () => { if (await ask(`Установить или обновить ${core} (${version}) на: ${sel.map((s) => s.name).join(', ')}? По одному серверу, первая ошибка останавливает.`)) void run(async () => { const r = await api.post<{ jobId: number }>(`/api/v1/cores/${core}/rollout`, { version, serverIds: sel.map((s) => s.id) }); setJobId(r.jobId); }); }}>{sel.length ? `Установить или обновить на выбранных: ${sel.length}` : 'Отметьте серверы в таблице'}</button>
          <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/cores/pin', { core, version }); void reload(); })}>Закрепить для новых узлов</button>
          <span className="k">Сейчас новые узлы получают: {core} {data.pins[core] ?? 'latest'}</span>
        </div>
        <ErrorBox error={error} />
      </div>}
      {jobId && <div style={{ padding: '0 20px 16px' }}><JobLog id={jobId} onDone={() => void reload()} /></div>}
    </section>
  );
}

function Editor({ draft, servers, current, templates, onServers, onSaved, onRollout, onDeleted }: {
  draft: Draft; servers: Server[]; current: Template | null; templates: Template[]; onServers: () => void; onSaved: (t: Template) => void; onRollout: (jobId: number) => void; onDeleted: () => void;
}) {
  const [d, setD] = useState(draft);
  useEffect(() => setD(draft), [draft]);   // после сохранения — то, что вернул сервер
  const { busy, error, run } = useAsync();
  const managed = servers.filter((s) => s.sudo_mode === 'restricted');
  const info = PROTO[d.protocol];
  // «eskadra» на сервере — VLESS-конфигурация с bundle
  const esk = d.protocol === 'eskadra';
  const vless = d.protocol === 'vless' || esk;
  const st = d.st;
  const setSt = (patch: Partial<Settings>) => setD({ ...d, st: { ...st, ...patch } });
  const tls = st.security === 'tls' || d.protocol === 'hysteria2';
  // XHTTP одной опцией: у входа (для клиентов), у плеча вход → выход, везде или вход за CDN; путь и режим панель ставит сама
  const hyIn = esk && st.entryProto === 'hysteria2';
  const chainX = vless && !!d.entryId;
  const [wantCdn, setWantCdn] = useState(false);
  useEffect(() => setWantCdn(false), [draft]);
  const xMode: XMode = !vless ? 'off'
    : chainX && !hyIn && (st.cdn || wantCdn) ? 'cdn'
    : !chainX ? (st.transport === 'xhttp' ? 'on' : 'off')
    : hyIn ? (st.transport === 'xhttp' ? 'leg' : 'off')
    : (st.entryTransport || st.transport) === 'xhttp' ? (st.transport === 'xhttp' ? 'all' : 'clients')
    : st.transport === 'xhttp' ? 'leg' : 'off';
  const setX = (m: XMode) => {
    setWantCdn(m === 'cdn');
    const path = st.path && st.path !== '/' ? st.path : '/' + randomHex(6);
    if (m === 'off') return setSt({ transport: st.transport === 'xhttp' ? 'tcp' : st.transport, entryTransport: '', cdn: '' });
    if (m === 'clients') return setSt({ transport: 'tcp', entryTransport: 'xhttp', cdn: '', path });
    if (m === 'leg') return setSt({ transport: 'xhttp', entryTransport: hyIn ? '' : 'tcp', cdn: '', path });
    if (m === 'cdn') return setSt({ entryTransport: '', path });
    setSt({ transport: 'xhttp', entryTransport: '', cdn: '', path });
  };
  const xUsed = xMode !== 'off';
  const entryHost = servers.find((s) => s.id === d.entryId)?.host ?? '';
  const usedIds = [...d.nodeIds, ...(d.entryId ? [d.entryId] : [])];
  // выходы «Авто»: серверы конфигурации кроме входа — в заданном порядке (новые — в конце)
  const rank = (id: string) => (st.exitOrder.includes(id) ? st.exitOrder.indexOf(id) : st.exitOrder.length);
  const exits = managed.filter((s) => d.nodeIds.includes(s.id) && s.id !== d.entryId).sort((a, b) => rank(a.id) - rank(b.id));
  const { data: health } = usePoll(() => (current?.entry_id ? api.get<Health>(`/api/v1/templates/${current.id}/health`) : Promise.resolve(null)), 60_000, [current?.id]);
  // замеры каналов серверов (на самих серверах) — ёмкость выходов «по нагрузке», если своё значение не задано
  const { data: links, reload: reloadLinks } = usePoll(() => api.get<Record<string, LinkTest>>('/api/v1/links'), null);
  const [measuring, setMeasuring] = useState<string | null>(null);
  // случайные свободные порты: проверяются на серверах конфигурации (не выбраны — на всех) так же, как при выкате
  const randomPorts = async (which: 'port' | 'entry' | 'both', base: Draft = d) => {
    const ids = [...base.nodeIds, ...(base.entryId ? [base.entryId] : [])];
    // вход eskadra по Hysteria2 слушает UDP
    const udp = which === 'entry' && base.protocol === 'eskadra' ? base.st.entryProto === 'hysteria2' : PROTO[base.protocol].udp;
    const q = new URLSearchParams({ proto: udp ? 'udp' : 'tcp', count: which === 'both' ? '2' : '1', servers: ids.join(','),
      avoid: which === 'port' ? base.entryPort : which === 'entry' ? base.port : '' });
    try {
      const { ports } = await api.get<{ ports: number[] }>(`/api/v1/free-ports?${q}`);
      return which === 'both' ? { ...base, port: String(ports[0]), entryPort: String(ports[1]) }
        : which === 'port' ? { ...base, port: String(ports[0]) } : { ...base, entryPort: String(ports[0]) };
    } catch (e) { toast((e as Error).message, 'fail'); return base; }
  };
  // новая конфигурация — сразу со случайными свободными портами (и после смены протокола)
  useEffect(() => {
    if (draft.id) return;
    let live = true;
    void randomPorts('both', d).then((next) => { if (live) setD((cur) => (cur.protocol === next.protocol && !cur.id ? { ...cur, port: next.port, entryPort: next.entryPort } : cur)); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.id, d.protocol]);
  const measure = async (ids: string[]) => {
    const names = ids.map((id) => servers.find((s) => s.id === id)?.name ?? id).join(', ');
    if (!(await ask(`Замерить канал: ${names}? На каждом сервере ~25 секунд канал будет занят целиком (пользователям этого сервера медленнее), трафик — до ${ids.length > 1 ? 'пары ГБ на сервер' : 'пары ГБ'} на гигабитном канале. В первый раз на сервер ставится speedtest от Ookla (в Ubuntu и Debian — из snap) — это может занять несколько минут.`))) return;
    for (const id of ids) {
      setMeasuring(id);
      const name = servers.find((s) => s.id === id)?.name ?? id;
      try {
        // замер — фоновая задача: первый раз на сервере может ставиться speedtest от Ookla (snap), это минуты
        const { jobId } = await api.post<{ jobId: number }>(`/api/v1/servers/${id}/link-test`);
        let job: Job;
        do { await new Promise((r) => setTimeout(r, 3000)); job = await api.get<Job>(`/api/v1/jobs/${jobId}`); } while (job.status === 'running');
        const last = (job.log ?? '').trim().split('\n').pop()?.replace(/^\[[^\]]+\]\s*/, '') ?? '';
        toast(`${name}: ${last}`, job.status === 'ok' ? 'ok' : 'fail');
      } catch (e) { toast(`${name}: ${(e as Error).message}`, 'fail'); }
    }
    setMeasuring(null);
    void reloadLinks();
  };
  const move = (i: number, dir: -1 | 1) => {
    const ids = exits.map((s) => s.id);
    [ids[i], ids[i + dir]] = [ids[i + dir]!, ids[i]!];
    setSt({ exitOrder: ids });
  };
  const dirty = JSON.stringify(d) !== JSON.stringify(draft);
  const body = () => ({
    name: d.name, protocol: esk ? 'vless' : d.protocol, port: Number(d.port), sni: d.sni.split(/[\s,]+/).filter(Boolean), fingerprint: d.fingerprint, ech: d.ech,
    // серверы, которых уже нет в панели (удалены), не отправляем — иначе конфигурацию не сохранить
    nodeIds: d.nodeIds.filter((id) => servers.some((s) => s.id === id)), entryId: d.entryId && servers.some((s) => s.id === d.entryId) ? d.entryId : null, entryPort: d.entryId ? Number(d.entryPort) : null,
    settings: {
      // flow — выбор Vision для звеньев по TCP: у XHTTP сервер его снимает сам
      security: st.security, transport: st.transport, flow: st.security !== 'none' && vless ? st.flow : '',
      entryTransport: chainX && !hyIn ? st.entryTransport : '', cdn: chainX && !hyIn ? st.cdn.trim() : '', cdnMode: st.cdnMode, cdnH3: st.cdnH3,
      xhttpExtra: xUsed ? cleanExtra(st.xhttpExtra) : {},
      path: st.path, host: st.host, serviceName: st.serviceName, xhttpMode: st.xhttpMode, alpn: st.alpn, certMode: st.certMode,
      domain: st.domain, domains: Object.fromEntries(Object.entries(st.domains).filter(([k, v]) => usedIds.includes(k) && v)),
      ssMethod: st.ssMethod, hy2Obfs: st.hy2Obfs, mtDomain: st.mtDomain, sniffing: st.sniffing,
      hy2UpMbps: Number(st.hy2UpMbps) || 0, hy2DownMbps: Number(st.hy2DownMbps) || 0, hy2ServerUpMbps: Number(st.hy2ServerUpMbps) || 0, hy2ServerDownMbps: Number(st.hy2ServerDownMbps) || 0,
      hy2IgnoreClientBw: st.hy2IgnoreClientBw, hy2Masquerade: st.hy2Masquerade.trim(), hy2Hop: st.hy2Hop.replace(/\s/g, ''), hy2HopInterval: Math.min(3600, Math.max(5, Number(st.hy2HopInterval) || 30)),
      autoEnabled: st.autoEnabled, autoMode: st.autoMode, exitOrder: exits.map((s) => s.id), maxRttMs: Number(st.maxRttMs) || 100, minMbps: Number(st.minMbps) || 10, checkMin: Number(st.checkMin) || 15, testMB: Number(st.testMB) || 5, orderMinMbps: Number(st.orderMinMbps) || 0, speedEveryMin: Number(st.speedEveryMin) || 1, decideMin: Number(st.decideMin) || 1,
      spreadGroups: Math.min(16, Math.max(2, Number(st.spreadGroups) || 6)), spreadHighPct: Math.min(95, Math.max(30, Number(st.spreadHighPct) || 80)), spreadFair: st.spreadFair,
      exitCapMbps: Object.fromEntries(exits.map((s) => [s.id, Number(st.exitCapMbps[s.id]) || 0])),
      hy2Relay: st.hy2Relay, hy2Leg: d.entryId && info.core === 'Xray' && info.relay ? st.hy2Leg : '',
      bundle: esk, hy2Port: esk ? Number(st.hy2Port) || 0 : 0, entryProto: esk ? st.entryProto : 'vless',
    },
    ...(d.certPem.trim() && d.keyPem.trim() ? { customCert: { fullchain: d.certPem.trim() + '\n', privkey: d.keyPem.trim() + '\n' } } : {}),
  });
  const saveT = async () => {
    const t = d.id ? await api.put<Template>(`/api/v1/templates/${d.id}`, body()) : await api.post<Template>('/api/v1/templates', body());
    if (!d.id) void refreshMe();   // счётчик «создано N из M» у лимита роли
    onSaved(t);
    return t;
  };
  const save = () => run(async () => { await saveT(); toast('Черновик сохранён — на серверах прежняя версия'); });
  const rollout = () => run(async () => {
    const t = await saveT();
    const r = await api.post<{ jobId: number }>(`/api/v1/templates/${t.id}/rollout`);
    onRollout(r.jobId);
    toast('Сохранено, выкат начался', 'info');
  });
  const pending = !!current && current.applied_revision < current.revision;
  // Hysteria2 через вход: вход пересылает UDP ядром ОС на один выход — выбор одного
  const nat = !!info.natRelay && st.hy2Relay !== 'core';
  const oneExit = !!d.entryId && nat;
  // резервное плечо вход → выход: Hysteria2-конфигурации, у которых есть хоть один из выходов этой
  const legChoices = templates.filter((t) => t.spec.protocol === 'hysteria2' && t.id !== d.id && t.node_ids.some((id) => id !== d.entryId && d.nodeIds.includes(id)));
  const toggleNode = (id: string) => setD({ ...d, nodeIds: d.nodeIds.includes(id) ? d.nodeIds.filter((x) => x !== id) : oneExit && id !== d.entryId ? [id] : [...d.nodeIds, id] });
  const stateOf = (sid: string, kind: string) => current?.inbounds.find((i) => i.server_id === sid && i.kind === kind);
  const relayState = d.entryId ? stateOf(d.entryId, 'relay') : undefined;
  // схема: выбранные серверы (в порядке «Авто»), затем остальные — их можно включить кликом
  const lead = !st.autoEnabled ? undefined : health?.actual ?? health?.selected ?? (st.autoMode !== 'random' ? health?.rows.find((r) => r.ok)?.exit_id : undefined);
  const mapExits: MapExit[] = [
    ...exits.map((x): MapExit => {
      const ib = stateOf(x.id, 'direct');
      const h = health?.rows.find((r) => r.exit_id === x.id);
      if (ib?.state === 'error') return { id: x.id, name: x.name, state: 'fail', note: 'ошибка выката' };
      if (!ib || ib.state !== 'active') return { id: x.id, name: x.name, state: 'idle', note: ib ? 'выкатывается' : 'после выката' };
      if (!d.entryId || oneExit) return { id: x.id, name: x.name, state: x.fail_since ? 'fail' : 'ok', note: x.fail_since ? 'нет связи' : 'работает' };
      // через вход: панель может не заходить на выход, а вход до него доходит — это решают замеры входа (exitView)
      return { id: x.id, name: x.name, ...exitView(h, { lead: lead === x.id, failSince: x.fail_since, mode: st.autoEnabled ? st.autoMode : 'off' }) };
    }),
    ...managed.filter((s) => s.id !== d.entryId && !d.nodeIds.includes(s.id)).map((s): MapExit => ({ id: s.id, name: s.name, state: 'off', note: 'не используется' })),
  ].map((x) => {
    // выход без прямого доступа не попадает в подписку как «… · напрямую» — показываем это и даём открыть
    const s = managed.find((m) => m.id === x.id);
    if (!s || s.direct_access || x.state === 'off') return x;
    return { ...x, extra: (
      <button type="button" className="btn ghost sm rm-direct" title={`Прямой доступ к ${s.name} выключен: в подписке нет профиля «${s.name} · напрямую»`}
        onClick={async () => { if (await ask(`Открыть прямой доступ к ${s.name}? В подписках появится профиль «${s.name} · напрямую», сервер начнёт принимать пользователей напрямую.`)) void run(async () => { await api.patch(`/api/v1/servers/${s.id}`, { directAccess: true }); toast(`Прямой доступ к ${s.name} открыт`); onServers(); }); }}>
        только через вход
      </button>
    ) };
  });
  const [pick, setPick] = useState(false);
  const pickProtocol = (p: Protocol) => setD({ ...d, protocol: p, port: PROTO[p].port, st: defaults(p), entryId: PROTO[p].relay ? d.entryId : '' });
  // «через вход» выбран, а сам вход ещё нет; у Eskadra вход обязателен
  const [wantEntry, setWantEntry] = useState(false);
  const viaEntry = info.relay && (esk || !!d.entryId || wantEntry);
  // порядок выходов важен для «по порядку» и «по нагрузке» — стрелки, когда выходов больше одного
  const ordered = !!d.entryId && !oneExit && exits.length > 1;
  // транспорты протокола; REALITY работает только с TCP, gRPC и XHTTP
  const TR_ORDER: Transport[] = ['tcp', 'xhttp', 'grpc', 'ws', 'httpupgrade'];
  const trChoices = TR_ORDER.filter((x) => info.tr.includes(x) && (st.security !== 'reality' || ['tcp', 'grpc', 'xhttp'].includes(x)));
  const pickTransport = (x: Transport) => {
    if (x === 'xhttp') return setX(chainX ? (hyIn ? 'leg' : 'clients') : 'on');
    setWantCdn(false);
    setSt({ transport: x, entryTransport: '', cdn: '' });
  };
  const showFp = st.security !== 'none' && d.protocol !== 'hysteria2' && info.sec.length > 0;
  const showFlow = vless && st.security !== 'none' && (st.transport === 'tcp' || (chainX && st.entryTransport === 'tcp'));

  // мастер: протокол → маршрут (сначала вход, потом выходы) → защита и транспорт → проверка. Дальше не пускает, пока
  // не заполнен минимум шага; у сохранённой конфигурации открыты все шаги сразу
  const [step, setStep] = useState(0);
  const [seen, setSeen] = useState(draft.id ? 3 : 0);
  // имя не придумали — случайное, не занятое другой конфигурацией
  const [nameSeed] = useState(() => randomHex(2));
  const namePh = ((base: string) => { let n = base, i = 0; while (templates.some((t) => t.name === n && t.id !== d.id)) n = `${base}-${++i}`; return n; })(`${d.protocol}-${nameSeed}`);
  const sniList = d.sni.split(/[\s,]+/).filter(Boolean);
  // крупный сайт на чужих адресах: имя и адрес сервера не совпадают — по этому признаку DPI замечает REALITY
  const sniWeak = st.security === 'reality' && info.sec.includes('reality') && WEAK_SNI.includes(sniList[0] ?? '');
  const portOk = (v: string) => /^\d{1,5}$/.test(v.trim()) && Number(v) > 0 && Number(v) < 65536;
  const missing = [
    portOk(d.port) ? '' : 'Укажите порт',
    viaEntry && !d.entryId ? 'Выберите сервер-вход'
      : esk && !d.nodeIds.some((id) => id !== d.entryId) ? 'Выберите хотя бы один выход'
      : !d.nodeIds.length && !d.entryId ? 'Отметьте хотя бы один сервер'
      : d.entryId && !portOk(d.entryPort) ? 'Укажите порт входа' : '',
    st.security === 'reality' && info.sec.includes('reality') && !sniList.length ? 'Укажите сайт маскировки (SNI)'
      : tls && info.cert.length > 0 && st.certMode === 'domain' && !usedIds.every((id) => !!st.domains[id]) ? 'Укажите домен для каждого сервера'
      : tls && info.cert.length > 0 && st.certMode === 'custom' && !current?.hasCustomCert && !(d.certPem.trim() && d.keyPem.trim()) ? 'Вставьте сертификат и ключ'
      : xMode === 'cdn' && !st.cdn.trim() ? 'Укажите домен на CDN' : '',
    '',
  ];
  const reach = (i: number) => i <= seen || (i === seen + 1 && missing.slice(0, i).every((m) => !m));
  const go = (i: number) => {
    if (!reach(i)) return;
    // имя можно не придумывать: дальше первого шага — подсказанное
    if (i > 0 && !d.name) setD({ ...d, name: slugName(namePh) });
    setStep(i);
    setSeen(Math.max(seen, i));
  };
  const nameOf = (id: string) => servers.find((s) => s.id === id)?.name ?? id;
  const routeText = d.entryId ? `${nameOf(d.entryId)} → ${exits.map((x) => x.name).join(', ') || '—'}` : exits.map((x) => x.name).join(', ') || '—';
  const secText = [
    info.sec.length > 1 || st.security === 'tls' ? SEC_LABEL[st.security] : '',
    st.security === 'reality' ? sniList[0] ?? '' : tls && info.cert.length > 0 ? CERT_LABEL[st.certMode].replace(/ \(.*\)$/, '') : d.protocol === 'shadowsocks' ? st.ssMethod : d.protocol === 'mtproto' ? st.mtDomain : '',
  ].filter(Boolean).join(' · ');
  const trText = [info.tr.length > 1 ? TR_LABEL[st.transport] : '', xUsed ? `XHTTP: ${X_LABEL[xMode]}` : ''].filter(Boolean).join(' · ');
  const def = defaults(d.protocol);
  // сколько настроек отличается от значений протокола по умолчанию
  const changed = (Object.keys(st) as Array<keyof Settings>).filter((k) => !['exitOrder', 'domains', 'exitCapMbps', 'path'].includes(k) && JSON.stringify(st[k]) !== JSON.stringify(def[k])).length;
  // шаги и краткий итог каждого — как в консоли: «vless :443», «msk-1→2», «reality/tcp»
  const steps: Array<[string, string]> = [
    ['Протокол', `${esk ? 'eskadra' : d.protocol} :${d.port}`],
    ['Маршрут', d.entryId ? `${nameOf(d.entryId)}→${exits.length}` : `${exits.length} × node`],
    ['Защита', [info.sec.length > 1 || st.security === 'tls' ? st.security : '', info.tr.length > 1 ? (xUsed ? 'xhttp' : st.transport) : ''].filter(Boolean).join('/') || '—'],
    ['Выкат', pending ? 'черновик' : current?.applied_revision ? 'выкачена' : ''],
  ];
  // REVIEW: что уйдёт на серверы; PREFLIGHT: что известно до выката (порт, конфиг и доступность проверяет сам выкат)
  const review: Array<[string, string, number]> = [
    ['protocol', `${info.name} · ${d.name || namePh} · :${d.port}`, 0],
    ['route', routeText + (d.entryId ? ` · вход :${d.entryPort}` : '') + (d.entryId && !nat ? ` · auto=${st.autoEnabled ? st.autoMode : 'off'}` : ''), 1],
    ['security', secText || '—', 2],
    ...(trText ? [['transport', trText, 2] as [string, string, number]] : []),
    ['advanced', changed ? `изменено полей: ${changed}` : 'значения по умолчанию', 2],
  ];
  const preflight: Array<['ok' | 'warn' | 'info', string]> = [
    ...missing.filter(Boolean).map((m) => ['warn', `не хватает: ${m}`] as ['warn', string]),
    ...(missing.some(Boolean) ? [] : [['ok', 'минимум для работы заполнен'] as ['ok', string]]),
    ['ok', `${d.entryId ? `вход ${nameOf(d.entryId)}, выходов: ${exits.length}` : `серверов: ${exits.length}`}`],
    ...(sniWeak ? [['warn', `sni ${sniList[0]} не из сети сервера — выкатить можно, но лучше scan`] as ['warn', string]] : []),
    ...(tls && st.certMode === 'self' ? [['warn', 'самоподписанный сертификат: клиенты подключаются с insecure — лучше Let\'s Encrypt на IP'] as ['warn', string]] : []),
    ...(xUsed ? [['warn', 'xhttp понимают только клиенты на Xray: в подписке sing-box этих профилей не будет'] as ['warn', string]] : []),
    ...(d.protocol === 'shadowsocks' ? [['warn', 'shadowsocks без маскировки — держите как запасной'] as ['warn', string]] : []),
    ...(!info.udp && d.protocol !== 'mtproto' && !d.entryId && d.port.trim() !== '443' ? [['info', `порт :${d.port} — для маскировки под сайт лучше 443`] as ['info', string]] : []),
    ['info', 'выкат идёт по одному серверу: проверка конфига, открытие порта, проверка снаружи; ошибка — откат и остановка'],
  ];

  // минимум для работы и итог — в левой колонке, меняются на ходу
  const mins: Array<[string, boolean, boolean?]> = [
    ['протокол/имя/порт', !missing[0]],
    [viaEntry ? `вход ${d.entryId ? nameOf(d.entryId) : '—'}` : info.relay ? 'подключение напрямую' : 'подключение', !missing[1] && seen >= 1],
    [`${d.entryId ? 'выходы' : 'серверы'} ${exits.map((x) => x.name).join(' ') || '—'}`, exits.length > 0 || (!!d.entryId && d.nodeIds.includes(d.entryId))],
    [st.security === 'reality' && info.sec.includes('reality') ? `sni${sniWeak && seen >= 2 ? ' (слабый)' : ''}` : tls && info.cert.length > 0 ? 'сертификат' : d.protocol === 'shadowsocks' ? 'шифр' : 'маскировка', !missing[2] && seen >= 2, sniWeak && seen >= 2],
  ];
  const minDone = mins.filter(([, ok]) => ok).length;
  const summary: Array<[string, string, boolean?]> = [
    ['protocol', esk ? 'eskadra' : d.protocol],
    ['name', d.name || namePh],
    ['port', d.port],
    ...(info.relay ? [['entry', d.entryId ? `${nameOf(d.entryId)}:${d.entryPort}` : viaEntry ? '—' : 'direct', viaEntry && !d.entryId] as [string, string, boolean]] : []),
    [d.entryId ? 'exits' : 'nodes', `[${exits.map((x) => x.name).join(', ')}]`, !exits.length && !d.entryId],
    ...(info.sec.length > 1 ? [['security', st.security] as [string, string]] : []),
    ...(st.security === 'reality' && info.sec.includes('reality') ? [['sni', sniList[0] ?? '—', sniWeak || !sniList.length] as [string, string, boolean]] : []),
    ...(tls && info.cert.length > 0 ? [['cert', st.certMode] as [string, string]] : []),
    ...(info.tr.length > 1 ? [['transport', st.transport + (vless && st.transport === 'tcp' && st.flow ? '+vision' : '') + (xUsed && st.transport !== 'xhttp' ? ' · xhttp' : '')] as [string, string]] : []),
    ...(st.security !== 'none' && d.protocol !== 'hysteria2' && info.sec.length ? [['utls', d.fingerprint] as [string, string]] : []),
    ...(d.entryId && !nat ? [['auto', st.autoEnabled ? st.autoMode : 'off'] as [string, string]] : []),
  ];
  const describeLine = [esk ? 'eskadra' : d.protocol, info.sec.length > 1 || st.security === 'tls' ? st.security : '', info.tr.length > 1 ? st.transport : '', `:${d.port}`, d.entryId ? `→ ${nameOf(d.entryId)}` : '', exits.length ? `${exits.length} × ${d.entryId ? 'exit' : 'node'}` : ''].filter(Boolean).join(' · ');
  const LEAD = [
    'Как клиенты подключаются. От протокола зависит, что спросим дальше — лишних полей не будет.',
    'Сначала — куда подключаются клиенты, затем — через какие серверы трафик выходит в интернет. Хватит одного сервера.',
    'Шифрование, маскировка и транспорт.',
    'Сверьте итог и предупреждения. После выката конфигурация появится у пользователей, которым она выдана.',
  ];

  return (
    <section className="wz-wrap" aria-label={d.id ? d.name : 'Новая конфигурация'}>
      <aside className="wz-aside">
        <div className="wz-steps">
          <span className="wz-cap">{`// ${d.id ? d.name : 'новая конфигурация'}`}</span>
          {current && (pending ? <Tag kind="warn">черновик не выкачен</Tag> : current.applied_revision ? <Tag kind="ok" dot>выкачена</Tag> : <Tag>ещё не выкатывалась</Tag>)}
          <ol aria-label="Шаги">
            {steps.map(([title, sum], i) => {
              const done = i < 3 && i <= seen && i !== step && !missing[i];
              const bad = i <= seen && i !== step && !!missing[i];
              return (
                <li key={title}>
                  <button type="button" className={`wz-step${i === step ? ' cur' : done ? ' done' : bad ? ' bad' : ''}`} disabled={!reach(i)} aria-current={i === step ? 'step' : undefined} onClick={() => go(i)}>
                    <span aria-hidden="true">{i === step ? '[>]' : done ? '[✓]' : bad ? '[!]' : '[ ]'}</span>
                    <span className="wz-t">{`0${i + 1}`} <span className="lc">{title}</span></span>
                    {i <= seen && <span className="wz-sum">{sum}</span>}
                  </button>
                </li>
              );
            })}
          </ol>
        </div>
        <div className="wz-box">
          <div className="wz-box-h"><span>minimum</span><span className="wz-count">{minDone}/{mins.length}</span></div>
          <div className="wz-bar" aria-hidden="true"><i style={{ width: `${(minDone / mins.length) * 100}%` }} /></div>
          <ul className="wz-mins">
            {mins.map(([label, ok, weak]) => <li key={label} title={label} className={weak ? 'weak' : ok ? 'ok' : ''}>{weak ? '~' : ok ? '+' : '-'} {label}</li>)}
          </ul>
        </div>
        <div className="wz-box">
          <div className="wz-box-h"><span>итог</span><span>изменено: {changed}</span></div>
          <dl className="wz-sumlist">
            {summary.map(([k, v, warn]) => <div key={k}><dt>{k}</dt><dd className={warn ? 'warn' : ''}>{v}</dd></div>)}
          </dl>
        </div>
        <div className="wz-legend">
          <span><b className="req">REQUIRED</b> — без этого не выкатится</span>
          <span><b className="rec">RECOMMENDED</b> — заполнено, проверьте</span>
          <span><b>ADVANCED</b> — свёрнуто, по нужде</span>
        </div>
      </aside>

      <div className="wz-main">
      <div className="wz-head">
        <h2>{`0${step + 1}`} <span className="lc">{steps[step]![0]}</span></h2>
        <span className="mono k">{describeLine}</span>
      </div>
      <p className="wz-lead">{LEAD[step]}</p>

      {step === 0 && (
      <section className="blk">
        <div className="blk-h req">REQUIRED <span>протокол, имя, порт</span></div>
        <div className="kv">
          <span className="kv-k">протокол <span className="req">*</span> <Info>{Object.values(PROTO).map((x) => <span key={x.name}><b>{x.name}</b> — {x.hint} ({x.core}).<br /></span>)}Протокол существующей конфигурации не меняется — создайте новую.</Info></span>
          <div className="picks" role="radiogroup" aria-label="Протокол">
            {PICK_ORDER.filter((p) => !d.id || p === d.protocol).map((p) => (
              <label key={p} className="pick">
                <input type="radio" name="proto" checked={d.protocol === p} disabled={!!d.id && d.protocol !== p} onChange={() => pickProtocol(p)} />
                <span className="pick-t">{p === 'shadowsocks' ? 'SS-2022' : p === 'mtproto' ? 'MTProto' : PROTO[p].name}{PICK[p].tag && <span className={`tag ${PICK[p].kind}`}>{PICK[p].tag}</span>}</span>
                <span className="pick-d">{PICK[p].desc}</span>
              </label>
            ))}
          </div>
          <label className="kv-k" htmlFor="cfg-name">имя <span className="req">*</span></label>
          <div className="kv-v">
            <input id="cfg-name" className="inp mono" value={d.name} onChange={(e) => setD({ ...d, name: slugName(e.target.value) })} placeholder={namePh} />
            <span className="hint">Видно пользователям в приложении. a-z, 0-9 и дефис — остальное исправится само; пусто — возьмётся подсказанное.</span>
          </div>
          <label className="kv-k" htmlFor="cfg-port">порт <span className="mono">{info.udp ? 'udp' : 'tcp'}</span> <span className="req">*</span></label>
          <div className="kv-v">
            <span className="flex" style={{ gap: 8, flexWrap: 'nowrap' }}>
              <input id="cfg-port" className="inp mono" style={{ flex: 1 }} value={d.port} onChange={(e) => setD({ ...d, port: e.target.value })} inputMode="numeric" />
              {!info.udp && <button type="button" className="btn" onClick={() => setD({ ...d, port: '443' })}>443</button>}
              <button type="button" className="btn" title="Случайный свободный порт на серверах конфигурации" onClick={async () => setD(await randomPorts('port'))}>rand</button>
            </span>
            {d.port.trim() === '443' && !info.udp ? <span className="hint ok">Обычный порт HTTPS — меньше всего выделяется.</span>
              : <span className="hint">{info.udp ? 'Порт UDP. Новая конфигурация получает случайный свободный порт.' : 'Свободный порт подобран сам. Для маскировки под сайт лучше 443; со входом этот порт — у выходов.'}</span>}
          </div>
        </div>
      </section>
      )}

      {step === 1 && <>
      <section className="blk">
        <div className="blk-h req">REQUIRED <span>сначала вход, затем выходы</span></div>
        {!managed.length ? <div className="blk-b"><span className="hint warn">Нет подключённых серверов — добавьте их в разделе «Серверы».</span></div> : (
        <div className="kv">
          {info.relay ? <>
            <span className="kv-k">1 · подключение <span className="req">*</span> <Info>Напрямую — каждый сервер принимает пользователей сам. Через вход — пользователи подключаются к ближнему серверу-входу, а в интернет выходят через выбранные выходы; в подписке появятся профили «вход → выход» и «вход → авто».</Info></span>
            <div className="picks picks-2" role="radiogroup" aria-label="Подключение">
              {!esk && <label className="pick">
                <input type="radio" name="via" checked={!viaEntry} onChange={() => { setWantEntry(false); setD({ ...d, entryId: '' }); }} />
                <span className="pick-t">напрямую</span>
                <span className="pick-d">Каждый сервер принимает клиентов сам. Проще всего.</span>
              </label>}
              <label className="pick">
                <input type="radio" name="via" checked={viaEntry} onChange={() => setWantEntry(true)} />
                <span className="pick-t">через вход{esk && <span className="tag acc">нужен Eskadra</span>}</span>
                <span className="pick-d">Клиенты — к ближнему серверу, в интернет — через дальние.</span>
              </label>
            </div>
          </> : <>
            <span className="kv-k">подключение</span>
            <span className="hint">{info.name} работает только напрямую: клиенты подключаются к каждому выбранному серверу.</span>
          </>}

          {viaEntry && <>
            <span className="kv-k">2 · вход <span className="req">*</span></span>
            <div className="kv-v kv-wide">
              <div className="radios" role="radiogroup" aria-label="Сервер-вход">
                {managed.map((s) => (
                  <label key={s.id} className="rdo">
                    <input type="radio" name="entry" checked={d.entryId === s.id} onChange={() => setD({ ...d, entryId: s.id, nodeIds: nat ? d.nodeIds.filter((x) => x !== s.id).slice(0, 1) : d.nodeIds })} />
                    <span className="mono">{s.name}</span>
                  </label>
                ))}
              </div>
              {d.entryId && <>
                <div className="flex" style={{ gap: '8px 20px' }}>
                  <label className="flex mono small" style={{ gap: 8 }}>порт входа
                    <input className="inp mono" style={{ width: 96 }} inputMode="numeric" value={d.entryPort} onChange={(e) => setD({ ...d, entryPort: e.target.value })} aria-label="Порт входа" />
                    <button type="button" className="btn sm" title="Случайный свободный порт на сервере-входе" onClick={async () => setD(await randomPorts('entry'))}>rand</button>
                  </label>
                  {relayState && <Tag kind={relayState.state === 'active' ? 'ok' : relayState.state === 'error' ? 'fail' : 'warn'}>{STATE_LABEL[relayState.state] ?? relayState.state}</Tag>}
                  {!nat && <label className="cb mono small"><input type="checkbox" checked={d.nodeIds.includes(d.entryId)} onChange={() => toggleNode(d.entryId)} />вход и сам принимает напрямую</label>}
                </div>
                {d.entryPort.trim() === '443' ? <span className="hint ok">Клиенты подключаются только к входу — 443 выглядит как обычный HTTPS.</span>
                  : <span className="hint">Клиенты подключаются только к входу. Для маскировки и CDN лучше 443.</span>}
              </>}
              {info.natRelay && <>
                <Seg value={st.hy2Relay} label="Режим входа Hysteria2" onChange={(v) => setSt({ hy2Relay: v, autoEnabled: v === 'core' })} options={[['core', 'ядра на входе'], ['nat', 'пересылка']]} />
                <span className="hint">{nat ? 'Пересылка: вход перекидывает UDP ядром системы на один выход, без своего ядра VPN. У выхода нужен IPv4-адрес.' : 'Ядра на входе: вход сам принимает Hysteria2 и выбирает выход — можно несколько выходов и авто-выбор.'}</span>
              </>}
              {esk && <>
                <Seg value={st.entryProto} label="Протокол на входе" onChange={(v) => setSt({ entryProto: v, ...(v === 'hysteria2' && st.autoMode === 'spread' ? { autoMode: 'order' as AutoMode } : {}) })}
                  options={[['vless', 'vless → резерв hy2'], ['hysteria2', 'hy2 → резерв vless']]} />
                <span className="hint">VLESS проходит почти везде. Hysteria2 быстрее, если провайдер не режет UDP. Второй протокол — резерв между входом и выходами. Смена меняет ссылки «через вход» — пользователям нужно обновить подписку.</span>
              </>}
            </div>
          </>}

          <span className="kv-k">{info.relay ? (viaEntry ? '3 · выходы' : '2 · серверы') : 'серверы'} <span className="req">*</span></span>
          <div className="kv-v kv-wide">
            <ul className="exits">
              {mapExits.map((x) => {
                const on = x.state !== 'off';
                const i = exits.findIndex((e) => e.id === x.id);
                return (
                  <li key={x.id} className={`ex${on ? ' on' : ''}`}>
                    <label className="ex-pick"><input type="checkbox" checked={on} onChange={() => toggleNode(x.id)} /><span className="mono">{x.name}</span></label>
                    <span className={`ex-note ${x.state}`}>{x.note}</span>
                    {x.extra}
                    {ordered && on && <>
                      <span className="ex-rank">#{i + 1}</span>
                      <button type="button" className="btn sm ex-mv" disabled={i === 0} aria-label={`${x.name} выше`} onClick={() => move(i, -1)}>↑</button>
                      <button type="button" className="btn sm ex-mv" disabled={i === exits.length - 1} aria-label={`${x.name} ниже`} onClick={() => move(i, 1)}>↓</button>
                    </>}
                  </li>
                );
              })}
            </ul>
            <span className="hint">{viaEntry ? 'Порядок важен для режима «порядок»: #1 — основной. Входной сервер выходом быть не может.' : 'Клиенты получат по профилю на каждый отмеченный сервер.'}</span>
            {oneExit && <span className="hint">Пересылка ведёт на один выход: отметка другого заменяет прежний.</span>}
            {current?.inbounds.filter((ib) => ib.error).map((ib) => <span key={ib.id} className="hint warn">{nameOf(ib.server_id)}{ib.kind === 'hy2' ? ' (Hysteria2)' : ''}: {ib.error}</span>)}
          </div>
        </div>
        )}
      </section>

      {d.entryId && info.relay && !nat && (
      <section className="blk">
        <div className="blk-h rec">RECOMMENDED <span>предзаполнено</span></div>
        <div className="kv">
          <span className="kv-k">авто-выбор выхода <Info>Включён — у пользователей есть профиль «вход → авто»: вход сам выбирает выход и переключает его, если тот перестал отвечать. Выключен — только явные профили «вход → выход». Задержку вход проверяет раз в минуту, скорость панель меряет по расписанию; о каждом переключении бот пишет админам.</Info></span>
          <div className="kv-v kv-wide">
            <span className="flex" style={{ gap: 12 }}><Switch label="Авто-выбор выхода" on={st.autoEnabled} onChange={(v) => setSt({ autoEnabled: v })} /><span className="mono small muted">{st.autoEnabled ? 'вход сам переводит трафик на рабочий выход' : 'только явные профили «вход → выход»'}</span></span>
            {st.autoEnabled && <>
              <Seg value={st.autoMode} label="Выбор выхода" onChange={(v) => setSt({ autoMode: v })} options={[['smart', 'качество'], ['order', 'порядок'], ['random', 'случайно'], ...(d.protocol === 'hysteria2' || hyIn ? [] : [['spread', 'нагрузка'] as [AutoMode, string]])]} />
              <span className="hint">{AUTO_HINT[st.autoMode]}</span>
              {st.autoMode === 'smart' && (
                <div className="grid g4 mini">
                  <label className="fld">задержка ≤, мс<input className="inp mono" inputMode="numeric" value={st.maxRttMs} onChange={(e) => setSt({ maxRttMs: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  <label className="fld">скорость ≥, Мбит/с<input className="inp mono" inputMode="decimal" value={st.minMbps} onChange={(e) => setSt({ minMbps: Number(e.target.value.replace(/[^\d.]/g, '')) })} /></label>
                  <label className="fld">проверка, мин<input className="inp mono" inputMode="numeric" value={st.checkMin} onChange={(e) => setSt({ checkMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  <label className="fld"><span>тест, МБ <Info>Сколько скачивать через каждый выход при проверке скорости. 5 МБ раз в 15 минут — около 0,5 ГБ трафика в сутки на выход.</Info></span><input className="inp mono" inputMode="numeric" value={st.testMB} onChange={(e) => setSt({ testMB: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                </div>
              )}
              {st.autoMode === 'order' && (
                <div className="grid g4 mini">
                  <label className="fld"><span>скорость ≥, Мбит/с <Info>0 — не мерить: только доступность. Иначе выход медленнее порога пропускается — трафик идёт на следующий по порядку. Медленный снова считается быстрым от порога +10%.</Info></span>
                    <input className="inp mono" inputMode="decimal" value={st.orderMinMbps} onChange={(e) => setSt({ orderMinMbps: Number(e.target.value.replace(/[^\d.]/g, '')) })} placeholder="0" /></label>
                  {st.orderMinMbps > 0 && <>
                    <label className="fld">мерить каждые, мин<input className="inp mono" inputMode="numeric" value={st.speedEveryMin} onChange={(e) => setSt({ speedEveryMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                    <label className="fld"><span>решать каждые, мин <Info>Выход пропускается или возвращается по медиане замеров за это время. 1 минута — по последнему замеру.</Info></span><input className="inp mono" inputMode="numeric" value={st.decideMin} onChange={(e) => setSt({ decideMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                    <label className="fld">тест, МБ<input className="inp mono" inputMode="numeric" value={st.testMB} onChange={(e) => setSt({ testMB: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                    <span className="hint" style={{ gridColumn: '1 / -1' }}>{`Трафик на замеры: около ${speedTraffic(st.testMB, st.speedEveryMin)} ГБ в сутки на каждый выход.`}</span>
                  </>}
                </div>
              )}
              {st.autoMode === 'spread' && (
                <div className="stack" style={{ gap: 12 }}>
                  <div className="flex" style={{ justifyContent: 'space-between' }}>
                    <span className="mono small muted">каналы выходов <Info>Замер идёт на самом сервере: speedtest от Ookla, если он установлен, иначе тестовые файлы Hetzner, OVH и Tele2. На время замера (~25 с) канал занят целиком. Своё значение в поле важнее замера; пусто — по замеру.</Info></span>
                    <button type="button" className="btn sm" disabled={!!measuring || !exits.length} onClick={() => void measure(exits.map((x) => x.id))}>{measuring ? `Замеряю ${nameOf(measuring)}…` : 'Замерить все'}</button>
                  </div>
                  <div className="grid g4 mini">
                    {exits.map((x) => {
                      const l = links?.[x.id];
                      const cap = linkCap(l);
                      return (
                        <div key={x.id} className="fld">
                          <label className="stack" style={{ gap: 4 }}><span>канал {x.name}, Мбит/с</span>
                            <input className="inp mono" inputMode="numeric" value={st.exitCapMbps[x.id] || ''} placeholder={cap ? `${cap} — по замеру` : 'не замерен'} aria-label={`Канал ${x.name}, Мбит/с`}
                              onChange={(e) => setSt({ exitCapMbps: { ...st.exitCapMbps, [x.id]: Number(e.target.value.replace(/\D/g, '')) } })} /></label>
                          <span className="k flex" style={{ gap: 8 }}>
                            {l ? <span className="mono">{`↓${l.down} ↑${l.up} · ${l.source === 'ookla' ? 'Ookla' : 'зеркала'} · ${ago(l.at)}`}</span> : <span>замера нет</span>}
                            <button type="button" className="btn ghost sm" disabled={!!measuring} onClick={() => void measure([x.id])}>{measuring === x.id ? 'замеряю…' : 'Замерить'}</button>
                          </span>
                        </div>
                      );
                    })}
                  </div>
                  <div className="grid g4 mini">
                    <label className="fld"><span>перевод при загрузке, % <Info>Канал выхода загружен сильнее — самая тяжёлая группа, которая поместится, переводится на выход с запасом. Между переводами — не меньше 3 минут.</Info></span>
                      <input className="inp mono" inputMode="numeric" value={st.spreadHighPct} onChange={(e) => setSt({ spreadHighPct: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                    <label className="fld"><span>групп пользователей <Info>Больше групп — точнее делится нагрузка, но чаще меняется выход у части пользователей. Для 10–50 пользователей и 2–4 выходов хватает 6.</Info></span>
                      <input className="inp mono" inputMode="numeric" value={st.spreadGroups} onChange={(e) => setSt({ spreadGroups: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  </div>
                  <span className="flex" style={{ gap: 12 }}><Switch label="Делить канал поровну" on={st.spreadFair} onChange={(v) => setSt({ spreadFair: v })} /><span className="mono small muted">делить канал выхода поровну между соединениями <Info>Пока группы переезжают, перегруженный канал делится честно: на выходах с заданной ёмкостью ставится очередь cake на 95% канала и BBR. Ёмкость указывайте реальную: заниженная — урежет скорость.</Info></span></span>
                </div>
              )}
            </>}
          </div>
        </div>
      </section>
      )}

      {d.entryId && info.relay && info.core === 'Xray' && (
      <section className="blk">
        <div className="blk-h fine">ADVANCED <span>свёрнуто</span></div>
        <Adv title="резервное плечо" sum={`backup=${templates.find((t) => t.id === st.hy2Leg)?.name ?? 'нет'}`}>
          <label className="fld" style={{ maxWidth: 420 }}><span>Hysteria2-конфигурация <Info>Если основное плечо от входа до выхода перестаёт отвечать, вход за ~10 секунд ведёт трафик этого выхода по Hysteria2 и сам возвращается, когда основное снова отвечает. Нужна конфигурация Hysteria2 на тех же выходах. На входе дополнительно запускается sing-box.</Info></span>
            <select className="inp" value={st.hy2Leg} onChange={(e) => setSt({ hy2Leg: e.target.value })}>
              <option value="">нет</option>
              {legChoices.map((t) => <option key={t.id} value={t.id}>Hysteria2 «{t.name}»</option>)}
              {st.hy2Leg && !legChoices.some((t) => t.id === st.hy2Leg) && <option value={st.hy2Leg}>недоступна — выберите другую</option>}
            </select>
          </label>
          <span className="hint">Упадёт основное плечо между серверами — вход пустит трафик через Hysteria2. Ссылки у пользователей не меняются.</span>
        </Adv>
      </section>
      )}
      </>}

      {step === 2 && <>
      <section className="blk">
        <div className="blk-h req">REQUIRED <span>{st.security === 'reality' && info.sec.includes('reality') ? 'защита и sni' : tls && info.cert.length ? 'защита и сертификат' : 'защита и маскировка'}</span></div>
        <div className="kv">
          {info.sec.length > 1 && <>
            <span className="kv-k">защита <span className="req">*</span></span>
            <div className="picks" role="radiogroup" aria-label="Защита">
              {info.sec.map((x) => (
                <label key={x} className="pick">
                  <input type="radio" name="sec" checked={st.security === x} onChange={() => setSt({ security: x, flow: x === 'none' ? '' : st.flow, transport: x === 'reality' && !['tcp', 'grpc', 'xhttp'].includes(st.transport) ? 'tcp' : st.transport })} />
                  <span className="pick-t">{x}{SEC_PICK[x].tag && <span className={`tag ${SEC_PICK[x].kind}`}>{SEC_PICK[x].tag}</span>}</span>
                  <span className="pick-d">{SEC_PICK[x].desc}</span>
                </label>
              ))}
            </div>
          </>}

          {st.security === 'reality' && info.sec.includes('reality') && <>
            <label className="kv-k" htmlFor="cfg-sni">sni <span className="req">*</span> <Info>Чужой сайт с TLS 1.3 и HTTP/2, под который маскируется сервер. Можно несколько через пробел — все имена должны обслуживаться первым сайтом. www.microsoft.com с REALITY не работает.</Info></label>
            <div className="kv-v">
              <span className="flex" style={{ gap: 8, flexWrap: 'nowrap' }}>
                <input id="cfg-sni" className={`inp mono${sniWeak ? ' warn' : ''}`} style={{ flex: 1 }} value={d.sni} onChange={(e) => setD({ ...d, sni: e.target.value })} placeholder="сайт из сети сервера" />
                <button type="button" className="btn" disabled={!managed.length} onClick={() => setPick(true)}>scan…</button>
              </span>
              <span className="hint">Лучше сайт из той же подсети или ASN, что и сервер, на TLS 1.3 + HTTP/2. scan ищет таких соседей с ваших серверов.</span>
              {sniWeak && <span className="hint warn">Не из сети сервера — несовпадение IP и SNI заметно DPI. Можно выкатить, но лучше заменить.</span>}
            </div>
          </>}

          {tls && info.cert.length > 0 && <>
            <span className="kv-k">сертификат <span className="req">*</span> <Info>Let's Encrypt на IP выпускается на каждом сервере сам и продлевается автоматически (порт 80 на время выпуска). Для домена — A-запись должна указывать на сервер. Загруженный сертификат раздаётся на все серверы конфигурации.</Info></span>
            <div className="kv-v kv-wide">
              <div className="picks picks-col" role="radiogroup" aria-label="Сертификат">
                {info.cert.map((m) => (
                  <label key={m} className="pick">
                    <input type="radio" name="cert" checked={st.certMode === m} onChange={() => setSt({ certMode: m })} />
                    <span className="pick-t">{CERT_PICK[m].label}{m === 'ip' && <span className="tag ok">rec</span>}</span>
                    <span className="pick-d">{CERT_PICK[m].desc}</span>
                  </label>
                ))}
              </div>
              {st.certMode === 'domain' && (
                <div className="grid g2">
                  {usedIds.length ? usedIds.map((id) => (
                    <label key={id} className="fld"><span>{`${nameOf(id)} — домен`}</span>
                      <input className="inp mono" value={st.domains[id] ?? ''} onChange={(e) => setSt({ domains: { ...st.domains, [id]: e.target.value.trim() } })} placeholder="de.example.com" />
                    </label>
                  )) : <span className="hint warn">Сначала выберите серверы на шаге «Маршрут».</span>}
                </div>
              )}
              {st.certMode === 'custom' && (
                <div className="stack" style={{ gap: 8 }}>
                  <label className="fld">Домен в сертификате (клиенты проверяют его)<input className="inp mono" value={st.domain} onChange={(e) => setSt({ domain: e.target.value.trim() })} placeholder="vpn.example.com" /></label>
                  {current?.hasCustomCert && !d.certPem && <span className="hint ok">Сертификат загружен. Чтобы заменить — вставьте новый.</span>}
                  <div className="grid g2">
                    <label className="fld">Сертификат (fullchain.pem)<textarea className="inp mono" rows={4} value={d.certPem} onChange={(e) => setD({ ...d, certPem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} /></label>
                    <label className="fld">Ключ (privkey.pem)<textarea className="inp mono" rows={4} value={d.keyPem} onChange={(e) => setD({ ...d, keyPem: e.target.value })} placeholder="-----BEGIN PRIVATE KEY-----" spellCheck={false} /></label>
                  </div>
                </div>
              )}
              {st.certMode === 'self' && <>
                <label className="fld">Имя в сертификате (SNI)<input className="inp mono" value={d.sni} onChange={(e) => setD({ ...d, sni: e.target.value })} placeholder="hy.example" /></label>
                <span className="hint warn">Клиенты не смогут проверить сервер: в ссылках будет insecure. Лучше Let's Encrypt на IP.</span>
              </>}
            </div>
          </>}

          {d.protocol === 'shadowsocks' && <>
            <label className="kv-k" htmlFor="cfg-ss">шифр <span className="req">*</span></label>
            <div className="kv-v">
              <select id="cfg-ss" className="inp mono" value={st.ssMethod} onChange={(e) => setSt({ ssMethod: e.target.value })}>
                {['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].map((m) => <option key={m}>{m}</option>)}
              </select>
              <span className="hint">aes-128 — на серверах с AES-NI, chacha20 — на слабых ARM.</span>
              <span className="hint warn">Без маскировки под сайт: распознаётся по первым байтам. Держите как запасной вариант.</span>
            </div>
          </>}

          {d.protocol === 'mtproto' && <>
            <label className="kv-k" htmlFor="cfg-mt">fake-tls домен <span className="req">*</span></label>
            <div className="kv-v">
              <input id="cfg-mt" className="inp mono" value={st.mtDomain} onChange={(e) => setSt({ mtDomain: e.target.value.trim() })} placeholder="www.apple.com" />
              <span className="hint">Telegram подключается как будто к этому сайту; неопознанные подключения уходят на него. На одном сервере — одна конфигурация MTProto.</span>
            </div>
          </>}

          {xMode === 'cdn' && <>
            <label className="kv-k" htmlFor="cfg-cdn">cdn домен <span className="req">*</span></label>
            <div className="kv-v">
              <input id="cfg-cdn" className="inp mono" value={st.cdn} onChange={(e) => setSt({ cdn: e.target.value.trim().toLowerCase() })} placeholder="vpn.example.com" />
              <span className="hint">Поддомен в Cloudflare (Proxied) → IP входа. Клиенты получат его вместо адреса входа.</span>
              {!CDN_PORTS.includes(d.entryPort) && (
                <span className="hint warn">Cloudflare проксирует только порты {CDN_PORTS.join(', ')} — сейчас у входа {d.entryPort}.{' '}
                  <button type="button" className="link" onClick={() => setD({ ...d, entryPort: '443' })}>поставить 443</button></span>
              )}
              <details className="more">
                <summary>Как настроить Cloudflare (5 минут)</summary>
                <ol className="small" style={{ margin: '8px 0 0', paddingLeft: 20, lineHeight: 1.6 }}>
                  <li>Добавьте свой домен в Cloudflare (бесплатный тариф подходит) и смените у регистратора NS-серверы на выданные Cloudflare.</li>
                  <li>DNS → Add record: тип A, имя — поддомен (например, vpn), адрес — IP входа <b className="mono">{entryHost || '—'}</b>, Proxy status — Proxied (оранжевое облако).</li>
                  <li>SSL/TLS → Overview: режим Full (не «Full (strict)») — вход отдаёт свой самоподписанный сертификат, панель выпустит его сама.</li>
                  <li>Порт входа — один из {CDN_PORTS.join(', ')}. Network → gRPC включать не нужно: по умолчанию ссылки используют режим packet-up, он проходит через любой CDN. Выбрали в тонкой настройке stream-up или stream-one — включите gRPC.</li>
                  <li>Сохраните и выкатите конфигурацию, затем обновите подписку у клиентов. Проверить: домен с портом входа, открытый в браузере по HTTPS, не должен давать ошибку Cloudflare 52x (521, 525, 526) — она значит, что CDN не достучался до входа.</li>
                </ol>
              </details>
            </div>
          </>}

          {st.security === 'none' && info.sec.length > 1 && <>
            <span className="kv-k">внимание</span>
            <span className="hint warn">Без шифрования трафик открыт. Только если TLS даёт CDN или прокси.</span>
          </>}
          {info.sec.length < 2 && !tls && d.protocol !== 'shadowsocks' && d.protocol !== 'mtproto' && <span className="hint">Отдельной защиты у протокола нет.</span>}
        </div>
      </section>

      {(trChoices.length > 1 || showFp || d.protocol === 'hysteria2' || esk) && (
      <section className="blk">
        <div className="blk-h rec">RECOMMENDED <span>предзаполнено</span></div>
        <div className="kv">
          {trChoices.length > 1 && <>
            <span className="kv-k">транспорт <Info>TCP — по умолчанию и быстрее всего. XHTTP — трафик похож на обычные HTTP-запросы, помогает, когда соединение режут; понимают только клиенты на Xray. gRPC, WebSocket, HTTPUpgrade — если сервер за CDN или прокси.</Info></span>
            <div className="picks" role="radiogroup" aria-label="Транспорт">
              {trChoices.map((x) => (
                <label key={x} className="pick">
                  <input type="radio" name="tr" checked={x === 'xhttp' ? xUsed : !xUsed && st.transport === x} onChange={() => pickTransport(x)} />
                  <span className="pick-t">{x === 'tcp' && vless && st.security !== 'none' ? 'tcp+vision' : x}{TR_PICK[x].tag && <span className={`tag ${TR_PICK[x].kind}`}>{TR_PICK[x].tag}</span>}</span>
                  <span className="pick-d">{TR_PICK[x].desc}</span>
                </label>
              ))}
            </div>
          </>}

          {xUsed && chainX && <>
            <span className="kv-k">xhttp где</span>
            <div className="kv-v kv-wide">
              <Seg value={xMode} label="Где XHTTP" onChange={setX}
                options={hyIn ? [['leg', 'между серверами']] : [['clients', 'для клиентов'], ['leg', 'между серверами'], ['all', 'везде'], ['cdn', 'через cdn']]} />
              <span className="hint">{hyIn && xMode === 'leg' ? 'XHTTP — у резервного плеча VLESS между входом и выходами. Клиенты подключаются к входу по Hysteria2.' : X_HINT[xMode]}</span>
            </div>
          </>}

          {showFp && <>
            <label className="kv-k" htmlFor="cfg-fp">utls</label>
            <div className="kv-v">
              <select id="cfg-fp" className="inp mono" style={{ maxWidth: 280 }} value={d.fingerprint} onChange={(e) => setD({ ...d, fingerprint: e.target.value })}>{['chrome', 'firefox', 'safari', 'edge', 'random'].map((f) => <option key={f}>{f}</option>)}</select>
              <span className="hint">chrome — самый частый отпечаток в сети, на нём трафик теряется лучше всего.</span>
            </div>
          </>}

          {(d.protocol === 'hysteria2' || esk) && <>
            <span className="kv-k">hysteria2 <Info>{esk ? 'У Eskadra Hysteria2 работает на выходах рядом с VLESS: по ней вход ведёт трафик до выхода — основным или резервным плечом.' : 'Настройки маскировки QUIC и смены портов. Клиенты получают их из ссылки и подписки.'}</Info></span>
            <div className="kv-v kv-wide">
              <span className="flex" style={{ gap: 12 }}>
                <Switch label="obfs salamander" on={!!st.hy2Obfs} onChange={(v) => setSt({ hy2Obfs: v ? randomHex(16) : '' })} /><span className="mono small">obfs salamander</span>
                {!!st.hy2Obfs && <span className="flex" style={{ gap: 8 }}><input className="inp mono" style={{ width: 260 }} value={st.hy2Obfs} onChange={(e) => setSt({ hy2Obfs: e.target.value })} aria-label="Пароль obfs" /><button type="button" className="btn sm" onClick={() => setSt({ hy2Obfs: randomHex(16) })}>rand</button></span>}
              </span>
              <span className="hint">Прячет признаки QUIC в первых пакетах — у большинства провайдеров РФ проходимость выше. Клиенты должны поддерживать obfs.</span>
              <span className="flex" style={{ gap: 12 }}>
                <Switch label="port hopping" on={!!st.hy2Hop.trim()} onChange={(v) => setSt({ hy2Hop: v ? '20000-30000' : '' })} /><span className="mono small">port hopping</span>
                {!!st.hy2Hop.trim() && <input className="inp mono" style={{ width: 160 }} value={st.hy2Hop} onChange={(e) => setSt({ hy2Hop: e.target.value })} placeholder="20000-30000" aria-label="Диапазон портов" />}
              </span>
              <span className="hint">Клиент периодически меняет UDP-порт из диапазона — одно соединение сложнее задушить. Диапазон откройте и во внешнем файрволе хостера.</span>
            </div>
          </>}
        </div>
      </section>
      )}

      <section className="blk">
        <div className="blk-h fine">ADVANCED <span>пусто = значение ядра; без причины не трогать — нестандартное выделяется</span></div>
        {xUsed && (
          <Adv title="xhttp" sum={`mode=${st.xhttpMode} path=${st.path || '/'}`}>
            <span className="hint">Пустое поле — значение Xray по умолчанию (серым). Число или диапазон «16-32» — Xray берёт случайное значение для каждого соединения.</span>
            <div className="grid g3">
              <label className="fld"><span>path <Info>Путь HTTP-запросов XHTTP — один у сервера и клиентов. Случайный путь не даёт сканерам найти прокси запросом на «/».</Info></span>
                <span className="flex" style={{ gap: 8, flexWrap: 'nowrap' }}><input className="inp mono" style={{ flex: 1 }} value={st.path} onChange={(e) => setSt({ path: e.target.value })} placeholder="/" aria-label="Путь XHTTP" /><button type="button" className="btn sm" onClick={() => setSt({ path: '/' + randomHex(6) })}>rand</button></span></label>
              <label className="fld"><span>host <Info>Заголовок Host запросов. Обычно пусто; у входа за CDN панель ставит домен CDN сама.</Info></span><input className="inp mono" value={st.host} onChange={(e) => setSt({ host: e.target.value.trim() })} placeholder="—" aria-label="Host XHTTP" /></label>
              <label className="fld"><span>mode <Info>auto — клиент выбирает сам: с REALITY — stream-one, с TLS — stream-up. packet-up — медленнее, зато проходит где угодно.</Info></span><select className="inp mono" value={st.xhttpMode} onChange={(e) => setSt({ xhttpMode: e.target.value })} aria-label="Режим XHTTP">{['auto', 'packet-up', 'stream-up', 'stream-one'].map((m) => <option key={m}>{m}</option>)}</select></label>
              {xMode === 'cdn' && <>
                <label className="fld"><span>mode через cdn <Info>packet-up проходит через любой CDN. stream-up и stream-one через Cloudflare — только с включённым Network → gRPC.</Info></span><select className="inp mono" value={st.cdnMode} onChange={(e) => setSt({ cdnMode: e.target.value as Settings['cdnMode'] })} aria-label="Режим через CDN">{['packet-up', 'stream-up', 'stream-one'].map((m) => <option key={m}>{m}</option>)}</select></label>
                <span className="flex" style={{ gap: 12, alignSelf: 'end', minHeight: 38 }}><Switch label="HTTP/3 до CDN" on={st.cdnH3} onChange={(v) => setSt({ cdnH3: v })} /><span className="mono small">http/3 до cdn</span></span>
              </>}
            </div>
            {X_FIELDS.map(({ group, fields }) => (
              <div key={group} className="stack" style={{ gap: 8 }}>
                <span className="mono small muted">{group}</span>
                <div className="grid g3">
                  {fields.map(([k, label, def, hint]) => (
                    <label key={k} className="fld"><span>{label} <Info>{hint}</Info></span>
                      <input className="inp mono" value={st.xhttpExtra[k] ?? ''} onChange={(e) => setSt({ xhttpExtra: { ...st.xhttpExtra, [k]: e.target.value.replace(/[^\d-]/g, '') } })} placeholder={def} aria-label={label} /></label>
                  ))}
                </div>
                {group === 'Маскировка' && (
                  <span className="flex" style={{ gap: '8px 24px' }}>
                    <span className="flex" style={{ gap: 12 }}><Switch label="Без заголовка gRPC" on={!!st.xhttpExtra.noGRPCHeader} onChange={(v) => setSt({ xhttpExtra: { ...st.xhttpExtra, noGRPCHeader: v } })} /><span className="mono small">без заголовка grpc</span></span>
                    <span className="flex" style={{ gap: 12 }}><Switch label="Без заголовка SSE" on={!!st.xhttpExtra.noSSEHeader} onChange={(v) => setSt({ xhttpExtra: { ...st.xhttpExtra, noSSEHeader: v } })} /><span className="mono small">без заголовка sse</span></span>
                  </span>
                )}
              </div>
            ))}
            <span className="hint">Раздельные пути для загрузки и отдачи (downloadSettings) и свои заголовки панель не настраивает: их вписывают в клиент вручную.</span>
          </Adv>
        )}
        {xUsed && (
          <Adv title="xmux" sum={Object.values(st.xhttpExtra.xmux ?? {}).some(Boolean) ? 'изменено' : 'по умолчанию'}>
            <span className="hint">Клиент держит несколько HTTP/2- или HTTP/3-соединений и раскладывает по ним соединения пользователя. Не раздувайте число соединений: всплеск из десятка TLS-соединений разом — известный повод для блокировки.</span>
            <div className="grid g3">
              {XMUX_FIELDS.map(([k, label, def, hint]) => (
                <label key={k} className="fld"><span>{label} <Info>{hint}</Info></span>
                  <input className="inp mono" value={st.xhttpExtra.xmux?.[k] ?? ''} onChange={(e) => setSt({ xhttpExtra: { ...st.xhttpExtra, xmux: { ...st.xhttpExtra.xmux, [k]: e.target.value.replace(/[^\d-]/g, '') } } })} placeholder={def} aria-label={label} /></label>
              ))}
            </div>
            {st.xhttpExtra.xmux?.maxConcurrency && st.xhttpExtra.xmux?.maxConnections && <span className="hint warn">«Потоков на соединение» и «Соединений» вместе не задаются — оставьте одно.</span>}
            {Object.keys(cleanExtra(st.xhttpExtra)).length > 0 && <span><button type="button" className="btn sm" onClick={() => setSt({ xhttpExtra: {} })}>Сбросить xhttp к умолчаниям Xray</button></span>}
          </Adv>
        )}
        {!xUsed && ['ws', 'httpupgrade'].includes(st.transport) && (
          <Adv title={st.transport} sum={`path=${st.path || '/'}`}>
            <div className="grid g3">
              <label className="fld">path<input className="inp mono" value={st.path} onChange={(e) => setSt({ path: e.target.value })} placeholder="/" /></label>
              <label className="fld"><span>host <Info>Нужен, если перед сервером обратный прокси с несколькими сайтами.</Info></span><input className="inp mono" value={st.host} onChange={(e) => setSt({ host: e.target.value.trim() })} placeholder="—" /></label>
            </div>
          </Adv>
        )}
        {!xUsed && st.transport === 'grpc' && (
          <Adv title="grpc" sum={`serviceName=${st.serviceName}`}>
            <label className="fld" style={{ maxWidth: 320 }}>serviceName<input className="inp mono" value={st.serviceName} onChange={(e) => setSt({ serviceName: e.target.value.trim() })} /></label>
          </Adv>
        )}
        <Adv title="handshake" sum={[showFlow ? `flow=${st.flow ? 'vision' : 'нет'}` : '', st.security === 'tls' && d.protocol !== 'hysteria2' ? `alpn=${st.alpn.join(',') || '—'}` : '', `ech=${d.ech ? 'on' : 'off'}`].filter(Boolean).join(' ')}>
          <div className="grid g3">
            {showFlow && <label className="fld"><span>flow <Info>Vision работает только с TCP. У XHTTP панель снимает его сама.</Info></span><select className="inp mono" value={st.flow} onChange={(e) => setSt({ flow: e.target.value })}><option value="xtls-rprx-vision">xtls-rprx-vision</option><option value="">нет</option></select></label>}
            {st.security === 'tls' && d.protocol !== 'hysteria2' && (
              <span className="fld">alpn
                <span className="flex">{['h2', 'http/1.1'].map((a) => <label key={a} className="cb mono small"><input type="checkbox" checked={st.alpn.includes(a)} onChange={() => setSt({ alpn: st.alpn.includes(a) ? st.alpn.filter((x) => x !== a) : [...st.alpn, a] })} />{a}</label>)}</span>
              </span>
            )}
          </div>
          <span className="flex" style={{ gap: 12 }}><Switch label="ECH" on={d.ech} onChange={(v) => setD({ ...d, ech: v })} /><span className="mono small">ech</span><Info>Encrypted Client Hello — скрывает имя сайта в рукопожатии. Профиль с ECH получают только клиенты с поддержкой.</Info></span>
        </Adv>
        {(d.protocol === 'hysteria2' || esk) && (
          <Adv title={esk ? 'hysteria2 на выходах' : 'hysteria2'} sum={[esk && st.hy2Port ? `port=${st.hy2Port}` : '', `masq=${st.hy2Masquerade ? st.hy2Masquerade.replace(/^https?:\/\//, '').replace(/\/$/, '') : '404'}`, st.hy2Hop.trim() ? `hop=${st.hy2HopInterval}s` : ''].filter(Boolean).join(' ')}>
            <div className="grid g3">
              {esk && <label className="fld"><span>порт hysteria2 (udp) <Info>Пусто или 0 — тот же номер, что у VLESS (TCP и UDP не мешают друг другу).</Info></span><input className="inp mono" inputMode="numeric" value={st.hy2Port || ''} placeholder={d.port || '8443'} onChange={(e) => setSt({ hy2Port: Number(e.target.value.replace(/\D/g, '')) })} /></label>}
              <label className="fld"><span>сайт маскировки <Info>Кто подключится без пароля (например, сканер), увидит этот сайт — сервер проксирует его как обычный HTTP/3-сайт. Пусто — ответ 404.</Info></span>
                <span className="flex" style={{ gap: 8, flexWrap: 'nowrap' }}>
                  <input className="inp mono" style={{ flex: 1 }} list="hy2-masq" value={st.hy2Masquerade} onChange={(e) => setSt({ hy2Masquerade: e.target.value.trim() })} placeholder="https://www.bing.com/" aria-label="Сайт маскировки" />
                  {esk && sniList[0] && <button type="button" className="btn sm" title="Тот же сайт, что у REALITY (SNI)" onClick={() => setSt({ hy2Masquerade: `https://${sniList[0]}/` })}>как sni</button>}
                </span>
                <datalist id="hy2-masq">{[...new Set([...sniList, 'www.bing.com', 'www.apple.com', 'www.cloudflare.com', 'www.samsung.com', 'dl.google.com'])].map((h) => <option key={h} value={`https://${h}/`} />)}</datalist>
              </label>
              {st.hy2Hop.trim() && <label className="fld">менять порт каждые, с<input className="inp mono" inputMode="numeric" value={st.hy2HopInterval} onChange={(e) => setSt({ hy2HopInterval: Number(e.target.value.replace(/\D/g, '')) })} /></label>}
            </div>
            <span className="hint">Буферы UDP на серверах с Hysteria2 увеличиваются до 16 МБ сами — без этого QUIC упирается в них на высоких скоростях.</span>
          </Adv>
        )}
        {(d.protocol === 'hysteria2' || esk) && (
          <Adv title="полоса" sum={`cc=${st.hy2IgnoreClientBw ? 'bbr' : 'brutal'} client=${st.hy2UpMbps || 0}/${st.hy2DownMbps || 0}`}>
            <span className="flex" style={{ gap: 12 }}><Switch label="BBR вместо Brutal" on={st.hy2IgnoreClientBw} onChange={(v) => setSt({ hy2IgnoreClientBw: v, ...(v ? { hy2ServerUpMbps: 0, hy2ServerDownMbps: 0 } : {}) })} /><span className="mono small">bbr вместо brutal</span><Info>Brutal держит заявленную скорость на каналах с потерями; BBR бережнее, но на плече с потерями заметно медленнее. Несовместимо с потолком на клиента.</Info></span>
            <div className="grid g4 mini">
              <label className="fld"><span>клиент: отдача, Мбит/с <Info>{esk ? 'Клиент Hysteria2 у Eskadra — сам вход: полоса включает Brutal на плече вход → выход. Ставьте чуть ниже канала между входом и выходом; 0 — без Brutal.' : 'Вшивается в подписку и ссылку: с полосой клиент включает Brutal. Ставьте чуть ниже реального канала пользователя; 0 — клиент решает сам.'}</Info></span><input className="inp mono" inputMode="numeric" value={st.hy2UpMbps} onChange={(e) => setSt({ hy2UpMbps: Number(e.target.value.replace(/\D/g, '')) })} placeholder="0" /></label>
              <label className="fld">клиент: загрузка, Мбит/с<input className="inp mono" inputMode="numeric" value={st.hy2DownMbps} onChange={(e) => setSt({ hy2DownMbps: Number(e.target.value.replace(/\D/g, '')) })} placeholder="0" /></label>
              {!st.hy2IgnoreClientBw && <>
                <label className="fld"><span>потолок к клиенту <Info>Сервер не даст клиенту больше этой полосы, даже если тот заявит больше. 0 — без потолка.</Info></span><input className="inp mono" inputMode="numeric" value={st.hy2ServerUpMbps} onChange={(e) => setSt({ hy2ServerUpMbps: Number(e.target.value.replace(/\D/g, '')) })} placeholder="0" /></label>
                <label className="fld">потолок от клиента<input className="inp mono" inputMode="numeric" value={st.hy2ServerDownMbps} onChange={(e) => setSt({ hy2ServerDownMbps: Number(e.target.value.replace(/\D/g, '')) })} placeholder="0" /></label>
              </>}
            </div>
            {!st.hy2UpMbps && !st.hy2DownMbps && <span><button type="button" className="btn sm" title="Отдача 50, загрузка 200 Мбит/с" onClick={() => setSt({ hy2UpMbps: 50, hy2DownMbps: 200 })}>типичные 50 / 200</button></span>}
            {!st.hy2UpMbps !== !st.hy2DownMbps && <span className="hint warn">Укажите обе величины — иначе Brutal не включится.</span>}
          </Adv>
        )}
        {d.protocol !== 'hysteria2' && (
          <Adv title="ядро" sum={`sniffing=${st.sniffing ? 'on' : 'off'}`}>
            <span className="flex" style={{ gap: 12 }}><Switch label="Sniffing" on={st.sniffing} onChange={(v) => setSt({ sniffing: v })} /><span className="mono small">sniffing</span></span>
            <span className="hint">Ядро определяет домен назначения по трафику — нужно для маршрутизации по доменам. Обычно включено.</span>
          </Adv>
        )}
      </section>
      </>}

      {step === 3 && <>
      <section className="blk">
        <div className="blk-h">REVIEW <span>что уйдёт на серверы</span></div>
        <dl className="wz-review">
          {review.map(([k, v, i]) => (
            <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd><button type="button" className="btn sm" onClick={() => setStep(i)}>Изменить</button></div>
          ))}
        </dl>
      </section>
      <section className="blk">
        <div className="blk-h">PREFLIGHT <span>проверки перед выкатом</span></div>
        <ul className="pf">
          {preflight.map(([kind, text]) => <li key={text} className={`pf-${kind}`}><span aria-hidden="true">{kind === 'ok' ? '[ok]' : kind === 'warn' ? '[!!]' : '[..]'}</span> {text}</li>)}
        </ul>
      </section>
      </>}

      <div className="wz-nav">
        {step > 0 && <button type="button" className="btn" onClick={() => setStep(step - 1)}>{'< '}<span className="lc">{steps[step - 1]![0]}</span></button>}
        <a className="wz-cancel" href="#/configs">{d.id ? 'к списку' : 'отмена'}</a>
        <span className="wz-miss">{missing[step]}</span>
        {step < 3 && <button type="button" className="btn pri" disabled={!!missing[step]} onClick={() => go(step + 1)}>далее: <span className="lc">{steps[step + 1]![0]}</span>{' >'}</button>}
        {step === 3 && !d.id && <>
          {can('configs.edit') && <button type="button" className="btn" disabled={busy || !d.name} onClick={() => void save()}>сохранить черновик</button>}
          {can('configs.rollout') && can('configs.edit') && <button type="button" className="btn pri" disabled={busy || !d.name || missing.some(Boolean)} onClick={() => void rollout()}>{'сохранить и выкатить >'}</button>}
        </>}
      </div>

      <ErrorBox error={error} />
      {!!d.id && <div className="savebar">
        {/* кнопки по правам роли: сохранить — configs.edit, выкатить — configs.rollout (с изменениями — оба), удалить — configs.delete */}
        {can('configs.rollout') && (can('configs.edit') || (!dirty && d.id)) && <button className="btn pri" disabled={busy || !d.name || (!d.nodeIds.length && !d.entryId) || missing.some(Boolean)} onClick={() => void rollout()}>{dirty || !d.id ? 'Сохранить и выкатить' : 'Выкатить'}</button>}
        {can('configs.edit') && <button className="btn" disabled={busy || !d.name || (!dirty && !!d.id)} onClick={() => void save()}>Сохранить черновик</button>}
        {!can('configs.edit') && !can('configs.rollout') && <span className="k">Только просмотр: у роли нет прав менять и выкатывать конфигурации.</span>}
        <Info>Выкат идёт по одному серверу: проверка конфига на сервере, открытие порта, проверка снаружи. Ошибка — откат и остановка. Черновик сохраняется в панели, серверы его не получают.</Info>
        {dirty && d.id && <><span className="dirty"><span className="dot" />Есть несохранённые изменения</span><button className="btn ghost sm" onClick={() => setD(draft)}>Отменить</button></>}
        <span className="spacer" />
        {d.id && can('configs.delete') && <button className="btn ghost sm" style={{ color: 'var(--fail)' }} disabled={busy} onClick={async () => { if (await ask(`Снять «${d.name}» со всех серверов и удалить? Профили этой конфигурации пропадут из подписок.`)) void run(async () => { await api.del(`/api/v1/templates/${d.id}`); toast(`«${d.name}» удалена`); onDeleted(); }); }}>Удалить</button>}
      </div>}
      {pick && <SniPicker servers={managed} prefer={[...d.nodeIds, ...(d.entryId ? [d.entryId] : [])]} current={d.sni.split(/[\s,]+/).filter(Boolean)}
        onPick={(domain) => { setD({ ...d, sni: domain }); setPick(false); toast(`Сайт маскировки: ${domain}. Сохраните и выкатите конфигурацию`, 'info'); }} onClose={() => setPick(false)} />}
      </div>
    </section>
  );
}

export function JobLog({ id, onDone, title = 'Выкат' }: { id: number; onDone: () => void; title?: string }) {
  const { data } = usePoll(() => api.get<Job>(`/api/v1/jobs/${id}`), 2000, [id]);
  const [notified, setNotified] = useState(false);
  useEffect(() => { if (data && data.status !== 'running' && !notified) { setNotified(true); onDone(); } }, [data, notified, onDone]);
  return (
    <section className="card pad stack">
      <div className="flex" style={{ justifyContent: 'space-between' }}><h2>{title} #{id}</h2>{data && <Tag kind={data.status === 'ok' ? 'ok' : data.status === 'failed' ? 'fail' : 'warn'}>{data.status === 'running' ? 'идёт…' : data.status}</Tag>}</div>
      <pre className="code">{data?.log || 'запуск…'}</pre>
    </section>
  );
}

interface Health { rows: Array<{ exit_id: string; name: string; host: string; exit_ip: string | null; exit_loc: string | null; rtt_ms: number | null; mbps: number | null; ok: number; error: string | null; checked_at: string; fresh?: number }>; selected: string | null; actual: string | null; checkedAt: string | null; slow: string[]; speedAt: string | null; decideAt: string | null; median: Record<string, number | null>; spread?: SpreadState | null }

/** Замер канала сервера на нём самом, Мбит/с. */
interface LinkTest { down: number; up: number; at: string; source?: 'ookla' | 'mirrors'; server?: string; note?: string }
/** Ёмкость по замеру — как на сервере (spread.ts measuredCap): меньшее из направлений, шагом 10. */
const linkCap = (l: LinkTest | undefined) => (l && l.down > 0 && l.up > 0 ? Math.max(10, Math.round(Math.min(l.down, l.up) / 10) * 10) : 0);

/** «по нагрузке»: последняя проверка — загрузка каналов и где каждая группа. */
interface SpreadState { at: string; high: number; exits: Array<{ id: string; cap: number; capFrom?: 'manual' | 'test' | null; load: number; measured: boolean }>; groups: Array<{ g: number; home: string; cur: string; mbps: number; users: number }> }

/** ГБ в сутки на замеры скорости одного выхода. */
const speedTraffic = (mb: number, everyMin: number) => Math.round(((mb || 5) * (1440 / Math.max(1, everyMin || 1))) / 102.4) / 10;

/** Страна по коду ISO на языке интерфейса (FI → «Финляндия»); флаги-эмодзи Windows не рисует. */
const countryOf = (cc: string) => { try { return new Intl.DisplayNames([getLang()], { type: 'region' }).of(cc) ?? cc; } catch { return cc; } };

/** Выходы «Авто через вход»: последние замеры, какой выбран; ручная проверка. */
function ExitHealth({ t }: { t: Template }) {
  const { data, reload } = usePoll(() => api.get<Health>(`/api/v1/templates/${t.id}/health`), 60_000, [t.id]);
  const { busy, error, run } = useAsync();
  const sp = t.spec as { maxRttMs?: number; minMbps?: number; autoMode?: string; orderMinMbps?: number; checkMin?: number; speedEveryMin?: number; decideMin?: number };
  const thr = sp.orderMinMbps ?? 0;
  const order = sp.autoMode === 'order';
  const lead = data?.actual ?? data?.selected ?? null;   // реальный выбор входа; если его ещё не видели — назначенный
  if (sp.autoMode === 'spread') return <SpreadHealth t={t} data={data ?? null} busy={busy} error={error} check={() => void run(async () => { await api.post(`/api/v1/templates/${t.id}/health/check`); await reload(); })} />;
  return (
    <section className="card">
      <div className="card-head">
        <h2>Выходы «Авто» <Info>{order ? <>По порядку: трафик идёт через первый отвечающий выход. Переключает сам вход за ~10 секунд; таблица обновляется раз в минуту.{thr > 0 && <> {`Выход медленнее ${thr} Мбит/с пропускается: скорость меряется каждые ${sp.speedEveryMin ?? 1} мин, решение — раз в ${sp.decideMin ?? 1} мин по медиане замеров; по кнопке «Проверить сейчас» — сразу.`}</>}</> : `Пороги: задержка не больше ${sp.maxRttMs ?? 100} мс, скорость не меньше ${sp.minMbps ?? 10} Мбит/с. Выбранный выход меняется, только когда текущий перестаёт проходить пороги.`}</Info></h2>
        <span className="flex">
          {data?.checkedAt && <span className="k">проверено {ago(data.checkedAt)}</span>}
          {can('configs.rollout') && <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/templates/${t.id}/health/check`); await reload(); })}>{busy ? 'Проверяю…' : 'Проверить сейчас'}</button>}
        </span>
      </div>
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table>
          <thead><tr><th>Выход</th><th>Выходит в интернет <Info>Адрес, с которым сайты видят трафик этого выхода, и страна по базе Cloudflare. Пользователи «напрямую» к этому серверу выходят с того же адреса. Клиент (Тропа, Hiddify и др.) может показывать другую страну — у него своя база GeoIP; сверяйте по адресу.</Info></th><th>Задержка</th>{(!order || thr > 0) && <th>Скорость</th>}<th>Состояние</th></tr></thead>
          <tbody>
            {data?.rows.map((r) => (
              <tr key={r.exit_id}>
                <td><b>{r.name}</b>{lead === r.exit_id && <> <Tag kind="acc" dot>ведёт трафик</Tag></>}{data.selected === r.exit_id && lead !== r.exit_id && <> <Tag kind="warn">назначен, вход ещё не переключился</Tag></>}</td>
                <td>{r.exit_ip ? <span className="mono small">{r.exit_loc && <>{countryOf(r.exit_loc)} · </>}{r.exit_ip}{r.exit_ip !== r.host && <span className="k"> (сервер {r.host})</span>}</span> : <span className="k">—</span>}</td>
                <td className="mono">{r.rtt_ms !== null ? `${r.rtt_ms} мс` : '—'}</td>
                {(!order || thr > 0) && <td className="mono">{r.mbps !== null ? `${r.mbps} Мбит/с` : '—'}{order && data.median?.[r.exit_id] != null && <div className="k">{`медиана ${data.median[r.exit_id]}`}</div>}</td>}
                <td>{order && r.ok && data.slow.includes(r.exit_id) ? <Tag kind="warn">медленнее {thr} Мбит/с — пропускается</Tag> : r.ok ? <Tag kind="ok">{order ? 'отвечает' : 'проходит'}</Tag> : <Tag kind={r.error ? 'fail' : 'warn'}>{r.error === 'выход не отвечает' ? 'неактивен — нет связи' : r.error ?? 'ниже порога'}</Tag>}</td>
              </tr>
            ))}
            {data && !data.rows.length && <tr><td colSpan={5} className="empty">Проверок ещё не было — нажмите «Проверить сейчас» или подождите расписания.</td></tr>}
          </tbody>
        </table>
      </div>
      {order
        ? !!data?.rows.length && !data.rows.some((r) => r.ok) && <div className="k" style={{ padding: '12px 20px' }}>Ни один выход не отвечает — вход держит трафик на первом по порядку.</div>
        : !data?.selected && !!data?.rows.length && <div className="k" style={{ padding: '12px 20px' }}>Выход не закреплён: Xray выбирает по наименьшей задержке.</div>}
      <div style={{ padding: '0 20px' }}><ErrorBox error={error} /></div>
    </section>
  );
}

/** Выходы «Авто по нагрузке»: загрузка каналов, группы пользователей на каждом выходе. */
function SpreadHealth({ t, data, busy, error, check }: { t: Template; data: Health | null; busy: boolean; error: string | null | undefined; check: () => void }) {
  const st = data?.spread ?? null;
  const pct = (load: number, cap: number) => Math.round((load / cap) * 100);
  return (
    <section className="card">
      <div className="card-head">
        <h2>Выходы «Авто» <Info>По нагрузке: у каждой группы пользователей свой выход. Канал загружен выше {st?.high ?? 80}% — самая тяжёлая группа, которая поместится, переводится на выход с запасом (не чаще раза в 3 минуты); нагрузка спала — возвращается домой. Таблица обновляется раз в минуту.</Info></h2>
        <span className="flex">
          {data?.checkedAt && <span className="k">проверено {ago(data.checkedAt)}</span>}
          {can('configs.rollout') && <button className="btn sm" disabled={busy} onClick={check}>{busy ? 'Проверяю…' : 'Проверить сейчас'}</button>}
        </span>
      </div>
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table>
          <thead><tr><th>Выход</th><th>Выходит в интернет</th><th>Задержка</th><th>Канал <Info>Загрузка канала сервера целиком (все конфигурации и прямые пользователи) по счётчикам его сетевых интерфейсов. «по входу» — счётчиков сервера ещё нет, показан только трафик этой конфигурации.</Info></th><th>Группы <Info>Сколько групп «Авто» сейчас идут через выход, сколько в них пользователей и сколько они качают. «чужих» — переведены сюда с перегруженных выходов.</Info></th><th>Состояние</th></tr></thead>
          <tbody>
            {data?.rows.map((r) => {
              const e = st?.exits.find((x) => x.id === r.exit_id);
              const here = st?.groups.filter((g) => g.cur === r.exit_id) ?? [];
              const guests = here.filter((g) => g.home !== r.exit_id).length;
              const over = e && e.cap > 0 && pct(e.load, e.cap) > (st?.high ?? 80);
              return (
                <tr key={r.exit_id}>
                  <td><b>{r.name}</b></td>
                  <td>{r.exit_ip ? <span className="mono small">{r.exit_loc && <>{countryOf(r.exit_loc)} · </>}{r.exit_ip}</span> : <span className="k">—</span>}</td>
                  <td className="mono">{r.rtt_ms !== null ? `${r.rtt_ms} мс` : '—'}</td>
                  <td className="mono">{e ? <>{Math.round(e.load)}{e.cap > 0 ? ` / ${e.cap} Мбит/с` : ' Мбит/с'}{e.cap > 0 && <> {over ? <Tag kind="warn">{pct(e.load, e.cap)}%</Tag> : <span className="k">{pct(e.load, e.cap)}%</span>}</>}<div className="k">{[e.cap > 0 ? (e.capFrom === 'manual' ? 'ёмкость своя' : 'ёмкость по замеру') : 'ёмкость не задана', !e.measured ? 'нагрузка по входу' : ''].filter(Boolean).join(' · ')}</div></> : '—'}</td>
                  <td>{st ? <span className="small">{here.length} · {here.reduce((a, g) => a + g.users, 0)} польз. · {Math.round(here.reduce((a, g) => a + g.mbps, 0))} Мбит/с{guests > 0 && <div className="k">{`из них чужих: ${guests}`}</div>}</span> : '—'}</td>
                  <td>{r.ok ? <Tag kind="ok">отвечает</Tag> : <Tag kind="fail">{r.error === 'выход не отвечает' ? 'неактивен — нет связи' : r.error ?? 'не отвечает'}</Tag>}</td>
                </tr>
              );
            })}
            {data && !data.rows.length && <tr><td colSpan={6} className="empty">Проверок ещё не было — нажмите «Проверить сейчас» или подождите минуту.</td></tr>}
          </tbody>
        </table>
      </div>
      {st && st.groups.some((g) => g.cur !== g.home) && (
        <div className="k" style={{ padding: '12px 20px' }}>{`Переведены группы: ${st.groups.filter((g) => g.cur !== g.home).map((g) => g.g + 1).join(', ')}. Вернутся на свои выходы, когда там освободится место.`}</div>
      )}
      <div style={{ padding: '0 20px' }}><ErrorBox error={error} /></div>
    </section>
  );
}

/** Итоговый конфиг ядра для сервера — для проверки; свёрнут, загружается только при открытии. */
function Preview({ t, servers }: { t: Template; servers: Server[] }) {
  const ids = [...t.node_ids, ...(t.entry_id ? [t.entry_id] : [])];
  const [sid, setSid] = useState(ids[0] ?? '');
  const [open, setOpen] = useState(false);
  const { data } = usePoll(() => (open && sid ? api.get<{ config: string | null }>(`/api/v1/templates/${t.id}/preview?server=${sid}`) : Promise.resolve({ config: null })), null, [sid, t.revision, open]);
  if (!ids.length) return null;
  return (
    <details className="card pad" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="k" style={{ cursor: 'pointer' }}>Итоговый конфиг для сервера <Info>Что получит ядро на выбранном сервере после выката. Секреты скрыты. Нужно только для проверки.</Info></summary>
      <div className="stack" style={{ paddingTop: 12 }}>
        <select className="inp" style={{ width: 'auto' }} value={sid} onChange={(e) => setSid(e.target.value)} aria-label="Сервер">{ids.map((i) => <option key={i} value={i}>{servers.find((s) => s.id === i)?.name ?? i}</option>)}</select>
        {data?.config ? <CopyBlock text={data.config} /> : <p className="k">Конфиг появится после выката (нужны ключи с сервера).</p>}
      </div>
    </details>
  );
}

interface SniResult {
  domain: string; source: 'list' | 'neighbor'; ok: boolean; ip: string | null; tcp_ms: number | null; tls_ms: number | null;
  tls13: boolean; h2: boolean; x25519: boolean; redirect: string | null; error: string | null; neighbor_ip?: string;
}

/** Подбор сайта маскировки REALITY: кандидаты проверяются с выбранного сервера (и соседи сервера по подсети). */
function SniPicker({ servers, prefer, current, onPick, onClose }: { servers: Server[]; prefer: string[]; current: string[]; onPick: (domain: string) => void; onClose: () => void }) {
  const [sid, setSid] = useState(prefer.find((id) => servers.some((s) => s.id === id)) ?? servers[0]?.id ?? '');
  const [near, setNear] = useState(true);
  const [res, setRes] = useState<SniResult[] | null>(null);
  const { busy, error, run } = useAsync();
  const scan = () => run(async () => { setRes(null); setRes((await api.post<{ results: SniResult[] }>(`/api/v1/servers/${sid}/sni-scan`, { neighbors: near })).results); });
  const good = res?.filter((r) => r.ok) ?? [];
  return (
    <Modal size="lg" title="Подбор сайта маскировки" onClose={onClose}>
      <p className="k">Проверка идёт с самого сервера — оттуда, откуда Xray будет обращаться к сайту. Нужны TLS 1.3, X25519 и HTTP/2; лучше без редиректа на другой сайт и с малой задержкой. Соседи по подсети — сайты из того же дата-центра: для наблюдателя такой сервер выглядит естественнее всего.</p>
      <div className="flex" style={{ alignItems: 'flex-end' }}>
        <label className="fld" style={{ flex: '1 1 200px' }}>Сервер
          <select className="inp" value={sid} onChange={(e) => { setSid(e.target.value); setRes(null); }}>{servers.map((s) => <option key={s.id} value={s.id}>{s.name}{prefer.includes(s.id) ? '' : ' · не в конфигурации'}</option>)}</select>
        </label>
        <label className="cb"><input type="checkbox" checked={near} onChange={(e) => setNear(e.target.checked)} />искать соседей по подсети /24</label>
        <button className="btn pri" disabled={busy || !sid} onClick={() => void scan()}>{busy ? 'Проверяю… до 2 минут' : res ? 'Проверить заново' : 'Проверить'}</button>
      </div>
      <ErrorBox error={error} />
      {res && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Сайт</th><th>Задержка</th><th>Проверка</th><th /></tr></thead>
            <tbody>
              {res.map((r) => (
                <tr key={r.domain}>
                  <td><b className="mono small">{r.domain}</b>{r.source === 'neighbor' && <> <Tag kind="acc">сосед{r.neighbor_ip ? ` · ${r.neighbor_ip}` : ''}</Tag></>}{current[0] === r.domain && <> <Tag>сейчас</Tag></>}</td>
                  <td className="mono small">{r.tcp_ms !== null ? `${r.tcp_ms} мс` : '—'}</td>
                  <td>{r.ok
                    ? <span className="flex" style={{ gap: 4 }}><Tag kind="ok">подходит</Tag>{r.redirect && <Tag kind="warn">редирект на {r.redirect}</Tag>}</span>
                    : <Tag kind="fail">{r.error ?? 'не подходит'}</Tag>}</td>
                  <td>{r.ok && <button className="btn sm" onClick={() => onPick(r.domain)}>Использовать</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {res && <span className="k">Подходят {good.length} из {res.length}. «Использовать» заменит сайт маскировки конфигурации — изменение попадёт на серверы после выката.</span>}
      <div className="flex"><button className="btn ghost" onClick={onClose}>Закрыть</button></div>
    </Modal>
  );
}
