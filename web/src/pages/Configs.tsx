import { useEffect, useState } from 'react';
import { api, ago, type Job, type Server, type Template } from '../api';
import { RouteMap, exitView, type MapExit } from '../RouteMap';
import { CopyBlock, ErrorBox, Info, Modal, Seg, Switch, Tag, toast, useAsync, usePoll, ask } from '../ui';
import { getLang } from '../i18n';

const TRANSLIT: Record<string, string> = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya' };
/** Имя конфигурации: строчная латиница, цифры и дефис — регистр и пробелы исправляются сами, кириллица транслитерируется. */
export const slugName = (v: string) => v.toLowerCase().split('').map((c) => TRANSLIT[c] ?? c).join('')
  .replace(/[\s_.]+/g, '-').replace(/[^a-z0-9-]/g, '').replace(/-+/g, '-').replace(/^-/, '').slice(0, 48);

type Protocol = 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'mtproto';
type Security = 'reality' | 'tls' | 'none';
type Transport = 'tcp' | 'ws' | 'grpc' | 'xhttp' | 'httpupgrade';
type CertMode = 'ip' | 'domain' | 'custom' | 'self';

/** Что поддерживает протокол (как в protocols.ts на сервере). */
const PROTO: Record<Protocol, { name: string; hint: string; core: string; sec: Security[]; tr: Transport[]; udp?: boolean; relay: boolean; cert: CertMode[]; port: string }> = {
  vless: { name: 'VLESS', hint: 'основной вариант: REALITY без своего сертификата, или TLS', core: 'Xray', sec: ['reality', 'tls', 'none'], tr: ['tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  vmess: { name: 'VMess', hint: 'для старых клиентов; обычно поверх WebSocket + TLS', core: 'Xray', sec: ['tls', 'none'], tr: ['tcp', 'ws', 'grpc', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  trojan: { name: 'Trojan', hint: 'похож на обычный HTTPS; TLS или REALITY', core: 'Xray', sec: ['tls', 'reality'], tr: ['tcp', 'ws', 'grpc', 'httpupgrade'], relay: true, cert: ['ip', 'domain', 'custom'], port: '8443' },
  shadowsocks: { name: 'Shadowsocks-2022', hint: 'простой и быстрый, без TLS', core: 'Xray', sec: ['none'], tr: ['tcp'], relay: true, cert: [], port: '8388' },
  hysteria2: { name: 'Hysteria2', hint: 'QUIC (UDP), быстрый на плохих сетях', core: 'sing-box', sec: ['tls'], tr: [], udp: true, relay: false, cert: ['self', 'ip', 'domain', 'custom'], port: '8444' },
  mtproto: { name: 'MTProto (Telegram)', hint: 'прокси только для Telegram, маскировка под HTTPS (fake-TLS)', core: 'telemt', sec: ['none'], tr: [], relay: false, cert: [], port: '443' },
};
const STATE_LABEL: Record<string, string> = { active: 'работает', error: 'ошибка', pending: 'выкатывается', deploying: 'выкатывается' };
const SEC_LABEL: Record<Security, string> = { reality: 'REALITY', tls: 'TLS', none: 'без шифрования' };
const TR_LABEL: Record<Transport, string> = { tcp: 'TCP', ws: 'WebSocket', grpc: 'gRPC', xhttp: 'XHTTP', httpupgrade: 'HTTPUpgrade' };
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
  autoMode: AutoMode; exitOrder: string[]; maxRttMs: number; minMbps: number; checkMin: number; testMB: number; orderMinMbps: number; speedEveryMin: number; decideMin: number;
  spreadGroups: number; exitCapMbps: Record<string, number>; spreadHighPct: number; spreadFair: boolean;
}

interface Draft {
  id: string | null; name: string; protocol: Protocol; port: string; sni: string; fingerprint: string;
  ech: boolean; nodeIds: string[]; entryId: string; entryPort: string; st: Settings;
  certPem: string; keyPem: string;
}

const defaults = (p: Protocol): Settings => ({
  security: PROTO[p].sec[0]!, transport: p === 'vmess' ? 'ws' : 'tcp', flow: p === 'vless' ? 'xtls-rprx-vision' : '', path: '/', host: '', serviceName: 'grpc',
  xhttpMode: 'auto', alpn: ['h2', 'http/1.1'], certMode: PROTO[p].cert[0] ?? 'self', domain: '', domains: {}, ssMethod: '2022-blake3-aes-128-gcm',
  hy2Obfs: '', mtDomain: 'www.apple.com', sniffing: true,
  autoMode: 'smart', exitOrder: [], maxRttMs: 100, minMbps: 10, checkMin: 15, testMB: 5, orderMinMbps: 0, speedEveryMin: 1, decideMin: 1,
  spreadGroups: 6, exitCapMbps: {}, spreadHighPct: 80, spreadFair: false,
});

const empty = (p: Protocol = 'vless'): Draft => ({
  id: null, name: '', protocol: p, port: PROTO[p].port, sni: 'www.apple.com', fingerprint: 'chrome', ech: false, nodeIds: [], entryId: '', entryPort: '9443',
  st: defaults(p), certPem: '', keyPem: '',
});

const toDraft = (t: Template): Draft => ({
  id: t.id, name: t.name, protocol: t.spec.protocol, port: String(t.port), sni: t.sni.join(' '), fingerprint: t.fingerprint, ech: t.ech,
  nodeIds: t.node_ids, entryId: t.entry_id ?? '', entryPort: String(t.entry_port ?? 9443),
  st: { ...defaults(t.spec.protocol), ...t.spec } as Settings, certPem: '', keyPem: '',
});

/** Краткое описание шаблона для списка: «VLESS · REALITY · TCP». */
const describe = (t: Template) => {
  const sp = t.spec;
  const parts = [PROTO[sp.protocol]?.name ?? sp.protocol];
  if (PROTO[sp.protocol]?.sec.length > 1 || sp.security === 'tls') parts.push(SEC_LABEL[sp.security]);
  if (PROTO[sp.protocol]?.tr.length > 1) parts.push(TR_LABEL[sp.transport]);
  return parts.join(' · ');
};

export function ConfigsPage() {
  const { data: templates, reload } = usePoll(() => api.get<Template[]>('/api/v1/templates'), 20_000);
  const { data: servers, reload: reloadServers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [jobId, setJobId] = useState<number | null>(null);

  useEffect(() => {
    if (!draft && templates?.length) setDraft(toDraft(templates[0]!));
  }, [templates, draft]);

  const current = templates?.find((t) => t.id === draft?.id) ?? null;
  return (
    <>
      <div className="page-head">
        <div><h1>Конфигурации</h1><p>Протоколы и порты, по которым подключаются пользователи</p></div>
        <button className="btn pri" onClick={() => { setDraft(empty()); setJobId(null); }}>Новая конфигурация</button>
      </div>
      {/* лента конфигураций: растёт вбок и переносится, редактор под ней — во всю ширину */}
      <section className="card tpl-list" aria-label="Конфигурации">
        {templates?.map((t) => (
          <button key={t.id} className={`tpl ${draft?.id === t.id ? 'on' : ''}`} onClick={() => { setDraft(toDraft(t)); setJobId(null); }}>
            <span className="flex" style={{ justifyContent: 'space-between', width: '100%' }}><b className="small">{t.name}</b><Tag>{t.core}</Tag></span>
            <span className="k mono">{describe(t)} · :{t.port}{t.entry_id ? ` · вход :${t.entry_port}` : ''}</span>
            <span className="flex" style={{ gap: 6 }}><span className="k">серверов: {t.inbounds.filter((i) => i.state === 'active').length}</span>{t.applied_revision < t.revision && <Tag kind="warn">не выкачена</Tag>}</span>
          </button>
        ))}
        {!templates?.length && <p className="k" style={{ padding: 8 }}>Конфигураций пока нет.</p>}
      </section>
      <div className="stack" style={{ gap: 20 }}>
        {draft && servers && <Editor key={draft.id ?? 'new'} draft={draft} servers={servers} current={current} onServers={() => void reloadServers()}
          onSaved={(t) => { void reload(); setDraft(toDraft(t)); }} onRollout={(id) => setJobId(id)} onDeleted={() => { setDraft(null); void reload(); }} />}
        {jobId && <JobLog id={jobId} onDone={() => void reload()} />}
        {current?.entry_id && current.spec.autoMode !== 'random' && <ExitHealth t={current} />}
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
  const { busy, error, run } = useAsync();
  if (!data) return null;
  const rels = (data.releases[core] ?? []).filter((r) => pre || !r.prerelease);
  const ver = (c: { version: string; previous?: string } | null, k: string, s: CoresInfo['servers'][number]) => {
    if (!c) return (
      <span className="stack" style={{ gap: 4 }}>
        <span className="k">не установлено</span>
        <span><button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/update`, { version: data.pins[k] ?? 'latest' }); void reload(); })}>Установить</button></span>
      </span>
    );
    const old = s.outdated.includes(k);
    return (
      <span className="stack" style={{ gap: 4 }}>
        <span className="flex" style={{ gap: 6 }}><span className="mono small">{c.version}</span>{old && <Tag kind="warn">устарел</Tag>}</span>
        <span className="flex" style={{ gap: 6 }}>
          {old && <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/update`, { version: data.pins[k] ?? 'latest' }); void reload(); })}>Обновить</button>}
          {c.previous && <button className="btn ghost sm" disabled={busy} onClick={async () => { if (await ask(`Вернуть ${k} ${c.previous} на ${s.name}?`)) void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/rollback`); void reload(); }); }}>Откат на {c.previous}</button>}
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
          <thead><tr><th>Узел</th><th>Режим</th><th>Xray</th><th>sing-box</th></tr></thead>
          <tbody>
            {data.servers.map((s) => (
              <tr key={s.id}>
                <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a></td>
                <td>{s.mode === 'xui' ? <Tag kind="info">через 3x-ui</Tag> : <Tag>своё ядро</Tag>}</td>
                <td>{s.mode === 'xui' ? <span className="stack" style={{ gap: 2 }}><span className="mono small">{s.xui?.version ?? '?'}</span><span className="k">3x-ui {s.xui?.panel ?? ''}</span></span> : ver(s.xray, 'xray', s)}</td>
                <td>{ver(s.singbox, 'sing-box', s)}</td>
              </tr>
            ))}
            {!data.servers.length && <tr><td colSpan={4} className="k">Узлов с nodekit нет.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="row stack" style={{ alignItems: 'stretch' }}>
        <h3>По всему флоту</h3>
        <div className="flex">
          <Seg value={core} label="Ядро" onChange={(c) => { setCore(c); setVersion('latest'); }} options={[['xray', 'Xray'], ['sing-box', 'sing-box']]} />
          <select className="inp" style={{ width: 'auto' }} value={version} onChange={(e) => setVersion(e.target.value)} aria-label="Версия">
            <option value="latest">последняя стабильная ({data.latest[core] ?? '?'})</option>
            {rels.map((r) => <option key={r.version} value={r.version}>{r.version}{r.prerelease ? ' · предрелиз' : ''} · {r.published.slice(0, 10)}</option>)}
          </select>
          <label className="cb small"><input type="checkbox" checked={pre} onChange={(e) => setPre(e.target.checked)} />показывать предрелизы</label>
        </div>
        <div className="flex">
          <button className="btn pri" disabled={busy} onClick={async () => { if (await ask(`Установить или обновить ${core} (${version}) на всех узлах? По одному узлу, первая ошибка останавливает.`)) void run(async () => { const r = await api.post<{ jobId: number }>(`/api/v1/cores/${core}/rollout`, { version }); setJobId(r.jobId); }); }}>Установить или обновить на всех узлах</button>
          <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/cores/pin', { core, version }); void reload(); })}>Закрепить для новых узлов</button>
          <span className="k">Сейчас новые узлы получают: {core} {data.pins[core] ?? 'latest'}</span>
        </div>
        <ErrorBox error={error} />
      </div>
      {jobId && <div style={{ padding: '0 20px 16px' }}><JobLog id={jobId} onDone={() => void reload()} /></div>}
    </section>
  );
}

function Editor({ draft, servers, current, onServers, onSaved, onRollout, onDeleted }: {
  draft: Draft; servers: Server[]; current: Template | null; onServers: () => void; onSaved: (t: Template) => void; onRollout: (jobId: number) => void; onDeleted: () => void;
}) {
  const [d, setD] = useState(draft);
  useEffect(() => setD(draft), [draft]);   // после сохранения — то, что вернул сервер
  const { busy, error, run } = useAsync();
  const managed = servers.filter((s) => s.sudo_mode === 'restricted');
  const info = PROTO[d.protocol];
  const st = d.st;
  const setSt = (patch: Partial<Settings>) => setD({ ...d, st: { ...st, ...patch } });
  const tls = st.security === 'tls' || d.protocol === 'hysteria2';
  const usedIds = [...d.nodeIds, ...(d.entryId ? [d.entryId] : [])];
  // выходы «Авто»: серверы конфигурации кроме входа — в заданном порядке (новые — в конце)
  const rank = (id: string) => (st.exitOrder.includes(id) ? st.exitOrder.indexOf(id) : st.exitOrder.length);
  const exits = managed.filter((s) => d.nodeIds.includes(s.id) && s.id !== d.entryId).sort((a, b) => rank(a.id) - rank(b.id));
  const { data: health } = usePoll(() => (current?.entry_id ? api.get<Health>(`/api/v1/templates/${current.id}/health`) : Promise.resolve(null)), 60_000, [current?.id]);
  // замеры каналов серверов (на самих серверах) — ёмкость выходов «по нагрузке», если своё значение не задано
  const { data: links, reload: reloadLinks } = usePoll(() => api.get<Record<string, LinkTest>>('/api/v1/links'), null);
  const [measuring, setMeasuring] = useState<string | null>(null);
  const measure = async (ids: string[]) => {
    const names = ids.map((id) => servers.find((s) => s.id === id)?.name ?? id).join(', ');
    if (!(await ask(`Замерить канал: ${names}? На каждом сервере ~25 секунд канал будет занят целиком (пользователям этого сервера медленнее), трафик — до ${ids.length > 1 ? 'пары ГБ на сервер' : 'пары ГБ'} на гигабитном канале.`))) return;
    for (const id of ids) {
      setMeasuring(id);
      try {
        const r = await api.post<LinkTest>(`/api/v1/servers/${id}/link-test`);
        toast(`${servers.find((s) => s.id === id)?.name}: ↓${r.down} ↑${r.up} Мбит/с`);
      } catch (e) { toast((e as Error).message, 'fail'); }
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
    name: d.name, protocol: d.protocol, port: Number(d.port), sni: d.sni.split(/[\s,]+/).filter(Boolean), fingerprint: d.fingerprint, ech: d.ech,
    // серверы, которых уже нет в панели (удалены), не отправляем — иначе конфигурацию не сохранить
    nodeIds: d.nodeIds.filter((id) => servers.some((s) => s.id === id)), entryId: d.entryId && servers.some((s) => s.id === d.entryId) ? d.entryId : null, entryPort: d.entryId ? Number(d.entryPort) : null,
    settings: {
      security: st.security, transport: st.transport, flow: st.transport === 'tcp' && st.security !== 'none' && d.protocol === 'vless' ? st.flow : '',
      path: st.path, host: st.host, serviceName: st.serviceName, xhttpMode: st.xhttpMode, alpn: st.alpn, certMode: st.certMode,
      domain: st.domain, domains: Object.fromEntries(Object.entries(st.domains).filter(([k, v]) => usedIds.includes(k) && v)),
      ssMethod: st.ssMethod, hy2Obfs: st.hy2Obfs, mtDomain: st.mtDomain, sniffing: st.sniffing,
      autoMode: st.autoMode, exitOrder: exits.map((s) => s.id), maxRttMs: Number(st.maxRttMs) || 100, minMbps: Number(st.minMbps) || 10, checkMin: Number(st.checkMin) || 15, testMB: Number(st.testMB) || 5, orderMinMbps: Number(st.orderMinMbps) || 0, speedEveryMin: Number(st.speedEveryMin) || 1, decideMin: Number(st.decideMin) || 1,
      spreadGroups: Math.min(16, Math.max(2, Number(st.spreadGroups) || 6)), spreadHighPct: Math.min(95, Math.max(30, Number(st.spreadHighPct) || 80)), spreadFair: st.spreadFair,
      exitCapMbps: Object.fromEntries(exits.map((s) => [s.id, Number(st.exitCapMbps[s.id]) || 0])),
    },
    ...(d.certPem.trim() && d.keyPem.trim() ? { customCert: { fullchain: d.certPem.trim() + '\n', privkey: d.keyPem.trim() + '\n' } } : {}),
  });
  const saveT = async () => {
    const t = d.id ? await api.put<Template>(`/api/v1/templates/${d.id}`, body()) : await api.post<Template>('/api/v1/templates', body());
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
  const toggleNode = (id: string) => setD({ ...d, nodeIds: d.nodeIds.includes(id) ? d.nodeIds.filter((x) => x !== id) : [...d.nodeIds, id] });
  const stateOf = (sid: string, kind: string) => current?.inbounds.find((i) => i.server_id === sid && i.kind === kind);
  const relayState = d.entryId ? stateOf(d.entryId, 'relay') : undefined;
  // схема: выбранные серверы (в порядке «Авто»), затем остальные — их можно включить кликом
  const lead = health?.actual ?? health?.selected ?? (st.autoMode !== 'random' ? health?.rows.find((r) => r.ok)?.exit_id : undefined);
  const mapExits: MapExit[] = [
    ...exits.map((x): MapExit => {
      const ib = stateOf(x.id, 'direct');
      const h = health?.rows.find((r) => r.exit_id === x.id);
      if (ib?.state === 'error') return { id: x.id, name: x.name, state: 'fail', note: 'ошибка выката' };
      if (!ib || ib.state !== 'active') return { id: x.id, name: x.name, state: 'idle', note: ib ? 'выкатывается' : 'после выката' };
      if (!d.entryId || x.fail_since) return { id: x.id, name: x.name, state: x.fail_since ? 'fail' : 'ok', note: x.fail_since ? 'нет связи' : 'работает' };
      return { id: x.id, name: x.name, ...exitView(h, { lead: lead === x.id, mode: st.autoMode }) };
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

  return (
    <section className="card pad stack" style={{ gap: 18 }}>
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>{d.id ? d.name : 'Новая конфигурация'}</h2>
        {current && (pending ? <Tag kind="warn">черновик не выкачен</Tag> : current.applied_revision ? <Tag kind="ok" dot>выкачена</Tag> : <Tag>ещё не выкатывалась</Tag>)}
      </div>

      <div className="grid g3">
        <label className="fld"><span>Протокол <Info>{Object.values(PROTO).map((x) => <span key={x.name}><b>{x.name}</b> — {x.hint} ({x.core}).<br /></span>)}Протокол существующей конфигурации не меняется — создайте новую.</Info></span>
          <select className="inp" value={d.protocol} disabled={!!d.id} onChange={(e) => pickProtocol(e.target.value as Protocol)}>
            {(Object.keys(PROTO) as Protocol[]).map((p) => <option key={p} value={p}>{PROTO[p].name}</option>)}
          </select>
        </label>
        <label className="fld"><span>Имя <Info>Строчная латиница, цифры и дефис — заглавные, пробелы и кириллица исправляются сами. Имя можно поменять в любой момент.</Info></span><input className="inp mono" value={d.name} onChange={(e) => setD({ ...d, name: slugName(e.target.value) })} placeholder={`${d.protocol}-${st.security === 'none' ? 'plain' : st.security}`} /></label>
        <label className="fld"><span>Порт ({info.udp ? 'UDP' : 'TCP'}) <Info>Откроется на серверах сам после проверки: не SSH, не занят, в диапазоне группы.{d.protocol === 'mtproto' ? ' Для MTProto лучше 443 — так соединение больше похоже на обычный HTTPS.' : ''}</Info></span>
          <input className="inp mono" value={d.port} onChange={(e) => setD({ ...d, port: e.target.value })} inputMode="numeric" />
        </label>
      </div>

      {/* защита: REALITY / TLS / нет */}
      {info.sec.length > 1 && (
        <div className="stack" style={{ gap: 8 }}>
          <span className="k">Защита <Info>REALITY — маскировка под чужой сайт, свой сертификат не нужен. TLS — свой сертификат (Let's Encrypt на IP сервера, домен или загруженный). Без шифрования — только для особых случаев (например, за CDN).</Info></span>
          <Seg value={st.security} label="Защита" onChange={(v) => setSt({ security: v, flow: v === 'none' ? '' : st.flow, transport: v === 'reality' && !['tcp', 'grpc', 'xhttp'].includes(st.transport) ? 'tcp' : st.transport })}
            options={info.sec.map((x) => [x, SEC_LABEL[x]] as [Security, string])} />
        </div>
      )}
      {st.security === 'reality' && info.sec.includes('reality') && (
        <div className="fld"><span>Сайт маскировки (SNI) <Info>Чужой сайт с TLS 1.3, под который маскируется сервер: www.apple.com, dl.google.com, www.cloudflare.com, www.samsung.com. Можно несколько через пробел — все имена должны обслуживаться первым сайтом. www.microsoft.com с REALITY не работает. «Подобрать» проверит кандидатов с самого сервера.</Info></span>
          <span className="flex">
            <input className="inp mono" style={{ flex: 1 }} value={d.sni} onChange={(e) => setD({ ...d, sni: e.target.value })} placeholder="www.apple.com" aria-label="Сайт маскировки (SNI)" />
            <button type="button" className="btn" disabled={!managed.length} onClick={() => setPick(true)}>Подобрать…</button>
          </span>
        </div>
      )}
      {tls && info.cert.length > 0 && (
        <div className="stack" style={{ gap: 8 }}>
          <label className="fld"><span>Сертификат <Info>Let's Encrypt на IP выпускается на каждом сервере сам и продлевается автоматически (порт 80 на время выпуска). Для домена — A-запись домена должна указывать на сервер. Загруженный сертификат (например, wildcard) раздаётся на все серверы конфигурации.</Info></span>
            <select className="inp" value={st.certMode} onChange={(e) => setSt({ certMode: e.target.value as CertMode })}>
              {info.cert.map((m) => <option key={m} value={m}>{CERT_LABEL[m]}</option>)}
            </select>
          </label>
          {st.certMode === 'domain' && (
            <div className="grid g2">
              {usedIds.length ? usedIds.map((id) => (
                <label key={id} className="fld">Домен для {servers.find((x) => x.id === id)?.name ?? id}
                  <input className="inp mono" value={st.domains[id] ?? ''} onChange={(e) => setSt({ domains: { ...st.domains, [id]: e.target.value.trim() } })} placeholder="de.example.com" />
                </label>
              )) : <span className="k">Сначала выберите серверы ниже.</span>}
            </div>
          )}
          {st.certMode === 'custom' && (
            <div className="stack" style={{ gap: 8 }}>
              <label className="fld">Домен в сертификате (клиенты проверяют его)<input className="inp mono" value={st.domain} onChange={(e) => setSt({ domain: e.target.value.trim() })} placeholder="vpn.example.com" /></label>
              {current?.hasCustomCert && !d.certPem && <span className="k">Сертификат загружен. Чтобы заменить — вставьте новый.</span>}
              <div className="grid g2">
                <label className="fld">Сертификат (fullchain.pem)<textarea className="inp mono" rows={4} value={d.certPem} onChange={(e) => setD({ ...d, certPem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} /></label>
                <label className="fld">Ключ (privkey.pem)<textarea className="inp mono" rows={4} value={d.keyPem} onChange={(e) => setD({ ...d, keyPem: e.target.value })} placeholder="-----BEGIN PRIVATE KEY-----" spellCheck={false} /></label>
              </div>
            </div>
          )}
          {st.certMode === 'self' && (
            <label className="fld">Имя в сертификате (SNI)<input className="inp mono" value={d.sni} onChange={(e) => setD({ ...d, sni: e.target.value })} placeholder="hy.example" /></label>
          )}
        </div>
      )}
      {d.protocol === 'shadowsocks' && (
        <label className="fld">Шифрование<select className="inp" value={st.ssMethod} onChange={(e) => setSt({ ssMethod: e.target.value })}>
          {['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].map((m) => <option key={m}>{m}</option>)}
        </select></label>
      )}
      {d.protocol === 'mtproto' && (
        <label className="fld"><span>Домен маскировки <Info>Сайт, под HTTPS которого маскируется прокси (fake-TLS). Неопознанные подключения перенаправляются на него. На одном сервере может быть одна конфигурация MTProto.</Info></span>
          <input className="inp mono" value={st.mtDomain} onChange={(e) => setSt({ mtDomain: e.target.value.trim() })} placeholder="www.apple.com" />
        </label>
      )}

      <div className="stack" style={{ gap: 12 }}>
        <h3>Связи <Info>Слева — откуда приходят пользователи: напрямую или через сервер-вход. Справа — серверы этой конфигурации: отметьте нужные. Со входом в подписке появятся профили «вход → сервер» для каждого выхода и «вход → авто».</Info></h3>
        {!managed.length ? <span className="k">Нет подключённых серверов — добавьте их в разделе «Серверы».</span> : (
          <RouteMap
            entry={
              <>
                <span className="k">{d.entryId ? 'Relay (вход)' : 'Пользователи'}</span>
                {info.relay ? (
                  <select className="inp" value={d.entryId} onChange={(e) => setD({ ...d, entryId: e.target.value })} aria-label="Сервер-вход">
                    <option value="">напрямую</option>
                    {managed.map((s) => <option key={s.id} value={s.id}>через {s.name}</option>)}
                  </select>
                ) : <span className="small">напрямую <Info>{info.name} не пересылается через вход.</Info></span>}
                {d.entryId && (
                  <>
                    <label className="flex small" style={{ gap: 8 }}>порт<input className="inp mono" style={{ width: 90, minHeight: 34 }} inputMode="numeric" value={d.entryPort} onChange={(e) => setD({ ...d, entryPort: e.target.value })} aria-label="Порт входа" />{relayState && <Tag kind={relayState.state === 'active' ? 'ok' : relayState.state === 'error' ? 'fail' : 'warn'}>{STATE_LABEL[relayState.state] ?? relayState.state}</Tag>}</label>
                    <label className="cb small" style={{ minHeight: 28 }}><input type="checkbox" checked={d.nodeIds.includes(d.entryId)} onChange={() => toggleNode(d.entryId)} />и сам принимает напрямую</label>
                  </>
                )}
              </>
            }
            entryOff={!d.entryId}
            exits={mapExits}
            ordered={!!d.entryId && (st.autoMode === 'order' || st.autoMode === 'spread')}
            onToggle={toggleNode}
            onMove={(id, dir) => move(exits.findIndex((x) => x.id === id), dir)}
          />
        )}
        {current?.inbounds.filter((i) => i.error).map((i) => <div key={i.id} className="alert warn small">{servers.find((s) => s.id === i.server_id)?.name}: {i.error}</div>)}
        {d.entryId && info.relay && (
          <div className="stack" style={{ gap: 8 }}>
            <span className="k">Профиль «вход → авто» выбирает выход <Info>Задержку вход проверяет сам раз в минуту, скорость скачивания панель меряет по расписанию. Переключение — без разрыва соединений; о каждом переключении бот пишет админам.</Info></span>
            <Seg value={st.autoMode} label="Выбор выхода" onChange={(v) => setSt({ autoMode: v })} options={[['smart', 'по качеству'], ['order', 'по порядку'], ['spread', 'по нагрузке'], ['random', 'случайно']]} />
            <span className="small muted" style={{ maxWidth: '68ch' }}>{AUTO_HINT[st.autoMode]}{st.autoMode === 'order' ? ' Порядок — стрелками на схеме.' : st.autoMode === 'spread' ? ' Порядок запасных выходов — стрелками на схеме.' : ''}</span>
            {st.autoMode === 'smart' && (
              <div className="grid g4">
                <label className="fld">Задержка не больше, мс<input className="inp mono" inputMode="numeric" value={st.maxRttMs} onChange={(e) => setSt({ maxRttMs: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                <label className="fld">Скорость не меньше, Мбит/с<input className="inp mono" inputMode="decimal" value={st.minMbps} onChange={(e) => setSt({ minMbps: Number(e.target.value.replace(/[^\d.]/g, '')) })} /></label>
                <label className="fld">Проверять каждые, мин<input className="inp mono" inputMode="numeric" value={st.checkMin} onChange={(e) => setSt({ checkMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                <label className="fld"><span>Объём теста, МБ <Info>Сколько скачивать через каждый выход при проверке скорости. 5 МБ раз в 15 минут — около 0,5 ГБ трафика в сутки на выход.</Info></span><input className="inp mono" inputMode="numeric" value={st.testMB} onChange={(e) => setSt({ testMB: Number(e.target.value.replace(/\D/g, '')) })} /></label>
              </div>
            )}
            {st.autoMode === 'spread' && (
              <div className="stack" style={{ gap: 10 }}>
                <div className="flex" style={{ justifyContent: 'space-between' }}>
                  <span className="k">Каналы выходов <Info>Замер идёт на самом сервере: 8 потоков к Cloudflare по 10 секунд на скачивание и на отдачу; ёмкость — меньшее из двух. На время замера (~25 с) канал занят целиком — пользователям этого сервера будет медленнее. Своё значение в поле важнее замера; пусто — по замеру; ни того, ни другого — загрузка выхода не контролируется, группы делятся поровну. Новая ёмкость меняет раскладку групп при следующем выкате.</Info></span>
                  <button type="button" className="btn sm" disabled={!!measuring || !exits.length} onClick={() => void measure(exits.map((x) => x.id))}>{measuring ? `Замеряю ${servers.find((s) => s.id === measuring)?.name ?? ''}…` : 'Замерить все'}</button>
                </div>
                <div className="grid g4">
                  {exits.map((x) => {
                    const l = links?.[x.id];
                    const cap = linkCap(l);
                    return (
                      <div key={x.id} className="fld">
                        <label className="stack" style={{ gap: 4 }}><span>Канал {x.name}, Мбит/с</span>
                          <input className="inp mono" inputMode="numeric" value={st.exitCapMbps[x.id] || ''} placeholder={cap ? `${cap} — по замеру` : 'не замерен'} aria-label={`Канал ${x.name}, Мбит/с`}
                            onChange={(e) => setSt({ exitCapMbps: { ...st.exitCapMbps, [x.id]: Number(e.target.value.replace(/\D/g, '')) } })} /></label>
                        <span className="k flex" style={{ gap: 6, flexWrap: 'wrap' }}>
                          {l ? <span className="mono">{`↓${l.down} ↑${l.up} · ${ago(l.at)}`}</span> : <span>замера нет</span>}
                          <button type="button" className="btn ghost sm" disabled={!!measuring} onClick={() => void measure([x.id])}>{measuring === x.id ? 'замеряю…' : 'Замерить'}</button>
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="grid g4">
                  <label className="fld"><span>Переводить при загрузке выше, % <Info>Канал выхода загружен сильнее — самая тяжёлая группа, которая поместится, переводится на выход с запасом. Домой группа возвращается, когда дома с ней будет на 20% ниже порога. Между переводами — не меньше 3 минут: нагрузка перетекает с новыми соединениями.</Info></span>
                    <input className="inp mono" inputMode="numeric" value={st.spreadHighPct} onChange={(e) => setSt({ spreadHighPct: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  <label className="fld"><span>Групп пользователей <Info>Больше групп — точнее делится нагрузка, но чаще меняется выход у части пользователей. Для 10–50 пользователей и 2–4 выходов хватает 6. Смена числа групп или ёмкостей заново раскладывает пользователей по выходам.</Info></span>
                    <input className="inp mono" inputMode="numeric" value={st.spreadGroups} onChange={(e) => setSt({ spreadGroups: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                </div>
                <div className="flex" style={{ justifyContent: 'space-between', maxWidth: '68ch' }}>
                  <span className="small">Делить канал выхода поровну между соединениями <Info>Пока группы переезжают, перегруженный канал делится честно: у каждого соединения своя доля, видео у остальных идёт в меньшем качестве, а не встаёт. На выходах с заданной ёмкостью ставится очередь cake на 95% канала и BBR; переживает перезагрузку. Ёмкость указывайте реальную: заниженная — урежет скорость. Выключить — снять галочку и выкатить.</Info></span>
                  <Switch label="Делить канал поровну" on={st.spreadFair} onChange={(v) => setSt({ spreadFair: v })} />
                </div>
              </div>
            )}
            {st.autoMode === 'order' && (
              <div className="grid g4">
                <label className="fld"><span>Скорость не меньше, Мбит/с <Info>0 — не мерить: только доступность. Иначе выход медленнее порога пропускается — трафик идёт на следующий по порядку; тот тоже медленный — на следующий за ним. Медленный снова считается быстрым от порога +10% — без дёрганья на границе. Медленные все — обычный порядок по доступности.</Info></span>
                  <input className="inp mono" inputMode="decimal" value={st.orderMinMbps} onChange={(e) => setSt({ orderMinMbps: Number(e.target.value.replace(/[^\d.]/g, '')) })} placeholder="0" /></label>
                {st.orderMinMbps > 0 && <>
                  <label className="fld">Мерить скорость каждые, мин<input className="inp mono" inputMode="numeric" value={st.speedEveryMin} onChange={(e) => setSt({ speedEveryMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  <label className="fld"><span>Решать о переключении каждые, мин <Info>Выход пропускается или возвращается по медиане замеров за это время. 1 минута — по последнему замеру, реакция быстрее всего; больше — одна неудачная минута трафик не перекидывает. Само переключение делает Xray на входе за секунды.</Info></span><input className="inp mono" inputMode="numeric" value={st.decideMin} onChange={(e) => setSt({ decideMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  <label className="fld"><span>Объём теста, МБ <Info>Сколько скачивать через каждый выход при замере. Меньше объём — меньше трафика, но замер грубее на быстрых каналах.</Info></span><input className="inp mono" inputMode="numeric" value={st.testMB} onChange={(e) => setSt({ testMB: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                  <span className="k" style={{ gridColumn: '1 / -1' }}>{`Трафик на замеры: около ${speedTraffic(st.testMB, st.speedEveryMin)} ГБ в сутки на каждый выход.`}</span>
                </>}
              </div>
            )}
          </div>
        )}
      </div>

      {(info.tr.length > 0 || d.protocol === 'hysteria2') && (
        <details className="stack">
          <summary className="k" style={{ cursor: 'pointer' }}>Дополнительно</summary>
          <div className="stack" style={{ gap: 14, paddingTop: 12 }}>
            {info.tr.length > 1 && (
              <div className="stack" style={{ gap: 8 }}>
                <span className="k">Транспорт <Info>TCP — по умолчанию и быстрее всего. WebSocket, gRPC, HTTPUpgrade — если сервер за CDN или прокси. XHTTP — новый транспорт Xray (только VLESS, в sing-box-подписке не поддерживается).</Info></span>
                <Seg value={st.transport} label="Транспорт" onChange={(v) => setSt({ transport: v })}
                  options={info.tr.filter((x) => st.security !== 'reality' || ['tcp', 'grpc', 'xhttp'].includes(x)).map((x) => [x, TR_LABEL[x]] as [Transport, string])} />
              </div>
            )}
            {['ws', 'httpupgrade', 'xhttp'].includes(st.transport) && (
              <div className="grid g3">
                <label className="fld">Путь<input className="inp mono" value={st.path} onChange={(e) => setSt({ path: e.target.value })} placeholder="/" /></label>
                <label className="fld">Host (необязательно)<input className="inp mono" value={st.host} onChange={(e) => setSt({ host: e.target.value.trim() })} /></label>
                {st.transport === 'xhttp' && <label className="fld">Режим XHTTP<select className="inp" value={st.xhttpMode} onChange={(e) => setSt({ xhttpMode: e.target.value })}>{['auto', 'packet-up', 'stream-up', 'stream-one'].map((m) => <option key={m}>{m}</option>)}</select></label>}
              </div>
            )}
            {st.transport === 'grpc' && <label className="fld">Имя сервиса gRPC<input className="inp mono" value={st.serviceName} onChange={(e) => setSt({ serviceName: e.target.value.trim() })} /></label>}
            <div className="grid g3">
              {d.protocol === 'vless' && st.transport === 'tcp' && st.security !== 'none' && (
                <label className="fld">Flow<select className="inp" value={st.flow} onChange={(e) => setSt({ flow: e.target.value })}><option value="xtls-rprx-vision">xtls-rprx-vision</option><option value="">нет</option></select></label>
              )}
              {st.security !== 'none' && d.protocol !== 'hysteria2' && (
                <label className="fld">Отпечаток клиента (uTLS)<select className="inp" value={d.fingerprint} onChange={(e) => setD({ ...d, fingerprint: e.target.value })}>{['chrome', 'firefox', 'safari', 'edge', 'random'].map((f) => <option key={f}>{f}</option>)}</select></label>
              )}
              {st.security === 'tls' && d.protocol !== 'hysteria2' && (
                <span className="fld">ALPN
                  <span className="flex">{['h2', 'http/1.1'].map((a) => <label key={a} className="cb small"><input type="checkbox" checked={st.alpn.includes(a)} onChange={() => setSt({ alpn: st.alpn.includes(a) ? st.alpn.filter((x) => x !== a) : [...st.alpn, a] })} />{a}</label>)}</span>
                </span>
              )}
              {d.protocol === 'hysteria2' && <label className="fld"><span>Пароль obfs (salamander) <Info>Дополнительно маскирует QUIC. Пусто — без obfs. Клиенты должны поддерживать obfs.</Info></span><input className="inp mono" value={st.hy2Obfs} onChange={(e) => setSt({ hy2Obfs: e.target.value })} /></label>}
            </div>
            {d.protocol !== 'hysteria2' && (
              <div className="flex" style={{ justifyContent: 'space-between' }}>
                <span className="small">Sniffing <Info>Ядро определяет домен назначения по трафику — нужно для маршрутизации по доменам. Обычно включено.</Info></span>
                <Switch label="Sniffing" on={st.sniffing} onChange={(v) => setSt({ sniffing: v })} />
              </div>
            )}
            <div className="flex" style={{ justifyContent: 'space-between' }}>
              <span className="small">ECH <Info>Encrypted Client Hello — скрывает имя сайта в рукопожатии. Опционально; профиль с ECH получают только клиенты с поддержкой.</Info></span>
              <Switch label="ECH" on={d.ech} onChange={(v) => setD({ ...d, ech: v })} />
            </div>
          </div>
        </details>
      )}

      <ErrorBox error={error} />
      <div className="savebar">
        <button className="btn pri" disabled={busy || !d.name || (!d.nodeIds.length && !d.entryId)} onClick={() => void rollout()}>{dirty || !d.id ? 'Сохранить и выкатить' : 'Выкатить'}</button>
        <button className="btn" disabled={busy || !d.name || (!dirty && !!d.id)} onClick={() => void save()}>Сохранить черновик</button>
        <Info>Выкат идёт по одному серверу: проверка конфига на сервере, открытие порта, проверка снаружи. Ошибка — откат и остановка. Черновик сохраняется в панели, серверы его не получают.</Info>
        {dirty && d.id && <><span className="dirty"><span className="dot" />Есть несохранённые изменения</span><button className="btn ghost sm" onClick={() => setD(draft)}>Отменить</button></>}
        <span className="spacer" />
        {d.id && <button className="btn ghost sm" style={{ color: 'var(--fail)' }} disabled={busy} onClick={async () => { if (await ask(`Снять «${d.name}» со всех серверов и удалить? Профили этой конфигурации пропадут из подписок.`)) void run(async () => { await api.del(`/api/v1/templates/${d.id}`); toast(`«${d.name}» удалена`); onDeleted(); }); }}>Удалить</button>}
      </div>
      {pick && <SniPicker servers={managed} prefer={[...d.nodeIds, ...(d.entryId ? [d.entryId] : [])]} current={d.sni.split(/[\s,]+/).filter(Boolean)}
        onPick={(domain) => { setD({ ...d, sni: domain }); setPick(false); toast(`Сайт маскировки: ${domain}. Сохраните и выкатите конфигурацию`, 'info'); }} onClose={() => setPick(false)} />}
    </section>
  );
}

function JobLog({ id, onDone }: { id: number; onDone: () => void }) {
  const { data } = usePoll(() => api.get<Job>(`/api/v1/jobs/${id}`), 2000, [id]);
  const [notified, setNotified] = useState(false);
  useEffect(() => { if (data && data.status !== 'running' && !notified) { setNotified(true); onDone(); } }, [data, notified, onDone]);
  return (
    <section className="card pad stack">
      <div className="flex" style={{ justifyContent: 'space-between' }}><h2>Выкат #{id}</h2>{data && <Tag kind={data.status === 'ok' ? 'ok' : data.status === 'failed' ? 'fail' : 'warn'}>{data.status === 'running' ? 'идёт…' : data.status}</Tag>}</div>
      <pre className="code">{data?.log || 'запуск…'}</pre>
    </section>
  );
}

interface Health { rows: Array<{ exit_id: string; name: string; host: string; exit_ip: string | null; exit_loc: string | null; rtt_ms: number | null; mbps: number | null; ok: number; error: string | null; checked_at: string }>; selected: string | null; actual: string | null; checkedAt: string | null; slow: string[]; speedAt: string | null; decideAt: string | null; median: Record<string, number | null>; spread?: SpreadState | null }

/** Замер канала сервера на нём самом, Мбит/с. */
interface LinkTest { down: number; up: number; at: string }
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
          <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/templates/${t.id}/health/check`); await reload(); })}>{busy ? 'Проверяю…' : 'Проверить сейчас'}</button>
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
        ? !!data?.rows.length && !data.rows.some((r) => r.ok) && <div className="k" style={{ padding: '10px 20px' }}>Ни один выход не отвечает — вход держит трафик на первом по порядку.</div>
        : !data?.selected && !!data?.rows.length && <div className="k" style={{ padding: '10px 20px' }}>Выход не закреплён: Xray выбирает по наименьшей задержке.</div>}
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
          <button className="btn sm" disabled={busy} onClick={check}>{busy ? 'Проверяю…' : 'Проверить сейчас'}</button>
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
        <div className="k" style={{ padding: '10px 20px' }}>{`Переведены группы: ${st.groups.filter((g) => g.cur !== g.home).map((g) => g.g + 1).join(', ')}. Вернутся на свои выходы, когда там освободится место.`}</div>
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
