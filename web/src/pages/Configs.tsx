import { useEffect, useState } from 'react';
import { api, ago, type Job, type Server, type Template } from '../api';
import { RouteMap, exitView, type MapExit } from '../RouteMap';
import { CopyBlock, ErrorBox, Info, Seg, Switch, Tag, toast, useAsync, usePoll, ask } from '../ui';

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

type AutoMode = 'smart' | 'order' | 'random';
const AUTO_HINT: Record<AutoMode, string> = {
  smart: 'Трафик идёт через выход, который проходит пороги задержки и скорости. Пока он их проходит — не меняется; перестал — вход переключается на самый быстрый из подходящих.',
  order: 'Трафик идёт через первый выход в списке. Не отвечает — вход сам переводит трафик на следующий примерно за 10 секунд; первый снова отвечает — трафик возвращается к нему. Не отвечают и первый, и второй — на следующий переводит панель при своей проверке (около минуты). Вход проверяет выходы каждые 5 секунд, без замера скорости.',
  random: 'Каждое соединение — через любой выход наугад. Без проверок задержки и скорости.',
};

interface Settings {
  security: Security; transport: Transport; flow: string; path: string; host: string; serviceName: string; xhttpMode: string;
  alpn: string[]; certMode: CertMode; domain: string; domains: Record<string, string>; ssMethod: string; hy2Obfs: string; mtDomain: string; sniffing: boolean;
  autoMode: AutoMode; exitOrder: string[]; maxRttMs: number; minMbps: number; checkMin: number; testMB: number;
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
  autoMode: 'smart', exitOrder: [], maxRttMs: 100, minMbps: 10, checkMin: 15, testMB: 5,
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
      <div className="split">
        <section className="card narrow tpl-list" style={{ flex: '1 1 280px' }} aria-label="Конфигурации">
          <div className="k" style={{ padding: '6px 8px' }}>Конфигурации · {templates?.length ?? 0}</div>
          {templates?.map((t) => (
            <button key={t.id} className={`tpl ${draft?.id === t.id ? 'on' : ''}`} onClick={() => { setDraft(toDraft(t)); setJobId(null); }}>
              <span className="flex" style={{ justifyContent: 'space-between', width: '100%' }}><b className="small">{t.name}</b><Tag>{t.core}</Tag></span>
              <span className="k mono">{describe(t)} · :{t.port}{t.entry_id ? ` · вход :${t.entry_port}` : ''}</span>
              <span className="flex" style={{ gap: 6 }}><span className="k">серверов: {t.inbounds.filter((i) => i.state === 'active').length}</span>{t.applied_revision < t.revision && <Tag kind="warn">не выкачена</Tag>}</span>
            </button>
          ))}
          {!templates?.length && <p className="k" style={{ padding: 8 }}>Конфигураций пока нет.</p>}
        </section>
        <div className="wide stack" style={{ gap: 20 }}>
          {draft && servers && <Editor key={draft.id ?? 'new'} draft={draft} servers={servers} current={current} onServers={() => void reloadServers()}
            onSaved={(t) => { void reload(); setDraft(toDraft(t)); }} onRollout={(id) => setJobId(id)} onDeleted={() => { setDraft(null); void reload(); }} />}
          {jobId && <JobLog id={jobId} onDone={() => void reload()} />}
          {current?.entry_id && current.spec.autoMode !== 'random' && <ExitHealth t={current} />}
          {current && <Preview t={current} servers={servers ?? []} />}
        </div>
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
  const move = (i: number, dir: -1 | 1) => {
    const ids = exits.map((s) => s.id);
    [ids[i], ids[i + dir]] = [ids[i + dir]!, ids[i]!];
    setSt({ exitOrder: ids });
  };
  const dirty = JSON.stringify(d) !== JSON.stringify(draft);
  const body = () => ({
    name: d.name, protocol: d.protocol, port: Number(d.port), sni: d.sni.split(/[\s,]+/).filter(Boolean), fingerprint: d.fingerprint, ech: d.ech,
    nodeIds: d.nodeIds, entryId: d.entryId || null, entryPort: d.entryId ? Number(d.entryPort) : null,
    settings: {
      security: st.security, transport: st.transport, flow: st.transport === 'tcp' && st.security !== 'none' && d.protocol === 'vless' ? st.flow : '',
      path: st.path, host: st.host, serviceName: st.serviceName, xhttpMode: st.xhttpMode, alpn: st.alpn, certMode: st.certMode,
      domain: st.domain, domains: Object.fromEntries(Object.entries(st.domains).filter(([k, v]) => usedIds.includes(k) && v)),
      ssMethod: st.ssMethod, hy2Obfs: st.hy2Obfs, mtDomain: st.mtDomain, sniffing: st.sniffing,
      autoMode: st.autoMode, exitOrder: exits.map((s) => s.id), maxRttMs: Number(st.maxRttMs) || 100, minMbps: Number(st.minMbps) || 10, checkMin: Number(st.checkMin) || 15, testMB: Number(st.testMB) || 5,
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
        <label className="fld"><span>Сайт маскировки (SNI) <Info>Чужой сайт с TLS 1.3, под который маскируется сервер: www.apple.com, dl.google.com, www.cloudflare.com, www.samsung.com. Можно несколько через пробел. www.microsoft.com с REALITY не работает.</Info></span>
          <input className="inp mono" value={d.sni} onChange={(e) => setD({ ...d, sni: e.target.value })} placeholder="www.apple.com" />
        </label>
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
            ordered={!!d.entryId && st.autoMode === 'order'}
            onToggle={toggleNode}
            onMove={(id, dir) => move(exits.findIndex((x) => x.id === id), dir)}
          />
        )}
        {current?.inbounds.filter((i) => i.error).map((i) => <div key={i.id} className="alert warn small">{servers.find((s) => s.id === i.server_id)?.name}: {i.error}</div>)}
        {d.entryId && info.relay && (
          <div className="stack" style={{ gap: 8 }}>
            <span className="k">Профиль «вход → авто» выбирает выход <Info>Задержку вход проверяет сам раз в минуту, скорость скачивания панель меряет по расписанию. Переключение — без разрыва соединений; о каждом переключении бот пишет админам.</Info></span>
            <Seg value={st.autoMode} label="Выбор выхода" onChange={(v) => setSt({ autoMode: v })} options={[['smart', 'по качеству'], ['order', 'по порядку'], ['random', 'случайно']]} />
            <span className="small muted" style={{ maxWidth: '68ch' }}>{AUTO_HINT[st.autoMode]}{st.autoMode === 'order' ? ' Порядок — стрелками на схеме.' : ''}</span>
            {st.autoMode === 'smart' && (
              <div className="grid g4">
                <label className="fld">Задержка не больше, мс<input className="inp mono" inputMode="numeric" value={st.maxRttMs} onChange={(e) => setSt({ maxRttMs: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                <label className="fld">Скорость не меньше, Мбит/с<input className="inp mono" inputMode="decimal" value={st.minMbps} onChange={(e) => setSt({ minMbps: Number(e.target.value.replace(/[^\d.]/g, '')) })} /></label>
                <label className="fld">Проверять каждые, мин<input className="inp mono" inputMode="numeric" value={st.checkMin} onChange={(e) => setSt({ checkMin: Number(e.target.value.replace(/\D/g, '')) })} /></label>
                <label className="fld"><span>Объём теста, МБ <Info>Сколько скачивать через каждый выход при проверке скорости. 5 МБ раз в 15 минут — около 0,5 ГБ трафика в сутки на выход.</Info></span><input className="inp mono" inputMode="numeric" value={st.testMB} onChange={(e) => setSt({ testMB: Number(e.target.value.replace(/\D/g, '')) })} /></label>
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

interface Health { rows: Array<{ exit_id: string; name: string; rtt_ms: number | null; mbps: number | null; ok: number; error: string | null; checked_at: string }>; selected: string | null; actual: string | null; checkedAt: string | null }

/** Выходы «Авто через вход»: последние замеры, какой выбран; ручная проверка. */
function ExitHealth({ t }: { t: Template }) {
  const { data, reload } = usePoll(() => api.get<Health>(`/api/v1/templates/${t.id}/health`), 60_000, [t.id]);
  const { busy, error, run } = useAsync();
  const sp = t.spec as { maxRttMs?: number; minMbps?: number; autoMode?: string };
  const order = sp.autoMode === 'order';
  const lead = data?.actual ?? data?.selected ?? null;   // реальный выбор входа; если его ещё не видели — назначенный
  return (
    <section className="card">
      <div className="card-head">
        <h2>Выходы «Авто» <Info>{order ? 'По порядку: трафик идёт через первый отвечающий выход. Переключает сам вход за ~10 секунд; таблица обновляется раз в минуту.' : `Пороги: задержка не больше ${sp.maxRttMs ?? 100} мс, скорость не меньше ${sp.minMbps ?? 10} Мбит/с. Выбранный выход меняется, только когда текущий перестаёт проходить пороги.`}</Info></h2>
        <span className="flex">
          {data?.checkedAt && <span className="k">проверено {ago(data.checkedAt)}</span>}
          <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/templates/${t.id}/health/check`); await reload(); })}>{busy ? 'Проверяю…' : 'Проверить сейчас'}</button>
        </span>
      </div>
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table>
          <thead><tr><th>Выход</th><th>Задержка</th>{!order && <th>Скорость</th>}<th>Состояние</th></tr></thead>
          <tbody>
            {data?.rows.map((r) => (
              <tr key={r.exit_id}>
                <td><b>{r.name}</b>{lead === r.exit_id && <> <Tag kind="acc" dot>ведёт трафик</Tag></>}{data.selected === r.exit_id && lead !== r.exit_id && <> <Tag kind="warn">назначен, вход ещё не переключился</Tag></>}</td>
                <td className="mono">{r.rtt_ms !== null ? `${r.rtt_ms} мс` : '—'}</td>
                {!order && <td className="mono">{r.mbps !== null ? `${r.mbps} Мбит/с` : '—'}</td>}
                <td>{r.ok ? <Tag kind="ok">{order ? 'отвечает' : 'проходит'}</Tag> : <Tag kind={r.error ? 'fail' : 'warn'}>{r.error === 'выход не отвечает' ? 'неактивен — нет связи' : r.error ?? 'ниже порога'}</Tag>}</td>
              </tr>
            ))}
            {data && !data.rows.length && <tr><td colSpan={4} className="empty">Проверок ещё не было — нажмите «Проверить сейчас» или подождите расписания.</td></tr>}
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
