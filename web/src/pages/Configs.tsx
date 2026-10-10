import { useEffect, useState } from 'react';
import { api, type Job, type Server, type Template } from '../api';
import { CopyBlock, ErrorBox, Seg, Switch, Tag, useAsync, usePoll } from '../ui';

interface Draft {
  id: string | null; name: string; protocol: 'vless-reality' | 'hysteria2'; port: string; sni: string; fingerprint: string;
  ech: boolean; nodeIds: string[]; entryId: string; entryPort: string;
}

const empty: Draft = { id: null, name: '', protocol: 'vless-reality', port: '8443', sni: 'www.microsoft.com', fingerprint: 'chrome', ech: false, nodeIds: [], entryId: '', entryPort: '9443' };

const toDraft = (t: Template): Draft => ({
  id: t.id, name: t.name, protocol: t.protocol, port: String(t.port), sni: t.sni.join('\n'), fingerprint: t.fingerprint, ech: t.ech,
  nodeIds: t.node_ids, entryId: t.entry_id ?? '', entryPort: String(t.entry_port ?? 9443),
});

export function ConfigsPage() {
  const { data: templates, reload } = usePoll(() => api.get<Template[]>('/api/v1/templates'), 20_000);
  const { data: servers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [jobId, setJobId] = useState<number | null>(null);

  useEffect(() => {
    if (!draft && templates?.length) setDraft(toDraft(templates[0]!));
  }, [templates, draft]);

  const current = templates?.find((t) => t.id === draft?.id) ?? null;
  return (
    <>
      <div className="page-head">
        <div><h1>Конфигурации</h1><p>Шаблоны inbound: рендер под каждый узел, проверка на узле, canary и поэтапный выкат с автооткатом</p></div>
        <button className="btn pri" onClick={() => { setDraft({ ...empty }); setJobId(null); }}>Новый шаблон</button>
      </div>
      <div className="split">
        <section className="card narrow" style={{ padding: 10, flex: '1 1 280px' }} aria-label="Шаблоны">
          <div className="k" style={{ padding: '6px 8px' }}>Шаблоны · {templates?.length ?? 0}</div>
          {templates?.map((t) => (
            <button key={t.id} className={`tpl ${draft?.id === t.id ? 'on' : ''}`} onClick={() => { setDraft(toDraft(t)); setJobId(null); }}>
              <span className="flex" style={{ justifyContent: 'space-between', width: '100%' }}><b className="small">{t.name}</b><Tag>{t.core}</Tag></span>
              <span className="k mono">{t.protocol === 'hysteria2' ? 'Hysteria2 · QUIC' : 'VLESS · REALITY · Vision'} · :{t.port}{t.entry_id ? ` · вход :${t.entry_port}` : ''}</span>
              <span className="k">{t.inbounds.filter((i) => i.state === 'active').length} активно · ревизия {t.revision}{t.applied_revision < t.revision ? ' · не выкачена' : ''}</span>
            </button>
          ))}
          {!templates?.length && <p className="k" style={{ padding: 8 }}>Шаблонов пока нет.</p>}
        </section>
        <div className="wide stack" style={{ gap: 20 }}>
          {draft && servers && <Editor key={draft.id ?? 'new'} draft={draft} servers={servers} current={current}
            onSaved={(t) => { void reload(); setDraft(toDraft(t)); }} onRollout={(id) => setJobId(id)} onDeleted={() => { setDraft(null); void reload(); }} />}
          {jobId && <JobLog id={jobId} onDone={() => void reload()} />}
          {current && <Preview t={current} servers={servers ?? []} />}
        </div>
      </div>
      <CoresPanel />
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

function CoresPanel() {
  const { data, reload } = usePoll(() => api.get<CoresInfo>('/api/v1/cores'), null);
  const [core, setCore] = useState<'xray' | 'sing-box'>('xray');
  const [version, setVersion] = useState('latest');
  const [pre, setPre] = useState(false);
  const [jobId, setJobId] = useState<number | null>(null);
  const { busy, error, run } = useAsync();
  if (!data) return null;
  const rels = (data.releases[core] ?? []).filter((r) => pre || !r.prerelease);
  const ver = (c: { version: string; previous?: string } | null, k: string, s: CoresInfo['servers'][number]) => {
    if (!c) return <span className="k">—</span>;
    const old = s.outdated.includes(k);
    return (
      <span className="stack" style={{ gap: 4 }}>
        <span className="flex" style={{ gap: 6 }}><span className="mono small">{c.version}</span>{old && <Tag kind="warn">устарел</Tag>}</span>
        <span className="flex" style={{ gap: 6 }}>
          {old && <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/update`, { version: data.pins[k] ?? 'latest' }); void reload(); })}>Обновить</button>}
          {c.previous && <button className="btn ghost sm" disabled={busy} onClick={() => { if (confirm(`Вернуть ${k} ${c.previous} на ${s.name}?`)) void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${k}/rollback`); void reload(); }); }}>Откат на {c.previous}</button>}
        </span>
      </span>
    );
  };
  return (
    <section className="card">
      <div className="card-head">
        <div className="row-text"><h2>Ядра</h2><span className="k">Обновление: новая версия ставится рядом, текущий конфиг проверяется новым бинарником, при неудаче узел сам возвращает прежнюю. Xray узлов с 3x-ui обновляется в самом 3x-ui.</span></div>
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
        <h3>Обновить по флоту</h3>
        <div className="flex">
          <Seg value={core} label="Ядро" onChange={(c) => { setCore(c); setVersion('latest'); }} options={[['xray', 'Xray'], ['sing-box', 'sing-box']]} />
          <select className="inp" style={{ width: 'auto' }} value={version} onChange={(e) => setVersion(e.target.value)} aria-label="Версия">
            <option value="latest">последняя стабильная ({data.latest[core] ?? '?'})</option>
            {rels.map((r) => <option key={r.version} value={r.version}>{r.version}{r.prerelease ? ' · предрелиз' : ''} · {r.published.slice(0, 10)}</option>)}
          </select>
          <label className="cb small"><input type="checkbox" checked={pre} onChange={(e) => setPre(e.target.checked)} />показывать предрелизы</label>
        </div>
        <div className="flex">
          <button className="btn pri" disabled={busy} onClick={() => { if (confirm(`Обновить ${core} до ${version} на всех узлах со своим ядром? Canary → остальные, первая ошибка останавливает.`)) void run(async () => { const r = await api.post<{ jobId: number }>(`/api/v1/cores/${core}/rollout`, { version }); setJobId(r.jobId); }); }}>Обновить все узлы</button>
          <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/cores/pin', { core, version }); void reload(); })}>Закрепить для новых узлов</button>
          <span className="k">Сейчас новые узлы получают: {core} {data.pins[core] ?? 'latest'}</span>
        </div>
        <ErrorBox error={error} />
      </div>
      {jobId && <div style={{ padding: '0 20px 16px' }}><JobLog id={jobId} onDone={() => void reload()} /></div>}
    </section>
  );
}

function Editor({ draft, servers, current, onSaved, onRollout, onDeleted }: {
  draft: Draft; servers: Server[]; current: Template | null; onSaved: (t: Template) => void; onRollout: (jobId: number) => void; onDeleted: () => void;
}) {
  const [d, setD] = useState(draft);
  const { busy, error, run } = useAsync();
  const managed = servers.filter((s) => s.sudo_mode === 'restricted');
  const body = () => ({
    name: d.name, protocol: d.protocol, port: Number(d.port), sni: d.sni.split(/\s+/).filter(Boolean), fingerprint: d.fingerprint, ech: d.ech,
    nodeIds: d.nodeIds, entryId: d.entryId || null, entryPort: d.entryId ? Number(d.entryPort) : null,
  });
  const save = () => run(async () => {
    const t = d.id ? await api.put<Template>(`/api/v1/templates/${d.id}`, body()) : await api.post<Template>('/api/v1/templates', body());
    onSaved(t);
    return t;
  });
  const rollout = () => run(async () => {
    const t = d.id ? await api.put<Template>(`/api/v1/templates/${d.id}`, body()) : await api.post<Template>('/api/v1/templates', body());
    onSaved(t);
    const r = await api.post<{ jobId: number }>(`/api/v1/templates/${t.id}/rollout`);
    onRollout(r.jobId);
  });
  const toggleNode = (id: string) => setD({ ...d, nodeIds: d.nodeIds.includes(id) ? d.nodeIds.filter((x) => x !== id) : [...d.nodeIds, id] });
  const stateOf = (sid: string, kind: string) => current?.inbounds.find((i) => i.server_id === sid && i.kind === kind);

  return (
    <section className="card pad stack" style={{ gap: 18 }}>
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <div><h2>{d.id ? d.name : 'Новый шаблон'}</h2>{current && <span className="k">ревизия {current.revision}, выкачена {current.applied_revision || '—'}</span>}</div>
        {d.id && <button className="btn ghost" style={{ color: 'var(--fail)' }} disabled={busy} onClick={() => { if (confirm('Снять шаблон со всех узлов и удалить?')) void run(async () => { await api.del(`/api/v1/templates/${d.id}`); onDeleted(); }); }}>Удалить</button>}
      </div>
      <div className="stack" style={{ gap: 8 }}>
        <span className="k">Протокол и ядро</span>
        <Seg value={d.protocol} label="Протокол" onChange={(v) => !d.id && setD({ ...d, protocol: v, port: v === 'hysteria2' ? '8444' : d.port })}
          options={[['vless-reality', 'VLESS · REALITY (Xray)'], ['hysteria2', 'Hysteria2 (sing-box)']]} />
        {d.id && <span className="k">Протокол существующего шаблона не меняется — создайте новый.</span>}
      </div>
      <div className="grid g3">
        <label className="fld">Имя<input className="inp mono" value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder="reality-vision" /></label>
        <label className="fld">Порт{d.protocol === 'hysteria2' ? ' (UDP)' : ' (TCP)'}<input className="inp mono" value={d.port} onChange={(e) => setD({ ...d, port: e.target.value })} /><span className="k">Откроется на узлах сам после проверки</span></label>
        <label className="fld">Отпечаток клиента<select className="inp" value={d.fingerprint} onChange={(e) => setD({ ...d, fingerprint: e.target.value })}>{['chrome', 'firefox', 'safari', 'edge', 'random'].map((f) => <option key={f}>{f}</option>)}</select></label>
      </div>
      <label className="fld">{d.protocol === 'hysteria2' ? 'SNI сертификата' : 'Пул SNI (serverNames) — сайт для маскировки, по одному в строке'}
        <textarea className="inp mono" rows={3} value={d.sni} onChange={(e) => setD({ ...d, sni: e.target.value })} /></label>
      <div className="flex" style={{ justifyContent: 'space-between', background: 'var(--surface2)', borderRadius: 10, padding: '12px 14px' }}>
        <div className="row-text"><b>ECH</b><span className="k">Опционально на подключение. Профиль с ECH попадает в подписку только клиентам с поддержкой.</span></div>
        <Switch label="ECH" on={d.ech} onChange={(v) => setD({ ...d, ech: v })} />
      </div>

      <div className="stack" style={{ gap: 8 }}>
        <h3>Узлы — напрямую</h3>
        {!managed.length && <span className="k">Нет узлов с установленным nodekit.</span>}
        <div className="flex">
          {managed.map((s) => {
            const st = stateOf(s.id, 'direct');
            return (
              <label key={s.id} className="cb tag" style={{ minHeight: 36, padding: '0 12px' }}>
                <input type="checkbox" checked={d.nodeIds.includes(s.id)} onChange={() => toggleNode(s.id)} />
                {s.name}{st && <span className={`tag ${st.state === 'active' ? 'ok' : st.state === 'error' ? 'fail' : 'warn'}`} style={{ padding: '0 6px' }}>{st.state}</span>}
              </label>
            );
          })}
        </div>
        {current?.inbounds.filter((i) => i.error).map((i) => <div key={i.id} className="alert warn small">{servers.find((s) => s.id === i.server_id)?.name}: {i.error}</div>)}
      </div>

      {d.protocol === 'vless-reality' && (
        <div className="stack" style={{ gap: 8 }}>
          <h3>Универсальный вход (необязательно)</h3>
          <span className="k">Пользователь подключается к входу, а тот ведёт на выбранный узел: «DE · через вход», «Авто · через вход».</span>
          <div className="flex">
            <select className="inp" style={{ width: 'auto' }} value={d.entryId} onChange={(e) => setD({ ...d, entryId: e.target.value })} aria-label="Узел входа">
              <option value="">без входа</option>
              {managed.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            {d.entryId && <label className="flex small">порт входа<input className="inp mono" style={{ width: 100 }} value={d.entryPort} onChange={(e) => setD({ ...d, entryPort: e.target.value })} /></label>}
            {d.entryId && stateOf(d.entryId, 'relay') && <Tag kind={stateOf(d.entryId, 'relay')!.state === 'active' ? 'ok' : 'warn'}>{stateOf(d.entryId, 'relay')!.state}</Tag>}
          </div>
        </div>
      )}

      <div className="stack" style={{ gap: 6 }}>
        <span className="k">Стратегия: canary (первый узел) → остальные → вход. Перед каждым: проверка конфига на узле, открытие порта, внешняя проба. Ошибка — откат и остановка.</span>
        <div className="flex">
          <button className="btn pri" disabled={busy || !d.name || (!d.nodeIds.length && !d.entryId)} onClick={() => void rollout()}>Сохранить и выкатить</button>
          <button className="btn" disabled={busy || !d.name} onClick={() => void save()}>Сохранить черновик</button>
        </div>
      </div>
      <ErrorBox error={error} />
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

function Preview({ t, servers }: { t: Template; servers: Server[] }) {
  const ids = [...t.node_ids, ...(t.entry_id ? [t.entry_id] : [])];
  const [sid, setSid] = useState(ids[0] ?? '');
  const { data } = usePoll(() => (sid ? api.get<{ config: string | null }>(`/api/v1/templates/${t.id}/preview?server=${sid}`) : Promise.resolve({ config: null })), null, [sid, t.revision]);
  if (!ids.length) return null;
  return (
    <section className="card pad stack">
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>Рендер для узла</h2>
        <select className="inp" style={{ width: 'auto' }} value={sid} onChange={(e) => setSid(e.target.value)} aria-label="Узел">{ids.map((i) => <option key={i} value={i}>{servers.find((s) => s.id === i)?.name ?? i}</option>)}</select>
      </div>
      {data?.config ? <CopyBlock text={data.config} /> : <p className="k">Конфиг появится после выката (нужны ключи с узла).</p>}
    </section>
  );
}
