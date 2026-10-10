import { useEffect, useState, type ReactNode } from 'react';
import { api, ago, fmtTime, type Check, type Job, type Preflight, type ServerDetail } from '../api';
import { CopyBlock, CopyButton, ErrorBox, Seg, StagePip, Switch, Tag, useAsync, usePoll } from '../ui';

type Tab = 'protect' | 'ports' | 'access' | 'sos' | 'host' | 'jobs';

export function ServerDetailPage({ id }: { id: string }) {
  const { data: d, error, reload } = usePoll(() => api.get<ServerDetail>(`/api/v1/servers/${id}`), 15_000, [id]);
  const [tab, setTab] = useState<Tab>('protect');
  if (!d) return <><ErrorBox error={error} />{!error && <p className="muted">Загрузка…</p>}</>;
  const s = d.server;
  const onboarding = s.stage < 2;

  return (
    <>
      <div className="page-head">
        <div className="stack" style={{ gap: 6 }}>
          <a href="#/servers" className="k">← Серверы</a>
          <h1>{s.name} <StagePip stage={s.stage} /></h1>
          <span className="k mono">{s.host}:{s.ssh_port} · {s.role} · группа {s.group_name} · {s.os_info?.pretty ?? 'ОС не определена'}{s.kit_version ? ` · nodekit ${s.kit_version}` : ''} · {s.sudo_mode === 'restricted' ? `sudo сужен · ${s.ssh_mode}` : 'sudo широкий'}</span>
        </div>
        <HeaderActions d={d} onChange={reload} />
      </div>
      <ErrorBox error={error} />
      {s.fail_since && <div className="alert fail">Нет связи с узлом с {fmtTime(s.fail_since)}. Если сбой продлится дольше порога, чек-лист придётся пройти заново.</div>}
      {s.fw_mode === 'pending' && <PendingBanner d={d} onChange={reload} />}

      {onboarding ? <Onboarding d={d} onChange={reload} /> : (
        <>
          <div className="tabs" role="tablist">
            {([['protect', 'Защита'], ['ports', 'Порты'], ['access', 'Доступ и SSH'], ['sos', 'Аварийный доступ'], ['host', 'Хост'], ['jobs', 'Задачи']] as Array<[Tab, string]>).map(([t, l]) => (
              <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'on' : ''} onClick={() => setTab(t)}>{l}</button>
            ))}
          </div>
          {tab === 'protect' && <ProtectTab d={d} onChange={reload} />}
          {tab === 'ports' && <PortsTab d={d} />}
          {tab === 'access' && <AccessTab d={d} onChange={reload} />}
          {tab === 'sos' && <SosTab d={d} />}
          {tab === 'host' && <HostTab d={d} onChange={reload} />}
          {tab === 'jobs' && <JobsCard serverId={s.id} jobs={d.jobs} />}
        </>
      )}
    </>
  );
}

function HeaderActions({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const { busy, error, run } = useAsync();
  const s = d.server;
  const del = () => {
    if (!confirm('Удалить сервер из панели? На самом сервере ничего не изменится: пользователь fleet и ключ останутся.')) return;
    void run(async () => { await api.del(`/api/v1/servers/${s.id}`); location.hash = '#/servers'; });
  };
  return (
    <div className="stack" style={{ alignItems: 'flex-end' }}>
      <div className="flex">
        {s.host_key_fp && <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/check`); onChange(); })}>Проверить связь</button>}
        <button className="btn ghost" style={{ color: 'var(--fail)' }} disabled={busy} onClick={del}>Удалить из панели</button>
      </div>
      <ErrorBox error={error} />
    </div>
  );
}

function PendingBanner({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const [left, setLeft] = useState(0);
  useEffect(() => {
    const tick = () => setLeft(Math.max(0, Math.round((Date.parse(s.fw_pending_until ?? '') - Date.now()) / 1000)));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [s.fw_pending_until]);
  const { busy, error, run } = useAsync();
  return (
    <div className="card pad stack" style={{ borderColor: 'var(--warn)' }}>
      <h2>Правила активны — подтвердите до отката: {left} с</h2>
      <p className="small muted">Проверьте вручную: SSH со своего устройства, панель, VPN-клиент. Если что-то не так — не подтверждайте, узел сам вернёт прежние правила.</p>
      <div className="flex">
        <button className="btn pri" disabled={busy || left === 0} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/fw/confirm`); onChange(); })}>Всё работает — подтвердить</button>
        <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/fw/rollback`); onChange(); })}>Откатить сейчас</button>
      </div>
      <ErrorBox error={error} />
    </div>
  );
}

// ───── онбординг: шаги 1–5 ─────

function Step({ n, title, done, cur, off, children }: { n: number; title: string; done: boolean; cur?: boolean; off?: boolean; children: ReactNode }) {
  return (
    <li className={`card pad step ${done ? 'done' : ''} ${cur ? 'cur' : ''} ${off ? 'off' : ''}`}>
      <div className="step-head"><span className="step-n" aria-hidden>{done ? '✓' : n}</span><h2>{title}</h2></div>
      <div className="step-body">{off ? <p className="k">Станет доступно после предыдущего шага.</p> : children}</div>
    </li>
  );
}

function Onboarding({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const pinned = !!s.host_key_fp;
  const connected = s.stage >= 1;
  const cmd = `ssh -p ${s.ssh_port} root@${s.host} 'bash -s' < bootstrap-${s.id}.sh`;
  return (
    <ol className="steps">
      <Step n={1} title="Bootstrap-сниппет" done={pinned} cur={!pinned}>
        <p className="small">Выполните на сервере под <b>root</b>. Сниппет только <b>добавляет</b> пользователя <code>fleet</code> с ключом панели и временный sudo — существующие ключи, пароли, порты и firewall не трогает.</p>
        <div className="flex"><a className="btn" href={`api/v1/servers/${s.id}/bootstrap.sh`} download>Скачать сниппет</a><span className="k">и запустить со своей машины (спросит root-пароль сервера):</span></div>
        <CopyBlock text={cmd} />
        <details><summary className="k" style={{ cursor: 'pointer' }}>Показать сниппет целиком</summary><CopyBlock text={d.snippet} /></details>
      </Step>
      <Step n={2} title="Сверка host key" done={pinned} cur={!pinned}><HostKeyStep d={d} onChange={onChange} /></Step>
      <Step n={3} title="Вход по ключу и sudo" done={connected} cur={pinned && !connected} off={!pinned}><CheckStep d={d} onChange={onChange} /></Step>
      <Step n={4} title="Preflight и baseline (только чтение)" done={!!d.preflight} cur={connected && !d.preflight} off={!connected}><PreflightView d={d} onChange={onChange} /></Step>
      <Step n={5} title="Nodekit, сужение sudo и строгий режим" done={s.sudo_mode === 'restricted'} cur={!!d.preflight} off={!d.preflight || d.preflight.blocking}><NodekitStep d={d} onChange={onChange} /></Step>
    </ol>
  );
}

function HostKeyStep({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const [fetched, setFetched] = useState<string | null>(s.host_key_pending_fp);
  const [typed, setTyped] = useState('');
  const { busy, error, run } = useAsync();
  const matches = !!fetched && typed.trim() === fetched;
  return (
    <>
      {s.host_key_fp && <p>Закреплён: <code>{s.host_key_fp}</code></p>}
      <p className="k">Панель запрашивает ключ у сервера, а вы вставляете отпечаток из вывода сниппета. Доверие на первом подключении (TOFU) запрещено.</p>
      <div className="flex">
        <button className="btn" disabled={busy} onClick={() => void run(async () => setFetched((await api.post<{ fingerprint: string }>(`/api/v1/servers/${s.id}/host-key/fetch`)).fingerprint))}>{fetched ? 'Получить заново' : 'Получить ключ сервера'}</button>
        {fetched && <span className="small">Сервер прислал: <code>{fetched}</code></span>}
      </div>
      {fetched && fetched !== s.host_key_fp && (
        <>
          {s.host_key_fp && <div className="alert fail">Сервер прислал ДРУГОЙ ключ. Подтверждайте только при пересборке сервера — статус и чек-лист сбросятся.</div>}
          <label className="fld">Отпечаток из вывода сниппета<input className="inp mono" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="SHA256:..." /></label>
          {typed && !matches && <div className="alert warn">Не совпадает. Не доверяйте ключу, пока не выясните причину.</div>}
          <div><button className="btn pri" disabled={!matches || busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/host-key/trust`, { fingerprint: typed.trim() }); onChange(); })}>Совпадает — доверять</button></div>
        </>
      )}
      <ErrorBox error={error} />
    </>
  );
}

function CheckStep({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const [res, setRes] = useState<{ ok: boolean; user: string; seenFromIp: string; sudo: string } | null>(null);
  const { busy, error, run } = useAsync();
  return (
    <>
      <div><button className="btn" disabled={busy} onClick={() => void run(async () => { setRes(await api.post(`/api/v1/servers/${s.id}/check`)); onChange(); })}>{busy ? 'Подключаюсь…' : 'Проверить вход'}</button></div>
      {res && <div className={`alert ${res.ok ? 'ok' : 'fail'}`}>Пользователь <code>{res.user}</code>, сервер видит панель с <code>{res.seenFromIp}</code>, sudo: {res.sudo}</div>}
      {!res && s.seen_from_ip && <p className="k">Последний вход с {s.seen_from_ip}, {ago(s.last_seen_at)}</p>}
      <ErrorBox error={error} />
    </>
  );
}

const ICON: Record<Check['status'], string> = { ok: '✓', warn: '!', fail: '✕', info: 'i' };

function PreflightView({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const [p, setP] = useState<Preflight | null>(d.preflight);
  const { busy, error, run } = useAsync();
  return (
    <>
      <div className="flex">
        <button className="btn" disabled={busy} onClick={() => void run(async () => { setP(await api.post<Preflight>(`/api/v1/servers/${d.server.id}/preflight`)); onChange(); })}>{busy ? 'Собираю снимок…' : p ? 'Повторить preflight' : 'Запустить preflight'}</button>
        {p?.created_at && <span className="k">последний: {fmtTime(p.created_at)}</span>}
      </div>
      {p && (
        <>
          {p.blocking && <div className="alert fail">Есть блокирующие проблемы — дальше идти нельзя.</div>}
          <ul className="checks">
            {p.checks.map((c) => <li key={c.id} className={`check ${c.status}`}><span className="ci" aria-label={c.status}>{ICON[c.status]}</span><b className="small">{c.title}</b><span className="small muted">{c.detail}</span></li>)}
          </ul>
          {p.baselinePath && <p className="k">Baseline на узле: <code>{p.baselinePath}</code></p>}
        </>
      )}
      <ErrorBox error={error} />
    </>
  );
}

function NodekitStep({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const [out, setOut] = useState<string | null>(null);
  const { busy, error, run } = useAsync();
  const outdated = s.sudo_mode === 'restricted' && s.kit_version !== d.nodekitVersion;
  return (
    <>
      <p className="small muted">Ставит <code>fleet-exec</code>, <code>fleetctl</code>, установщик ядер и страховочные скрипты firewall (не включая их), заменяет широкий sudo одной обёрткой и включает строгий режим ключа панели. Широкий sudo удаляется только после того, как обёртка ответила.</p>
      {(s.sudo_mode !== 'restricted' || outdated) && (
        <div><button className="btn pri" disabled={busy} onClick={() => void run(async () => { const r = await api.post<{ version: string }>(`/api/v1/servers/${s.id}/nodekit/install`); setOut(`nodekit ${r.version} установлен, sudo сужен, строгий режим включён`); onChange(); })}>{busy ? 'Устанавливаю…' : outdated ? `Обновить nodekit до ${d.nodekitVersion}` : `Установить nodekit ${d.nodekitVersion}`}</button></div>
      )}
      {out && <div className="alert ok">{out}</div>}
      <ErrorBox error={error} />
    </>
  );
}

// ───── вкладка «Защита» ─────

const LEVELS = [
  { code: 'P1', name: 'Обычный', desc: 'Хост как есть. Панель только показывает рекомендации.', c: [false, false, false] },
  { code: 'P2', name: 'Нормальный', desc: 'Входящие закрыты, открыты только порты роли хоста.', c: [true, false, false] },
  { code: 'P3', name: 'Высокий', desc: 'Закрытые порты, whitelist адресов и SSH только по ключам.', c: [true, true, true] },
] as const;
const CTRL = ['C1 · закрытые порты', 'C2 · whitelist адресов', 'C3 · SSH только по ключам'];

interface Plan { text: string; lint: string[]; warnings: string[]; summary: { level: string; stealth: string; sshPorts: number[]; svcTcp: number[]; svcUdp: number[]; panel: string[]; admin: string[]; peers: string[]; users: number } }

function ProtectTab({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [plan, setPlan] = useState<Plan | null>(null);
  const [win, setWin] = useState(120);
  const [shadow, setShadow] = useState<Array<{ flow: string; count: number }> | null>(null);
  const passed = !!d.checklist.passedAt;
  const fwStage = s.fw_mode === 'enforced' ? 5 : s.fw_mode === 'pending' ? 4 : s.fw_mode === 'shadow' ? 3 : plan ? 2 : passed ? 2 : 1;

  return (
    <div className="stack" style={{ gap: 20 }}>
      <section className="stack">
        <div className="flex" style={{ justifyContent: 'space-between' }}>
          <h2>Уровень защиты хоста</h2>
          <span className="k">Сейчас: <b className="mono">{s.protection_current}</b> · цель задаётся здесь, применение — по шагам ниже</span>
        </div>
        <div className="grid g3">
          {LEVELS.map((l) => (
            <button key={l.code} className={`lvl ${s.protection_target === l.code ? 'on' : ''}`} aria-pressed={s.protection_target === l.code} disabled={busy}
              onClick={() => void run(async () => { await api.patch(`/api/v1/servers/${s.id}`, { protectionTarget: l.code }); setPlan(null); onChange(); })}>
              <span className="flex" style={{ justifyContent: 'space-between', width: '100%' }}><span className="mono" style={{ color: 'var(--accent)', fontWeight: 500 }}>{l.code}</span><span className="k">{l.code === 'P1' ? 'по умолчанию для главного' : l.code === 'P3' ? 'цель для нод' : ''}</span></span>
              <span style={{ fontSize: 17, fontWeight: 600 }}>{l.name}</span>
              <span className="k">{l.desc}</span>
              <span className="stack" style={{ gap: 6 }}>{CTRL.map((c, i) => <span key={c} className="ctl"><span style={{ width: 14, color: l.c[i] ? 'var(--ok)' : 'var(--muted)', fontWeight: 700 }}>{l.c[i] ? '✓' : '–'}</span>{c}</span>)}</span>
            </button>
          ))}
        </div>
      </section>

      {s.protection_target !== 'P1' && (
        <section className="card pad stack" style={{ gap: 18 }}>
          <div className="flex" style={{ justifyContent: 'space-between' }}>
            <div><h2>Применение блокировок</h2><span className="k">Режим firewall: {s.fw_mode}</span></div>
          </div>
          <div className="pipeline" aria-label="Этапы применения">
            {['Наблюдение', 'Ручной чек-лист', 'План и линтер', 'Shadow', 'Таймер отката', 'Подтверждено'].map((t, i) => (
              <span key={t} className={`pst ${i < fwStage ? 'done' : i === fwStage ? 'cur' : ''}`}><b>{i < fwStage ? '✓' : i + 1}</b>{t}</span>
            ))}
          </div>
          {s.ufw_active ? <div className="alert warn">На узле включён ufw: он перебивает разрешения nftables. Выключите его на вкладке «Хост».</div> : null}
          <div className="split">
            <div className="wide"><Checklist d={d} onChange={onChange} /></div>
            <div className="narrow stack">
              <h3>План</h3>
              <div className="flex">
                <button className="btn" disabled={busy} onClick={() => void run(async () => setPlan(await api.post<Plan>(`/api/v1/servers/${s.id}/fw/plan`, {})))}>Построить план {s.protection_target}</button>
                {plan && <Tag kind={plan.lint.length ? 'fail' : 'ok'}>{plan.lint.length ? `линтер: ${plan.lint.length}` : 'линтер пройден'}</Tag>}
              </div>
              {plan && (
                <>
                  {plan.lint.map((l) => <div key={l} className="alert fail">{l}</div>)}
                  {plan.warnings.map((w) => <div key={w} className="alert warn">{w}</div>)}
                  <div className="k">SSH {plan.summary.sshPorts.join(', ')} · панель {plan.summary.panel.join(', ')} · админы {plan.summary.admin.join(', ') || '—'} · ноды {plan.summary.peers.length} · сервисные tcp {plan.summary.svcTcp.join(', ') || '—'} udp {plan.summary.svcUdp.join(', ') || '—'} · скрытность {plan.summary.stealth} · IP пользователей {plan.summary.users}</div>
                  <details><summary className="k" style={{ cursor: 'pointer' }}>Текст плана nft</summary><CopyBlock text={plan.text} /></details>
                  <div className="flex">
                    <button className="btn" disabled={busy || !!plan.lint.length} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/fw/shadow`, {}); onChange(); })}>Включить shadow</button>
                    <button className="btn ghost" disabled={busy} onClick={() => void run(async () => setShadow((await api.get<{ top: Array<{ flow: string; count: number }> }>(`/api/v1/servers/${s.id}/fw/shadow-log?minutes=1440`)).top))}>Что бы заблокировалось</button>
                  </div>
                  {shadow && (shadow.length ? <pre className="code">{shadow.map((h) => `${String(h.count).padStart(6)}  ${h.flow}`).join('\n')}</pre> : <p className="k">За сутки ничего бы не заблокировалось (или shadow ещё не включался).</p>)}
                  <div className="flex">
                    <select className="inp" style={{ width: 'auto' }} value={win} onChange={(e) => setWin(Number(e.target.value))} aria-label="Окно подтверждения"><option value={120}>120 с</option><option value={300}>300 с</option><option value={600}>600 с</option></select>
                    <button className="btn pri" disabled={busy || !passed || !!plan.lint.length || !!s.ufw_active} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/fw/apply`, { window: win }); onChange(); })}>Применить под таймером</button>
                  </div>
                  {!passed && <span className="k">Применение откроется после ручного чек-листа.</span>}
                </>
              )}
            </div>
          </div>
          {s.protection_target === 'P3' && s.fw_mode === 'enforced' && <KeyOnly d={d} onChange={onChange} />}
        </section>
      )}
      <ErrorBox error={error} />
    </div>
  );
}

function Checklist({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const [marks, setMarks] = useState<Record<string, boolean>>(() => Object.fromEntries(d.checklist.items.filter((i) => !i.auto).map((i) => [i.id, i.done])));
  const { busy, error, run } = useAsync();
  const done = d.checklist.items.filter((i) => (i.auto ? i.done : marks[i.id])).length;
  return (
    <div className="stack" style={{ gap: 4 }}>
      <div className="flex" style={{ justifyContent: 'space-between' }}><h3>Ручной чек-лист</h3><span className="k">{done} из {d.checklist.total} · {d.checklist.passedAt ? `пройден ${fmtTime(d.checklist.passedAt)}` : 'проходится один раз'}</span></div>
      {d.checklist.items.map((i) => (
        <label key={i.id} className="cb" style={{ borderTop: '1px solid var(--line)', padding: '6px 0', alignItems: 'flex-start' }}>
          <input type="checkbox" disabled={i.auto} checked={i.auto ? i.done : !!marks[i.id]} onChange={(e) => setMarks({ ...marks, [i.id]: e.target.checked })} />
          <span>{i.title}{i.auto && <span className="k"> · авто</span>}</span>
        </label>
      ))}
      <div className="flex" style={{ marginTop: 8 }}><button className="btn" disabled={busy} onClick={() => void run(async () => { await api.put(`/api/v1/servers/${d.server.id}/checklist`, marks); onChange(); })}>Сохранить отметки</button></div>
      <div className="alert info small">Пройденный чек-лист не истекает. Проверять заново нужно только после сбоя: нет связи с узлом или между узлами дольше порога (Настройки), а также после смены SSH или пересборки узла.</div>
      <ErrorBox error={error} />
    </div>
  );
}

function KeyOnly({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const { busy, error, run } = useAsync();
  const [pending, setPending] = useState(false);
  const s = d.server;
  return (
    <div className="row" style={{ padding: '14px 0 0' }}>
      <div className="row-text"><b>C3 · SSH только по ключам</b><span className="k">Под таймером отката 180 с. Включайте, только если вход своим ключом проверен.</span></div>
      {s.key_only ? <Tag kind="ok">включено</Tag> : pending ? (
        <div className="flex"><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/key-only`, { action: 'confirm' }); setPending(false); onChange(); })}>Вход работает — подтвердить</button>
          <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/key-only`, { action: 'rollback' }); setPending(false); onChange(); })}>Откатить</button></div>
      ) : <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/key-only`, { action: 'apply' }); setPending(true); })}>Включить</button>}
      <ErrorBox error={error} />
    </div>
  );
}

// ───── порты ─────

function PortsTab({ d }: { d: ServerDetail }) {
  const s = d.server;
  return (
    <section className="card">
      <div className="card-head"><div><h2>Порты</h2><span className="k">Порты inbounds открываются сами при выкате и закрываются после вывода</span></div><a href="#/ports">Связность нод</a></div>
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table>
          <thead><tr><th>Порт</th><th>Назначение</th><th>Источник</th><th>Состояние</th></tr></thead>
          <tbody>
            {s.ssh_ports.map((p) => <tr key={`ssh${p}`}><td className="mono">{p}/tcp</td><td>SSH</td><td><Tag kind="acc">защищён</Tag></td><td><Tag kind="ok">открыт</Tag></td></tr>)}
            <tr><td className="mono">10085/tcp</td><td>API ядра</td><td><Tag kind="acc">резерв</Tag></td><td><Tag>только 127.0.0.1</Tag></td></tr>
            {d.inbounds.map((i) => (
              <tr key={i.id}><td className="mono">{i.port}/{i.proto}</td><td>{i.protocol} · {i.kind === 'relay' ? 'вход' : 'напрямую'}</td><td>шаблон «{i.template}» · {i.core}</td>
                <td><Tag kind={i.state === 'active' ? 'ok' : i.state === 'error' ? 'fail' : 'warn'}>{i.state}</Tag>{i.error && <div className="k">{i.error}</div>}</td></tr>
            ))}
            {!d.inbounds.length && <tr><td colSpan={4} className="k">Конфигураций на узле нет — выкатите шаблон в разделе «Конфигурации».</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ───── доступ и SSH ─────

function AccessTab({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [ip, setIp] = useState('');
  const patch = (body: object) => run(async () => { await api.patch(`/api/v1/servers/${s.id}`, body); onChange(); });
  return (
    <section className="card">
      <div className="card-head"><h2>Доступ и SSH</h2></div>
      <div className="row">
        <div className="row-text"><b>Админские адреса</b><span className="k">Пускаются по SSH на уровне P3. Если адрес неизвестен — «Временно открыть SSH» на вкладке «Аварийный доступ».</span></div>
        <div className="flex">
          {s.admin_ips.map((a) => <span key={a} className="tag mono">{a} <button className="link" aria-label={`убрать ${a}`} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/admin-ips`, { ip: a, remove: true }); onChange(); })}>×</button></span>)}
          <input className="inp mono" style={{ width: 170 }} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="198.51.100.20" aria-label="Новый админский адрес" />
          <button className="btn" disabled={busy || !ip} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/admin-ips`, { ip }); setIp(''); onChange(); })}>Добавить</button>
        </div>
      </div>
      <div className="row">
        <div className="row-text"><b>Терминал (shell) в панели</b><span className="k">{s.ssh_mode === 'shell' ? 'Включён: ключ панели без forced command, широкий sudo.' : 'Выключен — ключ панели принудительно идёт через fleet-exec (строгий режим). Всё управление работает и без shell.'}</span></div>
        <Switch label="Терминал" on={s.ssh_mode === 'shell'} disabled={busy || s.sudo_mode !== 'restricted'} onChange={(v) => void run(async () => { await api.post(`/api/v1/servers/${s.id}/ssh-mode`, { mode: v ? 'shell' : 'strict' }); onChange(); })} />
      </div>
      {s.ssh_mode === 'shell' && <Terminal id={s.id} />}
      <div className="row">
        <div className="row-text"><b>Прямой доступ пользователей</b><span className="k">Профиль «{s.name} · напрямую» попадает в подписки. Узел виден снаружи.</span></div>
        <Switch label="Прямой доступ" on={!!s.direct_access} disabled={busy} onChange={(v) => void patch({ directAccess: v })} />
      </div>
      <div className="row">
        <div className="row-text"><b>SSH между нодами</b><span className="k">emergency: только проверка связи, allow нового IP панели и временное открытие SSH.</span></div>
        <Seg value={s.peer_ssh as 'off' | 'emergency'} label="SSH между нодами" options={[['off', 'выключен'], ['emergency', 'emergency']]} onChange={(v) => void patch({ peerSsh: v })} />
      </div>
      <div className="row">
        <div className="row-text"><b>Роль и группа</b><span className="k">Группа задаёт уровень скрытности, связность и диапазон портов (раздел «Порты и связность»).</span></div>
        <div className="flex">
          <select className="inp" style={{ width: 'auto' }} value={s.role} onChange={(e) => void patch({ role: e.target.value })} aria-label="Роль">{['entry', 'relay', 'exit', 'control'].map((r) => <option key={r}>{r}</option>)}</select>
          <GroupInput value={s.group_name} onSave={(g) => void patch({ group: g })} />
        </div>
      </div>
      <div style={{ padding: '0 20px 14px' }}><ErrorBox error={error} /></div>
    </section>
  );
}

function GroupInput({ value, onSave }: { value: string; onSave: (v: string) => void }) {
  const [v, setV] = useState(value);
  return <form className="flex" onSubmit={(e) => { e.preventDefault(); if (v.trim()) onSave(v.trim()); }}><input className="inp" style={{ width: 140 }} value={v} onChange={(e) => setV(e.target.value)} aria-label="Группа" /><button className="btn sm" disabled={v === value}>Сохранить</button></form>;
}

function Terminal({ id }: { id: string }) {
  const [cmd, setCmd] = useState('');
  const [out, setOut] = useState('');
  const { busy, error, run } = useAsync();
  return (
    <div style={{ padding: '0 20px 14px' }} className="stack">
      <form className="flex" onSubmit={(e) => { e.preventDefault(); void run(async () => { const r = await api.post<{ code: number; stdout: string; stderr: string }>(`/api/v1/servers/${id}/exec`, { command: cmd }); setOut(`$ ${cmd}\n${r.stdout}${r.stderr}[exit ${r.code}]`); }); }}>
        <input className="inp mono" style={{ flex: 1 }} value={cmd} onChange={(e) => setCmd(e.target.value)} placeholder="команда (без PTY, пишется в аудит)" aria-label="Команда" />
        <button className="btn" disabled={busy || !cmd}>Выполнить</button>
      </form>
      {out && <pre className="code">{out}</pre>}
      <ErrorBox error={error} />
    </div>
  );
}

// ───── аварийный доступ ─────

function SosTab({ d }: { d: ServerDetail }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [dur, setDur] = useState('30m');
  const [msg, setMsg] = useState<string | null>(null);
  const [fa, setFa] = useState<{ username: string; password: string } | null>(null);
  return (
    <>
      <div className="grid g2">
        <div className="card pad stack">
          <h3>Временно открыть SSH</h3>
          <span className="k">SSH с любого адреса, только ключ, ≤20 новых соединений в минуту. Возвращается само.</span>
          <div className="flex"><select className="inp" style={{ width: 'auto' }} value={dur} onChange={(e) => setDur(e.target.value)} aria-label="Срок"><option value="30m">30 мин</option><option value="1h">1 ч</option><option value="2h">2 ч</option></select>
            <button className="btn" disabled={busy} onClick={() => void run(async () => setMsg((await api.post<{ output: string }>(`/api/v1/servers/${s.id}/relax`, { duration: dur })).output))}>Открыть</button>
            <button className="btn ghost" disabled={busy} onClick={() => void run(async () => setMsg((await api.post<{ output: string }>(`/api/v1/servers/${s.id}/relax`, { duration: 'off' })).output))}>Закрыть сейчас</button></div>
        </div>
        <div className="card pad stack">
          <h3>Аварийно отключить блокировки</h3>
          <span className="k">Удаляет таблицу firewall и снимает from=. VPN-пользователи подключаются без whitelist. Возврат — заново по протоколу.</span>
          <div><button className="btn danger" disabled={busy} onClick={() => { if (confirm('Снять все блокировки на узле?')) void run(async () => setMsg((await api.post<{ output: string }>(`/api/v1/servers/${s.id}/emergency-open`)).output)); }}>Отключить блокировки…</button></div>
        </div>
        <div className="card pad stack">
          <h3>Команда для KVM хостера</h3>
          <span className="k">Если панель потеряла доступ: войдите в консоль хостера как fleetadmin и наберите:</span>
          {d.kvmCommand ? <><code style={{ padding: '10px 12px', fontSize: 14 }}>{d.kvmCommand}</code><div><CopyButton text={d.kvmCommand} /></div></> : <span className="k">Сначала задайте адрес исполнителя.</span>}
        </div>
        <div className="card pad stack">
          <h3>Консольный пользователь fleetadmin</h3>
          <span className="k">Break-glass для консоли хостера. SSH-вход ему запрещён. Пароль покажется один раз — сохраните офлайн.</span>
          {fa ? <div className="alert warn">Логин <code>{fa.username}</code>, пароль <code>{fa.password}</code></div> :
            <div><button className="btn" disabled={busy} onClick={() => { if (confirm('Создать (или сменить пароль) fleetadmin?')) void run(async () => setFa(await api.post(`/api/v1/servers/${s.id}/fleetadmin`))); }}>Создать / сменить пароль</button></div>}
        </div>
      </div>
      {msg && <pre className="code">{msg}</pre>}
      <ErrorBox error={error} />
    </>
  );
}

// ───── хост ─────

function HostTab({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [st, setSt] = useState<{ output: string; xray: string; singbox: string; fwState: string; keyOnly: boolean } | null>(null);
  return (
    <div className="stack" style={{ gap: 16 }}>
      {s.ufw_active ? (
        <div className="card pad flex" style={{ justifyContent: 'space-between', background: 'var(--warn-bg)', borderColor: 'transparent' }}>
          <div className="row-text"><b style={{ color: 'var(--warn)' }}>ufw включён</b><span className="small">Активный ufw перебивает разрешения nftables. Для P2/P3 его выключают; правила сохранятся в baseline.</span></div>
          <button className="btn" disabled={busy} onClick={() => { if (confirm('Выключить ufw на узле? Его правила будут сохранены в baseline.')) void run(async () => { await api.post(`/api/v1/servers/${s.id}/ufw-disable`); onChange(); }); }}>Выключить ufw…</button>
        </div>
      ) : null}
      <section className="card pad stack">
        <div className="flex" style={{ justifyContent: 'space-between' }}>
          <h2>Состояние узла</h2>
          <button className="btn" disabled={busy || s.sudo_mode !== 'restricted'} onClick={() => void run(async () => setSt(await api.post(`/api/v1/servers/${s.id}/status`)))}>Обновить</button>
        </div>
        <div className="grid g4">
          <div className="card pad" style={{ background: 'var(--surface2)' }}><div className="k">Xray</div><b>{s.cores.xray?.version ?? 'не установлен'}</b></div>
          <div className="card pad" style={{ background: 'var(--surface2)' }}><div className="k">sing-box</div><b>{s.cores['sing-box']?.version ?? 'не установлен'}</b></div>
          <div className="card pad" style={{ background: 'var(--surface2)' }}><div className="k">SSH</div><b>{s.ssh_ports.join(', ') || '?'} · {s.key_only ? 'только ключи' : 'пароль разрешён'}</b></div>
          <div className="card pad" style={{ background: 'var(--surface2)' }}><div className="k">Связь</div><b>{ago(s.last_seen_at)}</b></div>
        </div>
        {st && <pre className="code">{st.output}{'\nfirewall: ' + st.fwState}{'\n\nxray:\n' + st.xray}{'\nsing-box:\n' + st.singbox}</pre>}
      </section>
      <CoresCard d={d} onChange={onChange} />
      <section className="card pad stack">
        <h2>Preflight</h2>
        <PreflightView d={d} onChange={onChange} />
      </section>
      <section className="card pad stack">
        <h2>Nodekit</h2>
        <NodekitStep d={d} onChange={onChange} />
        {s.kit_version === d.nodekitVersion && <span className="k">Версия актуальна: {s.kit_version}</span>}
      </section>
      <ErrorBox error={error} />
    </div>
  );
}

function CoresCard({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const [f, setF] = useState({ user: s.xui_user ?? '', pass: '' });
  const [msg, setMsg] = useState<string | null>(null);
  const { busy, error, run } = useAsync();
  const hasXui = s.external_cores.some((c) => c.name === '3x-ui');
  return (
    <section className="card pad stack">
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>Ядра</h2>
        <Tag kind="acc">{s.coreModeEffective === 'xui' ? 'Xray из 3x-ui' : 'свой Xray Эскадры'}</Tag>
      </div>
      <div className="flex">
        <span className="k">Найдено на узле:</span>
        {s.external_cores.length ? s.external_cores.map((c) => <Tag key={c.name} kind={c.active === 'active' ? 'info' : undefined}>{c.name}{c.version ? ` ${c.version}` : ''} · {c.active || '?'}</Tag>) : <span className="k">сторонних ядер нет (по данным preflight)</span>}
      </div>
      <div className="row" style={{ padding: '12px 0 0' }}>
        <div className="row-text"><b>Режим ядра</b><span className="k">Если на узле уже есть 3x-ui, Эскадра добавляет свои inbounds (пометка eskadra-…) в его Xray и не запускает второй. Вход («через вход») на таком узле недоступен.</span></div>
        <Seg value={s.core_mode} label="Режим ядра" onChange={(m) => void run(async () => { await api.post(`/api/v1/servers/${s.id}/core-mode`, { mode: m }); onChange(); })}
          options={[['auto', 'авто'], ['own', 'свой'], ['xui', 'через 3x-ui']]} />
      </div>
      {(s.coreModeEffective === 'xui' || hasXui) && (
        <form className="stack" onSubmit={(e) => { e.preventDefault(); void run(async () => { const r = await api.put<{ info: { port: number; version: string | null } }>(`/api/v1/servers/${s.id}/xui`, f); setMsg(`Вход в 3x-ui ${r.info.version ?? ''} проверен (панель 3x-ui на порту ${r.info.port}).`); setF({ ...f, pass: '' }); onChange(); }); }}>
          <h3>Доступ к 3x-ui {s.xuiConfigured && <Tag kind="ok">задан</Tag>}</h3>
          <span className="k">Логин и пароль 3x-ui нужны, чтобы управлять своими inbounds через его API. Запрос идёт с самого узла на 127.0.0.1; пароль хранится зашифрованным. Чужие inbounds 3x-ui не трогаются.</span>
          <div className="flex">
            <input className="inp" style={{ width: 200 }} value={f.user} onChange={(e) => setF({ ...f, user: e.target.value })} placeholder="логин 3x-ui" aria-label="Логин 3x-ui" autoComplete="off" />
            <input className="inp" type="password" style={{ width: 200 }} value={f.pass} onChange={(e) => setF({ ...f, pass: e.target.value })} placeholder="пароль 3x-ui" aria-label="Пароль 3x-ui" autoComplete="new-password" />
            <button className="btn" disabled={busy || !f.user || !f.pass}>Проверить и сохранить</button>
          </div>
        </form>
      )}
      {msg && <div className="alert ok">{msg}</div>}
      <ErrorBox error={error} />
    </section>
  );
}

export function JobsCard({ serverId, jobs }: { serverId?: string; jobs: Job[] }) {
  const [open, setOpen] = useState<Job | null>(null);
  const show = async (j: Job) => setOpen(open?.id === j.id ? null : await api.get<Job>(serverId ? `/api/v1/servers/${serverId}/jobs/${j.id}` : `/api/v1/jobs/${j.id}`));
  if (!jobs.length) return <div className="card empty">Задач пока не было</div>;
  return (
    <section className="card pad stack">
      <h2>Задачи</h2>
      {jobs.map((j) => (
        <div key={j.id}>
          <button className="link" onClick={() => void show(j)}>#{j.id} {j.kind}</button>{' '}
          <Tag kind={j.status === 'ok' ? 'ok' : j.status === 'failed' ? 'fail' : 'warn'}>{j.status}</Tag> <span className="k mono">{fmtTime(j.started_at)}</span>
          {open?.id === j.id && <pre className="code" style={{ marginTop: 8 }}>{open.log}</pre>}
        </div>
      ))}
    </section>
  );
}
