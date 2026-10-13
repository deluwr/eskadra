import { useEffect, useState, type ReactNode } from 'react';
import { HostStatsPanel } from '../HostStats';
import { ViaPicker, viaBody, viaOnly, viaReady, type Via } from '../ViaPicker';
import { api, ago, fmtTime, paidLeftText, ruDate, type Check, type Job, type Preflight, type Server, type ServerDetail } from '../api';
import { CopyBlock, CopyButton, ErrorBox, Info, Level, Modal, Seg, StagePip, StageHelp, Switch, Tag, RoleTag, useAsync, usePoll, ask, toast, LEVEL_LABEL, Addr } from '../ui';

type Tab = 'protect' | 'ports' | 'access' | 'sos' | 'host' | 'jobs';

export function ServerDetailPage({ id }: { id: string }) {
  const [fast, setFast] = useState(false);
  const { data: d, error, reload } = usePoll(() => api.get<ServerDetail>(`/api/v1/servers/${id}`), fast ? 2_000 : 15_000, [id]);
  useEffect(() => setFast(!!d?.onboarding.running || !!d?.server.config_dirty), [d?.onboarding.running, d?.server.config_dirty]);
  const [tab, setTab] = useState<Tab>('protect');
  if (!d) return <><ErrorBox error={error} />{!error && <p className="muted">Загрузка…</p>}</>;
  const s = d.server;
  // блок подключения виден, пока идёт настройка или если последняя попытка не удалась (в т. ч. на шаге ядер)
  const onboarding = s.stage < 2 || d.onboarding.running || d.onboarding.job?.status === 'failed';

  return (
    <>
      <div className="page-head">
        <div className="stack" style={{ gap: 6 }}>
          <a href="#/servers" className="k">← Серверы</a>
          <h1><ServerName id={s.id} name={s.name} onSaved={reload} /> <StagePip stage={s.stage} /><Info label="Что значат этапы"><StageHelp /></Info></h1>
          <span className="k">
            <Addr value={s.host} /> · <RoleTag s={s} /> · защита <Level value={s.protection_current} />
            <Info label="Подробности о сервере">
              SSH-порт {s.ssh_port} · группа {s.group_name} · {s.os_info?.pretty ?? 'ОС не определена'}<br />
              Канал: {s.mgmt_mode === 'tunnel' ? `туннель, порт ${s.mgmt.port}` : s.mgmt_mode === 'local' ? 'локально (это главный сервер)' : 'напрямую'}<br />
              {s.kit_version ? `nodekit ${s.kit_version}, ` : ''}{s.sudo_mode === 'restricted' ? 'sudo сужен до одной обёртки' : 'служебные скрипты ещё не установлены'}
            </Info>
          </span>
        </div>
        <HeaderActions d={d} onChange={reload} />
      </div>
      <ErrorBox error={error} />
      {s.fail_since && <div className="alert fail">Нет связи с сервером с {fmtTime(s.fail_since)}.{s.protection_target !== 'P1' ? ' Если сбой продлится дольше порога из настроек, проверку перед защитой придётся пройти заново.' : ''}</div>}
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

/** Имя сервера с переименованием по нажатию. */
function ServerName({ id, name, onSaved }: { id: string; name: string; onSaved: () => void }) {
  const [edit, setEdit] = useState(false);
  const [v, setV] = useState(name);
  const { busy, error, run } = useAsync();
  if (!edit) return <span className="flex" style={{ gap: 6, display: 'inline-flex' }}>{name}<button className="btn ghost sm" aria-label="Переименовать" onClick={() => { setV(name); setEdit(true); }}>✎</button></span>;
  return (
    <form className="flex" style={{ display: 'inline-flex' }} onSubmit={(e) => { e.preventDefault(); void run(async () => { await api.patch(`/api/v1/servers/${id}`, { name: v.trim() }); setEdit(false); toast('Имя сохранено'); onSaved(); }); }}>
      <input className="inp" style={{ width: 220, fontSize: 18 }} value={v} onChange={(e) => setV(e.target.value)} autoFocus maxLength={64} aria-label="Имя сервера" />
      <button className="btn sm pri" disabled={busy || !v.trim()}>Сохранить</button>
      <button type="button" className="btn ghost sm" onClick={() => setEdit(false)}>Отмена</button>
      {error && <span className="tag fail">{error}</span>}
    </form>
  );
}

function HeaderActions({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const { busy, error, run } = useAsync();
  const s = d.server;
  const del = async () => {
    if (!await ask('Удалить сервер из панели? На самом сервере ничего не изменится: пользователь fleet и ключ останутся.')) return;
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

// ───── подключение: всё делает панель ─────

const ONBOARD_STEPS = ['Первичный доступ', 'Вход ключом панели', 'Проверка сервера', 'Служебные скрипты и sudo', 'Ядра Xray и sing-box'];

function Onboarding({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const job = d.onboarding.job;
  const running = d.onboarding.running;
  const log = job?.log ?? '';
  const reached = Math.max(0, ...[...log.matchAll(/шаг (\d)\/5/g)].map((m) => Number(m[1])));
  const failed = !running && job?.status === 'failed';
  const err = failed ? (log.match(/ошибка: (.*)/g)?.pop()?.replace(/^ошибка: /, '') ?? 'неизвестная ошибка') : null;
  const [askAuth, setAskAuth] = useState(false);
  return (
    <section className="card pad stack" style={{ gap: 16 }}>
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>Подключение сервера</h2>
        {running && <Tag kind="info" dot>идёт настройка</Tag>}
      </div>
      {job ? (
        <ol className="onb">
          {ONBOARD_STEPS.map((t, i) => {
            const n = i + 1;
            const st = job.status === 'ok' || n < reached ? 'done' : n === reached ? (failed ? 'fail' : running ? 'cur' : 'done') : '';
            return <li key={t} className={st}><span className="onb-n">{st === 'done' ? '✓' : st === 'fail' ? '✕' : n}</span>{t}</li>;
          })}
        </ol>
      ) : <p className="small">Сервер добавлен без пароля. Выполните на нём команду ниже (под root), затем нажмите «Подключить» — остальное панель сделает сама.</p>}
      {err && <div className="alert fail">{err}</div>}
      {job && <details><summary className="k" style={{ cursor: 'pointer' }}>Журнал</summary><pre className="code">{log.trim()}</pre></details>}

      {!running && (failed || !job) && (
        <div className="stack">
          {/* первичный доступ прошёл, а туннель с главного сервера до узла не доходит — сервер недоступен из РФ целиком */}
          {failed && reached === 2 && s.mgmt_mode === 'tunnel' && !askAuth && (
            <div className="alert warn stack">
              <span>Туннель управления не дошёл до сервера. Если сервер недоступен из РФ целиком (а не только по SSH), пустите туннель через прокси за границей — например, через конфигурацию на другом выходе — и повторите.</span>
              <TunnelVia s={s} onSaved={() => void api.post(`/api/v1/servers/${s.id}/onboard`, {}).then(onChange)} saveLabel="Сохранить и повторить" />
            </div>
          )}
          {askAuth || (failed && reached <= 1)
            ? <AuthForm id={s.id} mgmtMode={s.mgmt_mode} onStarted={() => { setAskAuth(false); onChange(); }} />
            : <div className="flex">
                <ConnectButton id={s.id} label={job ? 'Повторить' : 'Подключить'} onStarted={onChange} />
                <button className="link" onClick={() => setAskAuth(true)}>{failed ? 'Начать заново с первичного доступа' : 'Ввести логин и пароль'}</button>
              </div>}
          <ManualSnippet d={d} open={!job} />
        </div>
      )}
    </section>
  );
}

function ConnectButton({ id, label, onStarted }: { id: string; label: string; onStarted: () => void }) {
  const { busy, error, run } = useAsync();
  return (
    <>
      <button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${id}/onboard`, {}); onStarted(); })}>{label}</button>
      <ErrorBox error={error} />
    </>
  );
}

/** Одноразовый доступ для повторной попытки: не сохраняется. */
function AuthForm({ id, mgmtMode, onStarted }: { id: string; mgmtMode: string; onStarted: () => void }) {
  const [f, setF] = useState({ user: 'root', method: 'password', password: '', privateKey: '' });
  const [via, setVia] = useState<Via>({ kind: 'direct' });
  const [channel, setChannel] = useState<'direct' | 'tunnel'>(mgmtMode === 'tunnel' ? 'tunnel' : 'direct');
  const { busy, error, run } = useAsync();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return (
    <form className="stack" autoComplete="off" onSubmit={(e) => {
      e.preventDefault();
      void run(async () => {
        if (mgmtMode !== 'local' && channel !== mgmtMode) await api.patch(`/api/v1/servers/${id}`, { mgmtMode: channel });
        const auth = { ...(f.method === 'password' ? { user: f.user, password: f.password } : { user: f.user, privateKey: f.privateKey }), ...viaBody(via) };
        await api.post(`/api/v1/servers/${id}/onboard`, { auth });
        onStarted();
      });
    }}>
      <div className="grid g4">
        <label className="fld">Логин<input className="inp mono" value={f.user} onChange={set('user')} /></label>
        <label className="fld">Вход по<select className="inp" value={f.method} onChange={set('method')}><option value="password">паролю</option><option value="key">SSH-ключу</option></select></label>
        {f.method === 'password' && <label className="fld" style={{ gridColumn: 'span 2' }}><span>Пароль <Info>Используется один раз и не сохраняется.</Info></span><input className="inp" type="password" value={f.password} onChange={set('password')} autoComplete="new-password" /></label>}
      </div>
      {f.method === 'key' && <label className="fld">Приватный ключ<textarea className="inp mono" rows={4} value={f.privateKey} onChange={set('privateKey')} spellCheck={false} /></label>}
      {mgmtMode !== 'local' && (
        <div className="stack" style={{ gap: 8 }}>
          <span className="k">Канал управления <Info>Как панель будет ходить на сервер после настройки. Туннель — если главный сервер в РФ: SSH идёт внутри VLESS-REALITY.</Info></span>
          <Seg value={channel} label="Канал управления" onChange={setChannel} options={[['direct', 'напрямую по SSH'], ['tunnel', 'через туннель']]} />
        </div>
      )}
      <ViaPicker value={via} onChange={(v) => { setVia(v); if (v.kind !== 'direct' && mgmtMode !== 'local') setChannel('tunnel'); }} exclude={id} mgmtMode={channel} />
      <div><button className="btn pri" disabled={busy || !(f.method === 'password' ? f.password : f.privateKey.trim()) || !viaReady(via)}>Подключить</button></div>
      <ErrorBox error={error} />
    </form>
  );
}

/** Запасной путь: команда, которую администратор выполняет на сервере сам (консоль хостера или свой SSH). */
function ManualSnippet({ d, open }: { d: ServerDetail; open: boolean }) {
  const s = d.server;
  if (!d.snippet) return <p className="k">Ручная команда для этого канала содержит ключ узла и доступна только администратору.</p>;
  const body = (
    <div className="stack">
      <div className="flex">
        <a className="btn sm" href={`api/v1/servers/${s.id}/bootstrap.sh`} download>Скачать скрипт</a>
        <Info>Выполните под root: в консоли хостера или по своему SSH. Скрипт только добавляет доступ панели и ничего не удаляет.{s.mgmt_mode === 'tunnel' ? ` Он также поставит служебный Xray на порту ${s.mgmt.port}/tcp — если у хостера свой firewall, откройте этот порт.` : ''}</Info>
      </div>
      <CopyBlock text={d.snippet} />
    </div>
  );
  return open ? body : <details><summary className="k" style={{ cursor: 'pointer' }}>Не получается подключиться? Выполнить команду на сервере вручную</summary>{body}</details>;
}

// ───── вкладка «Защита» ─────

/** Уровни защиты: что в каждый входит. Высокая включает всё из средней. */
const LEVELS = [
  { code: 'P1', name: 'Обычная', base: null, items: ['Сервер работает как есть, ничего не блокируется', 'Панель только следит за состоянием'] },
  { code: 'P2', name: 'Средняя', base: null, items: ['Закрыты все входящие порты, кроме нужных: SSH, порты конфигураций, связь между вашими серверами', 'На главном сервере открыты ещё панель и подписки'] },
  { code: 'P3', name: 'Высокая', base: 'Всё из средней, плюс:', items: ['SSH пускает только адреса панели и ваши админские адреса', 'Вход по SSH только по ключам — пароли выключаются'] },
] as const;

interface Plan { text: string; lint: string[]; warnings: string[]; summary: { level: string; stealth: string; sshPorts: number[]; svcTcp: number[]; svcUdp: number[]; panel: string[]; admin: string[]; peers: string[]; users: number } }

function ProtectTab({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  return (
    <div className="stack" style={{ gap: 20 }}>
      <section className="stack">
        <div className="flex" style={{ justifyContent: 'space-between' }}>
          <h2>Уровень защиты</h2>
          <span className="k">Сейчас: <Level value={s.protection_current} /></span>
        </div>
        <div className="grid g3">
          {LEVELS.map((l) => (
            <button key={l.code} className={`lvl ${s.protection_target === l.code ? 'on' : ''}`} aria-pressed={s.protection_target === l.code} disabled={busy}
              onClick={() => void run(async () => { await api.patch(`/api/v1/servers/${s.id}`, { protectionTarget: l.code }); toast(`Уровень защиты: ${LEVEL_LABEL[l.code] ?? l.code}`); onChange(); })}>
              <span style={{ fontSize: 17, fontWeight: 600 }}>{l.name}</span>
              {l.base && <span className="k">{l.base}</span>}
              <span className="stack" style={{ gap: 6 }}>{l.items.map((x) => <span key={x} className="ctl"><span style={{ width: 14, color: 'var(--ok)', fontWeight: 700 }}>✓</span>{x}</span>)}</span>
            </button>
          ))}
        </div>
        <ErrorBox error={error} />
      </section>
      {s.protection_target !== 'P1' && <ProtectSteps d={d} onChange={onChange} />}
    </div>
  );
}

/** Включение средней/высокой защиты: проверка доступа → пробный режим → включение с автоматическим откатом. */
function ProtectSteps({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [win, setWin] = useState(120);
  const [report, setReport] = useState<Array<{ flow: string; count: number }> | null>(null);
  // план правил строится сам — пользователь видит только найденные проблемы
  const { data: plan } = usePoll(() => api.post<Plan>(`/api/v1/servers/${s.id}/fw/plan`, {}), null, [s.protection_target, s.fw_mode, s.checklist_passed_at]);
  const passed = !!d.checklist.passedAt;
  const trial = s.fw_mode === 'shadow';
  const enforced = s.fw_mode === 'enforced' && s.protection_current === s.protection_target;
  const blocked = !!plan?.lint.length || !!s.ufw_active;

  if (enforced) return (
    <section className="card pad stack">
      <div className="alert ok">Защита «{LEVELS.find((l) => l.code === s.protection_target)?.name.toLowerCase()}» включена.</div>
      {s.protection_target === 'P3' && <KeyOnly d={d} onChange={onChange} />}
    </section>
  );

  return (
    <section className="card pad stack" style={{ gap: 18 }}>
      <h2>Как включить</h2>
      {s.ufw_active ? <div className="alert warn">На сервере включён ufw/firewalld — он мешает правилам Эскадры. Выключите его на вкладке «Хост».</div> : null}
      {plan?.lint.map((l) => <div key={l} className="alert fail">{l}</div>)}

      <div className="stack" style={{ gap: 8 }}>
        <h3>1. Проверьте, что не потеряете доступ <Info>Отметьте то, что проверили сами. Пункты с пометкой «авто» панель проверяет сама.</Info></h3>
        <Checklist d={d} onChange={onChange} />
      </div>

      <div className="stack" style={{ gap: 8 }}>
        <h3>2. Пробный режим (по желанию) <Info>Правила ставятся, но ничего не блокируют: сервер только записывает, кого бы он отрезал. Оставьте на несколько часов, затем посмотрите отчёт — если там ваши адреса или нужные сервисы, значит, что-то не учтено.</Info></h3>
        <div className="flex">
          {trial ? <Tag kind="info" dot>пробный режим включён</Tag>
            : <button className="btn" disabled={busy || blocked} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/fw/shadow`, {}); onChange(); })}>Включить пробный режим</button>}
          {trial && <button className="btn" disabled={busy} onClick={() => void run(async () => setReport((await api.get<{ top: Array<{ flow: string; count: number }> }>(`/api/v1/servers/${s.id}/fw/shadow-log?minutes=1440`)).top))}>Показать отчёт пробного режима</button>}
        </div>
        {report && (report.length
          ? <><span className="small">За последние сутки защита отрезала бы эти подключения (источник → порт, число попыток):</span><pre className="code">{report.map((h) => `${String(h.count).padStart(6)}  ${h.flow}`).join('\n')}</pre></>
          : <div className="alert ok">За последние сутки защита никого бы не отрезала — можно включать.</div>)}
      </div>

      <div className="stack" style={{ gap: 8 }}>
        <h3>3. Включите защиту <Info>Правила включаются с таймером: если за выбранное время вы не подтвердите, что доступ к серверу есть, сервер сам вернёт всё как было.</Info></h3>
        <div className="flex">
          <label className="flex small">время на проверку
            <select className="inp" style={{ width: 'auto' }} value={win} onChange={(e) => setWin(Number(e.target.value))} aria-label="Время на проверку"><option value={120}>2 минуты</option><option value={300}>5 минут</option><option value={600}>10 минут</option></select>
          </label>
          <button className="btn pri" disabled={busy || !passed || blocked} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/fw/apply`, { window: win }); onChange(); })}>Включить защиту</button>
        </div>
        {!passed && <span className="k">Сначала отметьте пункты шага 1.</span>}
      </div>

      {plan && (
        <details>
          <summary className="k" style={{ cursor: 'pointer' }}>Технические подробности правил</summary>
          <div className="stack" style={{ paddingTop: 8 }}>
            {plan.warnings.map((w) => <div key={w} className="alert warn small">{w}</div>)}
            <span className="k">SSH {plan.summary.sshPorts.join(', ')} · адреса панели {plan.summary.panel.join(', ') || '—'} · админы {plan.summary.admin.join(', ') || '—'} · серверов флота {plan.summary.peers.length} · порты TCP {plan.summary.svcTcp.join(', ') || '—'} · UDP {plan.summary.svcUdp.join(', ') || '—'}</span>
            <CopyBlock text={plan.text} />
          </div>
        </details>
      )}
      <ErrorBox error={error} />
    </section>
  );
}

function Checklist({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const [marks, setMarks] = useState<Record<string, boolean>>(() => Object.fromEntries(d.checklist.items.filter((i) => !i.auto).map((i) => [i.id, i.done])));
  const { busy, error, run } = useAsync();
  const done = d.checklist.items.filter((i) => (i.auto ? i.done : marks[i.id])).length;
  return (
    <div className="stack" style={{ gap: 4 }}>
      <span className="k">{done} из {d.checklist.total}{d.checklist.passedAt ? ' · пройдено' : ''}</span>
      {d.checklist.items.map((i) => (
        <label key={i.id} className="cb" style={{ borderTop: '1px solid var(--line)', padding: '6px 0', alignItems: 'flex-start' }}>
          <input type="checkbox" disabled={i.auto} checked={i.auto ? i.done : !!marks[i.id]} onChange={(e) => setMarks({ ...marks, [i.id]: e.target.checked })} />
          <span>{i.title}{i.auto && <span className="k"> · авто</span>}</span>
        </label>
      ))}
      <div className="flex" style={{ marginTop: 8 }}><button className="btn" disabled={busy} onClick={() => void run(async () => { await api.put(`/api/v1/servers/${d.server.id}/checklist`, marks); onChange(); })}>Сохранить отметки</button></div>
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
      <div className="row-text"><b>Вход по SSH только по ключам <Info>Пароли для SSH выключаются. Включается с таймером: если за 3 минуты не подтвердить, что вход работает, сервер вернёт как было. Включайте, только если входите на сервер своим ключом.</Info></b></div>
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
  const patch = (body: object) => run(async () => { await api.patch(`/api/v1/servers/${s.id}`, body); toast('Сохранено'); onChange(); });
  return (
    <section className="card">
      <div className="card-head"><h2>Доступ и SSH</h2></div>
      <div className="row">
        <div className="row-text"><b>Админские адреса</b><span className="k">Пускаются по SSH на уровне P3. Если адрес неизвестен — «Временно открыть SSH» на вкладке «Аварийный доступ».</span></div>
        <div className="flex">
          {s.admin_ips.map((a) => <span key={a} className="tag"><Addr value={a} /> <button className="link" aria-label={`убрать ${a}`} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/admin-ips`, { ip: a, remove: true }); onChange(); })}>×</button></span>)}
          <input className="inp mono" style={{ width: 170 }} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="198.51.100.20" aria-label="Новый админский адрес" />
          <button className="btn" disabled={busy || !ip} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/admin-ips`, { ip }); setIp(''); onChange(); })}>Добавить</button>
        </div>
      </div>
      <div className="row">
        <div className="row-text"><b>Терминал (shell) в панели</b><span className="k">{s.ssh_mode === 'shell' ? 'Включён: ключ панели без forced command, широкий sudo.' : 'Выключен — ключ панели принудительно идёт через fleet-exec (строгий режим). Всё управление работает и без shell.'}</span></div>
        <Switch label="Терминал" on={s.ssh_mode === 'shell'} disabled={busy || s.sudo_mode !== 'restricted'} onChange={(v) => void run(async () => { await api.post(`/api/v1/servers/${s.id}/ssh-mode`, { mode: v ? 'shell' : 'strict' }); onChange(); })} />
      </div>
      {s.ssh_mode === 'shell' && <Terminal id={s.id} />}
      <MgmtRow d={d} onChange={onChange} />
      <div className="row">
        <div className="row-text"><b>Прямой доступ пользователей <Info>Пользователи подключаются к этому серверу напрямую, а не только через вход: профиль «{s.name} · напрямую» попадает в подписки.</Info></b></div>
        <span className="flex">
          {(busy || !!s.config_dirty) && <Tag kind="info" dot>применяется на сервере…</Tag>}
          <Switch label="Прямой доступ" on={!!s.direct_access} onChange={(v) => void patch({ directAccess: v })} />
        </span>
      </div>
      <div className="row">
        <div className="row-text"><b>SSH между нодами</b><span className="k">emergency: только проверка связи, allow нового IP панели и временное открытие SSH.</span></div>
        <Seg value={s.peer_ssh as 'off' | 'emergency'} label="SSH между нодами" options={[['off', 'выключен'], ['emergency', 'emergency']]} onChange={(v) => void patch({ peerSsh: v })} />
      </div>
      <PaidRow s={s} onSave={(body) => void patch(body)} busy={busy} />
      <div className="row">
        <div className="row-text"><b>Роль и группа <Info>Relay (вход) принимает пользователей и может пересылать их на выходы; выход выпускает трафик в интернет. Группа задаёт политику: скрытность портов, связь между нодами, диапазон портов — настраивается в «Портах и связности».</Info></b></div>
        <div className="flex">
          <select className="inp" style={{ width: 'auto' }} value={s.role === 'exit' ? 'exit' : 'entry'} onChange={(e) => void patch({ role: e.target.value })} aria-label="Роль"><option value="entry">Relay</option><option value="exit">Выход</option></select>
          <GroupSelect value={s.group_name} onSave={(g) => void patch({ group: g })} />
        </div>
      </div>
      <div style={{ padding: '0 20px 14px' }}><ErrorBox error={error} /></div>
    </section>
  );
}

/** Канал управления (§5.8): напрямую или через служебный туннель. Смена требует повторного сниппета на узле. */
/** Прокси туннеля управления: цепочка панель → прокси → туннель сервера (сервер недоступен из РФ целиком). */
function TunnelVia({ s, onSaved, saveLabel = 'Сохранить' }: { s: Server; onSaved: () => void; saveLabel?: string }) {
  const [v, setV] = useState<Via>({ kind: 'direct' });
  const { busy, error, run } = useAsync();
  return (
    <div className="stack" style={{ gap: 10 }}>
      <ViaPicker value={v} onChange={setV} exclude={s.id} mgmtMode="tunnel" mode="tunnel" />
      <div className="flex">
        <button className="btn pri sm" disabled={busy || !viaReady(v)} onClick={() => void run(async () => { await api.patch(`/api/v1/servers/${s.id}`, { mgmtVia: viaOnly(v) }); toast(v.kind === 'direct' ? 'Туннель идёт напрямую' : 'Туннель пойдёт через прокси'); onSaved(); })}>{saveLabel}</button>
        {s.mgmt.via && <span className="k">{`сейчас: через ${s.mgmt.via}`}</span>}
      </div>
      <ErrorBox error={error} />
    </div>
  );
}

function MgmtRow({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [ask, setAsk] = useState<'direct' | 'tunnel' | null>(null);
  const [switched, setSwitched] = useState(false);
  const st = s.mgmt.client;
  if (s.mgmt_mode === 'local') return (
    <div className="row"><div className="row-text"><b>Канал управления</b><span className="k">Локально: это главный сервер, панель ходит на свой же SSH.</span></div></div>
  );
  const mode = s.mgmt_mode;
  return (
    <div className="row stack" style={{ alignItems: 'stretch' }}>
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <div className="row-text">
          <b>Канал управления</b>
          <span className="k">
            {s.mgmt_mode === 'tunnel'
              ? <>SSH панели идёт внутри VLESS-REALITY: порт узла <code>{s.mgmt.port}/tcp</code>, маскировка под <code>{s.mgmt.sni}</code>{s.mgmt.via ? <>, цепочкой через <b>{s.mgmt.via}</b></> : ''}. {st ? (st.running ? `Клиент туннелей работает (Xray ${st.version ?? '?'}).` : st.error ? `Клиент туннелей: ${st.error}` : 'Клиент туннелей запустится при первом подключении.') : ''}</>
              : 'SSH напрямую с адреса главного сервера. Если главный сервер в РФ и SSH режется — переключите на туннель.'}
          </span>
        </div>
        <Seg value={mode} label="Канал управления" options={[['direct', 'напрямую'], ['tunnel', 'туннель']]} onChange={(v) => setAsk(v === mode ? null : v)} />
      </div>
      {ask && (
        <div className="alert warn stack">
          <span>После переключения панель перенастроит доступ к серверу — понадобится его логин и пароль (один раз). Пока это не сделано, управление сервером недоступно; VPN пользователей это не затрагивает.</span>
          <div className="flex">
            <button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.patch(`/api/v1/servers/${s.id}`, { mgmtMode: ask }); setAsk(null); setSwitched(true); onChange(); })}>Переключить</button>
            <button className="btn ghost" onClick={() => setAsk(null)}>Отмена</button>
          </div>
        </div>
      )}
      {mode === 'tunnel' && !ask && <details className="more"><summary>{s.mgmt.via ? 'Изменить прокси туннеля' : 'Сервер недоступен из РФ целиком? Пустить туннель через прокси'}</summary><div style={{ marginTop: 10 }}><TunnelVia s={s} onSaved={onChange} /></div></details>}
      {switched && (
        <div className="stack">
          <b className="small">Перенастроить доступ</b>
          <AuthForm id={s.id} mgmtMode={s.mgmt_mode} onStarted={() => { setSwitched(false); onChange(); }} />
          <ManualSnippet d={d} open={false} />
        </div>
      )}
      <ErrorBox error={error} />
    </div>
  );
}

/** Группа сервера — из существующих; новые создаются в «Портах и связности». */
function GroupSelect({ value, onSave }: { value: string; onSave: (v: string) => void }) {
  const { data } = usePoll(() => api.get<Array<{ name: string }>>('/api/v1/groups'), null);
  return (
    <span className="flex" style={{ gap: 6 }}>
      <select className="inp" style={{ width: 'auto' }} value={value} onChange={(e) => onSave(e.target.value)} aria-label="Группа">
        {(data ?? [{ name: value }]).map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
      </select>
      <a className="k" href="#/ports">настроить группы</a>
    </span>
  );
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
          <div><button className="btn danger" disabled={busy} onClick={async () => { if (await ask('Снять все блокировки на узле?')) void run(async () => setMsg((await api.post<{ output: string }>(`/api/v1/servers/${s.id}/emergency-open`)).output)); }}>Отключить блокировки…</button></div>
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
            <div><button className="btn" disabled={busy} onClick={async () => { if (await ask('Создать (или сменить пароль) fleetadmin?')) void run(async () => setFa(await api.post(`/api/v1/servers/${s.id}/fleetadmin`))); }}>Создать / сменить пароль</button></div>}
        </div>
      </div>
      {msg && <pre className="code">{msg}</pre>}
      <ErrorBox error={error} />
    </>
  );
}

// ───── хост ─────

const certName = (n: string) => (n === 'ip' ? 'На IP сервера' : n.startsWith('dom-') ? n.slice(4) : n.startsWith('tpl-') ? 'Загруженный' : n);

/** TLS-сертификаты узла: Let's Encrypt продлевает сам узел; здесь — сроки, результат продления, ручной запуск. */
function CertsCard({ s, onChange }: { s: Server; onChange: () => void }) {
  const { busy, error, run } = useAsync();
  const st = s.tls_state;
  const act = (a: 'check' | 'renew') => run(async () => { await api.post(`/api/v1/servers/${s.id}/certs/${a}`); toast(a === 'renew' ? 'Продление выполнено — результат ниже' : 'Сертификаты проверены'); onChange(); });
  return (
    <section className="card pad stack">
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>TLS-сертификаты <Info>Let's Encrypt продлевает сам сервер: таймер дважды в сутки, сертификат на IP — за 3 дня до конца, на домен — за 30. Панель проверяет сроки каждые 3 часа и пишет в бот, если продление не удалось или срок подходит к концу. Для продления нужен открытый снаружи порт 80.</Info></h2>
        <span className="flex">
          <button className="btn sm" disabled={busy || s.sudo_mode !== 'restricted'} onClick={() => void act('check')}>Проверить</button>
          {st?.certs.some((c) => c.le) && <button className="btn sm" disabled={busy} onClick={() => void act('renew')}>{busy ? 'Продлеваю…' : 'Продлить сейчас'}</button>}
        </span>
      </div>
      {s.certProblems.map((p) => <div key={p.key} className={`alert ${p.level}`}><b>{p.title}</b><br />{p.detail}</div>)}
      {!st ? <span className="k">Ещё не проверялись. Сертификаты появляются у конфигураций с TLS и Hysteria2.</span> : !st.certs.length ? <span className="k">На сервере нет TLS-сертификатов Эскадры.</span> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Сертификат</th><th>Действует до</th><th>Продление</th></tr></thead>
            <tbody>{st.certs.map((c) => (
              <tr key={c.name}>
                <td><b>{certName(c.name)}</b></td>
                <td className="mono small">{c.notAfter ? fmtTime(c.notAfter) : '?'}</td>
                <td>{c.le ? (st.timer ? <Tag kind="ok">сам, Let's Encrypt</Tag> : <Tag kind="warn">таймер выключен</Tag>) : <Tag>вручную</Tag>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {st?.renew && <span className="k">{`Последнее продление: ${fmtTime(st.renew.at)}`} · {st.renew.code === 0 ? 'успешно' : `ошибка: ${st.renew.err || 'certbot завершился с ошибкой'}`} · {`проверено ${ago(st.checkedAt)}`}</span>}
      <ErrorBox error={error} />
    </section>
  );
}

function HostTab({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const [st, setSt] = useState<{ output: string; xray: string; singbox: string; fwState: string; keyOnly: boolean } | null>(null);
  return (
    <div className="stack" style={{ gap: 16 }}>
      {s.ufw_active ? (
        <div className="card pad flex" style={{ justifyContent: 'space-between', background: 'var(--warn-bg)', borderColor: 'transparent' }}>
          <div className="row-text"><b style={{ color: 'var(--warn)' }}>Firewall хоста включён (ufw/firewalld)</b><span className="small">Активный ufw или firewalld перебивает разрешения nftables. Для P2/P3 его выключают; правила сохранятся в baseline.</span></div>
          <button className="btn" disabled={busy} onClick={async () => { if (await ask('Выключить firewall хоста (ufw/firewalld) на узле? Его правила будут сохранены в baseline.')) void run(async () => { await api.post(`/api/v1/servers/${s.id}/ufw-disable`); onChange(); }); }}>Выключить firewall хоста…</button>
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
      {s.sudo_mode === 'restricted' && <section className="card pad stack"><h2>Нагрузка <span className="k" style={{ fontWeight: 400 }}>вживую</span></h2><HostStatsPanel url={`/api/v1/servers/${s.id}/stats`} pollMs={s.mgmt_mode === 'local' ? 3000 : 5000} /></section>}
      <CoresCard d={d} onChange={onChange} />
      <CertsCard s={s} onChange={onChange} />
      <section className="card pad stack">
        <h2>Проверка сервера <Info>Снимок только для чтения: ОС, SSH, firewall, занятые порты, сторонние ядра. Ничего не меняет.</Info></h2>
        <PreflightView d={d} onChange={onChange} />
      </section>
      <section className="card pad stack">
        <h2>Служебные скрипты <Info>Nodekit — скрипты панели на узле: обёртка sudo, установщик ядер, страховочный откат firewall.</Info></h2>
        {s.kit_version === d.nodekitVersion ? <span className="k">Версия актуальна: {s.kit_version}</span> : <NodekitStep d={d} onChange={onChange} />}
      </section>
      <ErrorBox error={error} />
    </div>
  );
}

const ICON: Record<Check['status'], string> = { ok: '✓', warn: '!', fail: '✕', info: 'i' };

/** Снимок сервера (только чтение): что найдено и есть ли проблемы. */
function PreflightView({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const [p, setP] = useState<Preflight | null>(d.preflight);
  const { busy, error, run } = useAsync();
  return (
    <>
      <div className="flex">
        <button className="btn" disabled={busy} onClick={() => void run(async () => { setP(await api.post<Preflight>(`/api/v1/servers/${d.server.id}/preflight`)); onChange(); })}>{busy ? 'Проверяю…' : 'Проверить заново'}</button>
        {p?.created_at && <span className="k">последняя: {fmtTime(p.created_at)}</span>}
      </div>
      {p && (
        <ul className="checks">
          {p.checks.map((c) => <li key={c.id} className={`check ${c.status}`}><span className="ci" aria-label={c.status}>{ICON[c.status]}</span><b className="small">{c.title}</b><span className="small muted">{c.detail}</span></li>)}
        </ul>
      )}
      <ErrorBox error={error} />
    </>
  );
}

/** Обновление служебных скриптов на узле, если вышла новая версия. */
function NodekitStep({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  if (s.sudo_mode === 'restricted' && s.kit_version === d.nodekitVersion) return null;
  return (
    <>
      <div><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/nodekit/install`); onChange(); })}>{busy ? 'Обновляю…' : `Обновить до ${d.nodekitVersion}`}</button></div>
      <ErrorBox error={error} />
    </>
  );
}

/** Свои ядра на узле: версия или «не установлено» с кнопкой установки. */
type CoreState = Record<string, { active: boolean; manualOff: boolean }>;

function CoreRows({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const { busy, error, run } = useAsync();
  const managed = s.sudo_mode === 'restricted';
  const { data: state, setData: setState } = usePoll(() => (managed ? api.get<CoreState>(`/api/v1/servers/${s.id}/cores/state`) : Promise.resolve({} as CoreState)), null, [s.id]);
  const rows: Array<['xray' | 'sing-box' | 'telemt', string]> = [['xray', 'Xray'], ['sing-box', 'sing-box'], ['telemt', 'telemt (MTProto)']];
  const power = async (core: string, label: string, on: boolean) => {
    if (!on && !(await ask(`Остановить ${label} на ${s.name}? Пользователи, подключённые к этому серверу напрямую или через него, потеряют связь, пока ядро не запустят снова. Панель не запустит его сама — даже при выкате конфигурации.`))) return;
    void run(async () => {
      const r = await api.post<{ state: CoreState }>(`/api/v1/servers/${s.id}/cores/${core}/power`, { on });
      setState(r.state);
      toast(on ? `${label} запущен` : `${label} остановлен — «Авто» перепроверяет выходы`);
      onChange();
    });
  };
  return (
    <div className="stack">
      {rows.map(([core, label]) => {
        const v = s.cores[core]?.version;
        const xui = core === 'xray' && s.coreModeEffective === 'xui';
        const st = state?.[core];
        if (core === 'telemt' && !v && !st) return null;
        return (
          <div key={core} className="flex" style={{ justifyContent: 'space-between' }}>
            <span className="flex" style={{ gap: 8 }}>
              <b>{label}</b><span className="k">{xui ? `из 3x-ui${s.cores.xui?.version ? ' ' + s.cores.xui.version : ''}` : v ? v : 'не установлено'}</span>
              {st && (st.active ? <Tag kind="ok" dot>работает</Tag> : <Tag kind={st.manualOff ? 'warn' : 'fail'} dot>{st.manualOff ? 'остановлен вручную' : 'не работает'}</Tag>)}
            </span>
            <span className="flex" style={{ gap: 6 }}>
              {!xui && !v && managed && (
                <button className="btn sm" disabled={busy} onClick={() => void run(async () => { await api.post(`/api/v1/servers/${s.id}/cores/${core}/update`, {}); onChange(); })}>{busy ? 'Ставлю…' : 'Установить'}</button>
              )}
              {!xui && st && (st.active
                ? <button className="btn sm" disabled={busy} onClick={() => void power(core, label, false)}>Остановить</button>
                : <button className="btn sm pri" disabled={busy} onClick={() => void power(core, label, true)}>Запустить</button>)}
            </span>
          </div>
        );
      })}
      <span className="k">Остановка ядра — например, чтобы проверить, что профиль «вход → авто» уходит на другой выход. Остановленное вручную ядро остаётся выключенным, пока его не запустят здесь.</span>
      <ErrorBox error={error} />
    </div>
  );
}

function CoresCard({ d, onChange }: { d: ServerDetail; onChange: () => void }) {
  const s = d.server;
  const [f, setF] = useState({ by: s.xui_user === '@token' ? 'token' : 'password', user: s.xui_user === '@token' ? '' : s.xui_user ?? '', pass: '', token: '' });
  const [msg, setMsg] = useState<string | null>(null);
  const { busy, error, run } = useAsync();
  const hasXui = s.external_cores.some((c) => c.name === '3x-ui');
  return (
    <section className="card pad stack">
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>Ядра</h2>
        <Tag kind="acc">{s.coreModeEffective === 'xui' ? 'Xray из 3x-ui' : 'свой Xray Эскадры'}</Tag>
      </div>
      <CoreRows d={d} onChange={onChange} />
      <div className="flex">
        <span className="k">Найдено на узле:</span>
        {s.external_cores.length ? s.external_cores.map((c) => <Tag key={c.name} kind={c.active === 'active' ? 'info' : undefined}>{c.name}{c.version ? ` ${c.version}` : ''} · {c.active || '?'}</Tag>) : <span className="k">сторонних ядер нет (по данным preflight)</span>}
      </div>
      <div className="row" style={{ padding: '12px 0 0' }}>
        <div className="row-text"><b>Режим ядра</b><span className="k">Если на узле уже есть 3x-ui, Эскадра добавляет свои inbounds (пометка eskadra-…) в его Xray и не запускает второй. Вход («через вход») на таком узле недоступен.</span></div>
        <Seg value={s.core_mode} label="Режим ядра" onChange={(m) => void run(async () => { await api.post(`/api/v1/servers/${s.id}/core-mode`, { mode: m }); onChange(); })}
          options={[['auto', 'авто'], ['own', 'свой'], ['xui', 'через 3x-ui']]} />
      </div>
      {s.sudo_mode === 'restricted' && (hasXui || s.external_cores.some((c) => ['xray', 'sing-box', 'v2ray', 'hysteria-server'].includes(c.name) && c.active === 'active')) && (
        <div className="row" style={{ padding: '12px 0 0' }}>
          <div className="row-text"><b>Конфликт ядер</b><span className="k">Дополнить — оставить как есть (Эскадра не запустит второе ядро того же типа). Удалить 3x-ui — его база сохранится в baseline узла, пользователи 3x-ui потеряют доступ.</span></div>
          <div className="flex">
            {hasXui && <button className="btn danger" disabled={busy} onClick={async () => { if (await ask('Удалить 3x-ui с узла? Его пользователи потеряют доступ; база сохранится в /var/lib/fleet/baseline.')) void run(async () => { setMsg((await api.post<{ output: string }>(`/api/v1/servers/${s.id}/xui-remove`)).output); onChange(); }); }}>Удалить 3x-ui</button>}
            {s.external_cores.filter((c) => ['xray', 'sing-box', 'v2ray', 'hysteria-server'].includes(c.name) && c.active === 'active').map((c) => (
              <button key={c.name} className="btn" disabled={busy} onClick={async () => { if (await ask(`Остановить и отключить ${c.name}.service? Файлы не удаляются.`)) void run(async () => { setMsg((await api.post<{ output: string }>(`/api/v1/servers/${s.id}/foreign-stop`, { name: c.name })).output); onChange(); }); }}>Остановить {c.name}</button>
            ))}
          </div>
        </div>
      )}
      {(s.coreModeEffective === 'xui' || hasXui) && (
        <form className="stack" onSubmit={(e) => { e.preventDefault(); void run(async () => { const r = await api.put<{ info: { port: number; version: string | null } }>(`/api/v1/servers/${s.id}/xui`, f.by === 'token' ? { token: f.token } : { user: f.user, pass: f.pass }); setMsg(`Вход в 3x-ui ${r.info.version ?? ''} проверен (панель 3x-ui на порту ${r.info.port}).`); setF({ ...f, pass: '', token: '' }); onChange(); }); }}>
          <h3>Доступ к 3x-ui {s.xuiConfigured && <Tag kind="ok">задан</Tag>}</h3>
          <span className="k">Логин и пароль или API-токен 3x-ui нужны, чтобы управлять своими inbounds через его API. Запрос идёт с самого узла на 127.0.0.1; секрет хранится зашифрованным. Чужие inbounds 3x-ui не трогаются.</span>
          <Seg value={f.by} label="Вход в 3x-ui" onChange={(v) => setF({ ...f, by: v })} options={[['password', 'логин и пароль'], ['token', 'API-токен']]} />
          <div className="flex">
            {f.by === 'password' ? <>
              <input className="inp" style={{ width: 200 }} value={f.user} onChange={(e) => setF({ ...f, user: e.target.value })} placeholder="логин 3x-ui" aria-label="Логин 3x-ui" autoComplete="off" />
              <input className="inp" type="password" style={{ width: 200 }} value={f.pass} onChange={(e) => setF({ ...f, pass: e.target.value })} placeholder="пароль 3x-ui" aria-label="Пароль 3x-ui" autoComplete="new-password" />
            </> : <input className="inp mono" type="password" style={{ width: 420, maxWidth: '100%' }} value={f.token} onChange={(e) => setF({ ...f, token: e.target.value.trim() })} placeholder="API-токен из настроек 3x-ui" aria-label="API-токен 3x-ui" autoComplete="off" />}
            <button className="btn" disabled={busy || (f.by === 'token' ? f.token.length < 8 : !f.user || !f.pass)}>Проверить и сохранить</button>
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
  const [all, setAll] = useState(false);
  const show = async (j: Job) => setOpen(await api.get<Job>(serverId ? `/api/v1/servers/${serverId}/jobs/${j.id}` : `/api/v1/jobs/${j.id}`));
  if (!jobs.length) return <div className="card empty">Задач пока не было</div>;
  const LIMIT = 10;
  const tag = (j: Job) => <Tag kind={j.status === 'ok' ? 'ok' : j.status === 'failed' ? 'fail' : 'warn'}>{j.status}</Tag>;
  return (
    <section className="card">
      <div className="card-head"><h2>Задачи</h2><span className="k">журнал задачи открывается поверх страницы</span></div>
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table>
          <thead><tr><th>Задача</th><th>Состояние</th><th>Начата</th></tr></thead>
          <tbody>{(all ? jobs : jobs.slice(0, LIMIT)).map((j) => (
            <tr key={j.id} className="clickable" onClick={() => void show(j)}><td><span className="mono small">#{j.id}</span> {j.kind}</td><td>{tag(j)}</td><td className="k mono">{fmtTime(j.started_at)}</td></tr>
          ))}</tbody>
        </table>
      </div>
      {jobs.length > LIMIT && <div className="row"><button className="btn ghost sm" onClick={() => setAll(!all)}>{all ? 'Свернуть' : `Показать все (${jobs.length})`}</button></div>}
      {open && <Modal size="lg" title={`Задача #${open.id} · ${open.kind}`} head={tag(open)} onClose={() => setOpen(null)}><pre className="code">{open.log}</pre></Modal>}
    </section>
  );
}

/** Срок оплаты сервера: до какого дня оплачен и за сколько дней напоминать (бот и баннер в панели). */
function PaidRow({ s, onSave, busy }: { s: Server; onSave: (body: { paidUntil: string | null; paidWarnDays?: number }) => void; busy: boolean }) {
  const [date, setDate] = useState(s.paid_until ?? '');
  const [warn, setWarn] = useState(String(s.paid_warn_days || 5));
  useEffect(() => { setDate(s.paid_until ?? ''); setWarn(String(s.paid_warn_days || 5)); }, [s.paid_until, s.paid_warn_days]);
  const changed = date !== (s.paid_until ?? '') || Number(warn) !== (s.paid_warn_days || 5);
  const left = s.paidDaysLeft;
  return (
    <div className="row">
      <div className="row-text"><b>Оплачен до <Info>Последний оплаченный день у хостера. За указанное число дней до конца бот раз в день напоминает админам (категория «Оплата серверов»), а в панели появляется баннер; после окончания срока — ещё три дня напоминаний. Продлили — поставьте новую дату.</Info></b>
        <span className="k">{s.paid_until ? `${ruDate(s.paid_until)}${left !== null ? ` · ${paidLeftText(left)}` : ''}` : 'Не указано — срок оплаты не отслеживается.'}</span></div>
      <div className="flex">
        <input className="inp mono" type="date" style={{ width: 'auto' }} value={date} onChange={(e) => setDate(e.target.value)} aria-label="Оплачен до" />
        <label className="flex small" style={{ gap: 6 }}>напомнить за<input className="inp mono" style={{ width: 60 }} inputMode="numeric" value={warn} onChange={(e) => setWarn(e.target.value.replace(/\D/g, ''))} aria-label="Напомнить за, дней" />дн.</label>
        <button className="btn" disabled={busy || !changed || (!!date && !/^\d{4}-\d{2}-\d{2}$/.test(date))} onClick={() => onSave({ paidUntil: date || null, paidWarnDays: Math.min(60, Math.max(1, Number(warn) || 5)) })}>Сохранить</button>
        {s.paid_until && <button className="btn ghost sm" disabled={busy} onClick={() => onSave({ paidUntil: null })}>Не следить</button>}
      </div>
    </div>
  );
}
