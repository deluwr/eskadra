import { useState } from 'react';
import { api, fmtTime } from '../api';
import { CopyButton, ErrorBox, Switch, Tag, TgBind, toast, useAsync, usePoll, ask, Addr } from '../ui';
import type { AuthState } from '../App';
import { RolesCard, type RolesData } from './Roles';

interface Admin { id: number; username: string; role: string; totp_enabled: number; tg_id: string | null; backup_recipient: number; last_login_at: string | null }

export function AccessPage({ auth, onChange }: { auth: AuthState; onChange: () => void }) {
  // администраторы и роли — раздел owner; остальным сервер отдаёт только их самих: «Мой аккаунт» со своим Telegram
  if (!auth.owner) return <MyAccount auth={auth} onChange={onChange} />;
  return <OwnerAccess auth={auth} onChange={onChange} />;
}

/** «Мой аккаунт» для не-owner: 2FA, пароль, сессии, уведомления и свой Telegram — без списка администраторов и ролей. */
function MyAccount({ auth, onChange }: { auth: AuthState; onChange: () => void }) {
  const { data: admins, reload } = usePoll(() => api.get<Admin[]>('/api/v1/admins'), null);
  const me = admins?.find((a) => a.username === auth.username);
  return (
    <>
      <div className="page-head"><div><h1>Мой аккаунт</h1><p>Вход, 2FA, сессии и уведомления. Роль: {auth.roleName ?? auth.role}; права роли назначает owner</p></div></div>
      <MySecurity auth={auth} onChange={onChange} />
      <MyNotify />
      {me && (
        <section className="card pad stack">
          <h2>Мой Telegram</h2>
          <p className="small muted">На этот Telegram бот присылает уведомления и принимает команды администратора.</p>
          <TgBind tgId={me.tg_id} canEdit linkUrl={`/api/v1/admins/${me.id}/tg-link`} onChanged={() => void reload()} onSaveId={(v) => api.patch('/api/v1/me', { tgId: v })} />
        </section>
      )}
    </>
  );
}

function OwnerAccess({ auth, onChange }: { auth: AuthState; onChange: () => void }) {
  const { data: admins, setData, reload } = usePoll(() => api.get<Admin[]>('/api/v1/admins'), null);
  const { busy, error, run } = useAsync();
  const [nu, setNu] = useState({ username: '', role: 'admin' });
  const [created, setCreated] = useState<{ username: string; password: string } | null>(null);
  const isOwner = auth.owner;
  // роли для выбора: встроенные и свои (owner — первым)
  const { data: rolesData, reload: reloadRoles } = usePoll(() => api.get<RolesData>('/api/v1/roles'), null);
  const roleOpts = rolesData?.roles ?? [];
  const roleName = (id: string) => roleOpts.find((r) => r.id === id)?.name ?? id;
  const patch = (id: number, body: object, done?: string) => run(async () => { setData(await api.patch<Admin[]>(`/api/v1/admins/${id}`, body)); if (done) toast(done); });

  return (
    <>
      <div className="page-head"><div><h1>Права и роли</h1><p>Кто управляет эскадрой и что ему разрешено. Права проверяет сервер панели, бот — только клиент</p></div></div>
      <MySecurity auth={auth} onChange={onChange} />
      <MyNotify />
      <section className="card">
        <div className="card-head"><h2>Администраторы</h2><span className="k">Личный флот: реселлеров нет</span></div>
        <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
          <table>
            <thead><tr><th>Учётная запись</th><th>Роль</th><th>2FA</th><th>Telegram</th><th>Последний вход</th><th /></tr></thead>
            <tbody>{admins?.map((a) => (
              <tr key={a.id}>
                <td><b>{a.username}</b>{a.username === auth.username && <> <span className="k">(вы)</span></>}</td>
                <td>{isOwner ? <select className="inp" style={{ width: 'auto' }} value={a.role} aria-label={`Роль ${a.username}`} onChange={(e) => void patch(a.id, { role: e.target.value }, `${a.username}: роль ${roleName(e.target.value)} сохранена`)}>{roleOpts.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select> : <Tag kind="acc">{roleName(a.role)}</Tag>}</td>
                <td>{a.totp_enabled ? <Tag kind="ok">TOTP</Tag> : <Tag kind="warn">не включена</Tag>}</td>
                <td><TgBind tgId={a.tg_id} canEdit={isOwner || a.username === auth.username} linkUrl={`/api/v1/admins/${a.id}/tg-link`} onChanged={() => void reload()}
                  onSaveId={(v) => (isOwner ? api.patch(`/api/v1/admins/${a.id}`, { tgId: v }) : api.patch('/api/v1/me', { tgId: v }))} /></td>
                <td className="k">{fmtTime(a.last_login_at)}</td>
                <td>{isOwner && a.username !== auth.username && <button className="btn ghost sm" style={{ color: 'var(--fail)' }} onClick={async () => { if (await ask(`Удалить ${a.username}?`)) void run(async () => { setData(await api.del<Admin[]>(`/api/v1/admins/${a.id}`)); toast(`${a.username} удалён`); }); }}>Удалить</button>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        {isOwner && (
          <form className="row" onSubmit={(e) => { e.preventDefault(); void run(async () => { const r = await api.post<{ username: string; password: string; admins: Admin[] }>('/api/v1/admins', nu); setCreated(r); setData(r.admins); setNu({ username: '', role: 'admin' }); toast(`${r.username} приглашён`); }); }}>
            <div className="flex"><input className="inp" style={{ width: 200 }} value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} placeholder="логин" aria-label="Логин" />
              <select className="inp" style={{ width: 'auto' }} value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })} aria-label="Роль">{roleOpts.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select>
              <button className="btn pri" disabled={busy || nu.username.length < 3}>Пригласить</button>{nu.role === 'owner' && <span className="small" style={{ color: 'var(--warn)' }}>owner получает все права, включая управление администраторами и бэкапами</span>}</div>
            {created && <div className="alert warn">Временный пароль для <code>{created.username}</code>: <code>{created.password}</code> — покажется один раз. <CopyButton text={created.password} /></div>}
          </form>
        )}
        <div style={{ padding: '0 20px 14px' }}><ErrorBox error={error} /></div>
      </section>
      <RolesCard isOwner={isOwner} onChange={() => { void reload(); void reloadRoles(); }} />
    </>
  );
}

function MySecurity({ auth, onChange }: { auth: AuthState; onChange: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [pw, setPw] = useState({ current: '', next: '' });
  const { data: sessions, reload } = usePoll(() => api.get<Array<{ id: string; created_at: string; expires_at: string; ip: string | null; current: boolean }>>('/api/v1/me/sessions'), null);
  const { busy, error, run } = useAsync();
  const [ok, setOk] = useState<string | null>(null);
  const [allSessions, setAllSessions] = useState(false);
  return (
    <div className="split">
      <section className="card pad wide stack">
        <h2>Моя безопасность</h2>
        {auth.totp ? <div className="alert ok">2FA включена. Чувствительные операции спрашивают код.</div> : (
          <>
            <div className="alert warn">2FA не включена. Включите её — после этого опасные операции (firewall, аварийный доступ, бэкапы) будут требовать код.</div>
            {!setup ? <div><button className="btn pri" disabled={busy} onClick={() => void run(async () => setSetup(await api.post('/api/v1/me/2fa/setup')))}>Настроить 2FA</button></div> : (
              <div className="stack">
                <span className="small">Добавьте ключ в приложение-аутентификатор (Aegis, 2FAS, Google Authenticator) вручную или ссылкой:</span>
                <code style={{ padding: 10 }}>{setup.secret}</code>
                <div className="flex"><CopyButton text={setup.secret} label="Копировать ключ" /><CopyButton text={setup.uri} label="Копировать otpauth-ссылку" /></div>
                <form className="flex" onSubmit={(e) => { e.preventDefault(); void run(async () => { await api.post('/api/v1/me/2fa/enable', { code }); setSetup(null); onChange(); }); }}>
                  <input className="inp mono" style={{ width: 140 }} inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} placeholder="6 цифр" aria-label="Код" /><button className="btn pri" disabled={code.length !== 6}>Включить</button></form>
              </div>
            )}
          </>
        )}
        <form className="flex" onSubmit={(e) => { e.preventDefault(); void run(async () => { await api.post('/api/v1/me/password', pw); setPw({ current: '', next: '' }); setOk('Пароль изменён'); }); }}>
          <input className="inp" type="password" style={{ width: 180 }} value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} placeholder="текущий пароль" aria-label="Текущий пароль" autoComplete="current-password" />
          <input className="inp" type="password" style={{ width: 180 }} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} placeholder="новый, от 12 символов" aria-label="Новый пароль" autoComplete="new-password" />
          <button className="btn" disabled={busy || pw.next.length < 12}>Сменить пароль</button>
        </form>
        {ok && <div className="alert ok">{ok}</div>}
        <ErrorBox error={error} />
      </section>
      <section className="card pad narrow stack">
        <h2>Сессии</h2>
        {(allSessions ? sessions : sessions?.slice(0, 3))?.map((s) => <div key={s.id} className="flex" style={{ justifyContent: 'space-between', borderTop: '1px solid var(--line)', paddingTop: 8 }}><span className="row-text"><span className="small"><Addr value={s.ip} empty="?" /> · с {fmtTime(s.created_at)}</span><span className="k">истекает {fmtTime(s.expires_at)}</span></span>{s.current && <Tag kind="ok">текущая</Tag>}</div>)}
        <div className="flex">{(sessions?.length ?? 0) > 3 && <button className="btn ghost sm" onClick={() => setAllSessions(!allSessions)}>{allSessions ? 'Свернуть' : `Показать все (${sessions!.length})`}</button>}
          <button className="btn" disabled={busy} onClick={() => void run(async () => { await api.post('/api/v1/me/sessions/revoke-others'); void reload(); })}>Завершить остальные сессии</button></div>
      </section>
    </div>
  );
}

/** Какие уведомления присылать мне в Telegram — то же, что команда /notify в боте. */
function MyNotify() {
  const { data, setData } = usePoll(() => api.get<{ categories: Record<string, string>; off: string[] }>('/api/v1/me/notify'), null);
  const { busy, error, run } = useAsync();
  if (!data) return null;
  const toggle = (k: string, on: boolean) => run(async () => {
    const off = on ? data.off.filter((x) => x !== k) : [...data.off, k];
    setData(await api.put('/api/v1/me/notify', { off }));
    toast(on ? `«${data.categories[k]}» — включено` : `«${data.categories[k]}» — выключено`);
  });
  return (
    <section className="card pad stack">
      <h2>Мои уведомления в Telegram</h2>
      <p className="small muted">Что бот присылает вам. Пользователям VPN такие сообщения не приходят. То же настраивается в боте командой /notify.</p>
      <div className="grid g3">
        {Object.entries(data.categories).map(([k, label]) => (
          <span key={k} className="flex" style={{ justifyContent: 'space-between' }}><span className="small">{label}</span><Switch label={label} on={!data.off.includes(k)} disabled={busy} onChange={(v) => void toggle(k, v)} /></span>
        ))}
      </div>
      <ErrorBox error={error} />
    </section>
  );
}
