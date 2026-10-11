import { useState } from 'react';
import { api, fmtTime } from '../api';
import { CopyButton, ErrorBox, Switch, Tag, TgBind, toast, useAsync, usePoll, ask } from '../ui';
import type { AuthState } from '../App';

interface Admin { id: number; username: string; role: string; totp_enabled: number; tg_id: string | null; backup_recipient: number; last_login_at: string | null }

const MATRIX: Array<[string, Array<[string, string, string, string]>]> = [
  ['Серверы', [
    ['Просмотр, проверка связи, preflight', '✓', '✓', '✓'],
    ['Подключение и удаление серверов', '✓', '✓', '—'],
    ['Смена уровня защиты, план и применение firewall', '2FA', '2FA', '—'],
    ['Временно открыть SSH, аварийно отключить блокировки', '2FA', '2FA', '—'],
    ['Включить терминал (shell) на сервере', '2FA', '—', '—'],
  ]],
  ['Конфигурации и пользователи', [
    ['Редактировать шаблоны, выкат', '✓', '✓', '✓'],
    ['Создавать пользователей, менять лимиты', '✓', '✓', '✓'],
  ]],
  ['Бэкапы и безопасность', [
    ['Запустить бэкап, посмотреть историю', '✓', '✓', '—'],
    ['Сменить получателей и ключи age, токен бота', '2FA', '—', '—'],
    ['Управлять ролями и администраторами', '2FA', '—', '—'],
  ]],
];
const cell = (v: string) => <td style={{ textAlign: 'center', color: v === '✓' ? 'var(--ok)' : v === '—' ? 'var(--muted)' : 'var(--warn)', fontWeight: 700, fontSize: v === '2FA' ? 12 : 14 }}>{v}</td>;

export function AccessPage({ auth, onChange }: { auth: AuthState; onChange: () => void }) {
  const { data: admins, setData, reload } = usePoll(() => api.get<Admin[]>('/api/v1/admins'), null);
  const { busy, error, run } = useAsync();
  const [nu, setNu] = useState({ username: '', role: 'admin' });
  const [created, setCreated] = useState<{ username: string; password: string } | null>(null);
  const isOwner = auth.role === 'owner';
  const patch = (id: number, body: object, done?: string) => run(async () => { setData(await api.patch<Admin[]>(`/api/v1/admins/${id}`, body)); if (done) toast(done); });

  return (
    <>
      <div className="page-head"><div><h1>Права и роли</h1><p>Кто управляет эскадрой и что ему разрешено. Права проверяет сервер панели, бот — только клиент</p></div></div>
      <MySecurity auth={auth} onChange={onChange} />
      <section className="card">
        <div className="card-head"><h2>Администраторы</h2><span className="k">Личный флот: реселлеров нет</span></div>
        <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
          <table>
            <thead><tr><th>Учётная запись</th><th>Роль</th><th>2FA</th><th>Telegram</th><th>Получает бэкапы</th><th>Последний вход</th><th /></tr></thead>
            <tbody>{admins?.map((a) => (
              <tr key={a.id}>
                <td><b>{a.username}</b>{a.username === auth.username && <> <span className="k">(вы)</span></>}</td>
                <td>{isOwner ? <select className="inp" style={{ width: 'auto' }} value={a.role} aria-label={`Роль ${a.username}`} onChange={(e) => void patch(a.id, { role: e.target.value }, `${a.username}: роль ${e.target.value} сохранена`)}>{['owner', 'admin', 'operator'].map((r) => <option key={r}>{r}</option>)}</select> : <Tag kind="acc">{a.role}</Tag>}</td>
                <td>{a.totp_enabled ? <Tag kind="ok">TOTP</Tag> : <Tag kind="warn">не включена</Tag>}</td>
                <td><TgBind tgId={a.tg_id} canEdit={isOwner || a.username === auth.username} linkUrl={`/api/v1/admins/${a.id}/tg-link`} onChanged={() => void reload()}
                  onSaveId={(v) => (isOwner ? api.patch(`/api/v1/admins/${a.id}`, { tgId: v }) : api.patch('/api/v1/me', { tgId: v }))} /></td>
                <td><Switch label="Получает бэкапы" on={!!a.backup_recipient} disabled={!isOwner || busy} onChange={(v) => void patch(a.id, { backupRecipient: v }, v ? `${a.username} получает бэкапы` : `${a.username} больше не получает бэкапы`)} /></td>
                <td className="k">{fmtTime(a.last_login_at)}</td>
                <td>{isOwner && a.username !== auth.username && <button className="btn ghost sm" style={{ color: 'var(--fail)' }} onClick={async () => { if (await ask(`Удалить ${a.username}?`)) void run(async () => { setData(await api.del<Admin[]>(`/api/v1/admins/${a.id}`)); toast(`${a.username} удалён`); }); }}>Удалить</button>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        {isOwner && (
          <form className="row" onSubmit={(e) => { e.preventDefault(); void run(async () => { const r = await api.post<{ username: string; password: string; admins: Admin[] }>('/api/v1/admins', nu); setCreated(r); setData(r.admins); setNu({ username: '', role: 'admin' }); toast(`${r.username} приглашён`); }); }}>
            <div className="flex"><input className="inp" style={{ width: 200 }} value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} placeholder="логин" aria-label="Логин" />
              <select className="inp" style={{ width: 'auto' }} value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })} aria-label="Роль"><option value="admin">admin</option><option value="operator">operator</option></select>
              <button className="btn pri" disabled={busy || nu.username.length < 3}>Пригласить</button></div>
            {created && <div className="alert warn">Временный пароль для <code>{created.username}</code>: <code>{created.password}</code> — покажется один раз. <CopyButton text={created.password} /></div>}
          </form>
        )}
        <div style={{ padding: '0 20px 14px' }}><ErrorBox error={error} /></div>
      </section>
      <section className="card">
        <div className="card-head"><h2>Матрица прав</h2><span className="k"><span style={{ color: 'var(--ok)' }}>✓</span> разрешено · <span style={{ color: 'var(--warn)' }}>2FA</span> с кодом, если 2FA включена</span></div>
        <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
          <table>
            <thead><tr><th>Действие</th><th style={{ textAlign: 'center' }}>owner</th><th style={{ textAlign: 'center' }}>admin</th><th style={{ textAlign: 'center' }}>operator</th></tr></thead>
            <tbody>{MATRIX.flatMap(([g, rows]) => [<tr key={g} className="grp"><td colSpan={4}>{g}</td></tr>, ...rows.map((r) => <tr key={r[0]}><td>{r[0]}</td>{cell(r[1])}{cell(r[2])}{cell(r[3])}</tr>)])}</tbody>
          </table>
        </div>
      </section>
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
        {sessions?.map((s) => <div key={s.id} className="flex" style={{ justifyContent: 'space-between', borderTop: '1px solid var(--line)', paddingTop: 8 }}><span className="row-text"><span className="small">{s.ip ?? '?'} · с {fmtTime(s.created_at)}</span><span className="k">истекает {fmtTime(s.expires_at)}</span></span>{s.current && <Tag kind="ok">текущая</Tag>}</div>)}
        <div><button className="btn" disabled={busy} onClick={() => void run(async () => { await api.post('/api/v1/me/sessions/revoke-others'); void reload(); })}>Завершить остальные сессии</button></div>
      </section>
    </div>
  );
}
