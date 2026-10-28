import { useState } from 'react';
import { api, can, fmtBytes, fmtTime } from '../api';
import { ErrorBox, Info, Tag, ask, useAsync, usePoll } from '../ui';

interface Backup { id: number; created_at: string; profile: string; size: number | null; status: string; detail: string | null }

export function BackupsPage() {
  const { data, reload } = usePoll(() => api.get<Backup[]>('/api/v1/backups'), 30_000);
  const { busy, error, run } = useAsync();
  return (
    <>
      <div className="page-head">
        <div><h1>Бэкапы</h1><p>Зашифрованные копии панели: отправляются ботом получателям, локально хранятся последние 14</p></div>
        {/* восстановление и настройки бэкапов — только owner (раздел виден с правом запуска бэкапа) */}
        <div className="flex">{can('owner') && <a className="btn" href="#/settings">Настройки бэкапов</a>}{can('owner') && <a className="btn" href="#/backups" onClick={(e) => { e.preventDefault(); document.querySelector('.restore-anchor')?.scrollIntoView({ behavior: 'smooth' }); }}>Восстановить</a>}<button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.post('/api/v1/backups/run'); void reload(); })}>{busy ? 'Создаю…' : 'Бэкап сейчас'}</button></div>
      </div>
      <ErrorBox error={error} />
      <section className="card table-wrap">
        <table>
          <thead><tr><th>Время</th><th>Профиль</th><th>Размер</th><th>Доставка</th><th>Файл</th></tr></thead>
          <tbody>
            {data?.map((b) => {
              // detail — JSON доставки или просто текст ошибки («нет получателей age»): текст не должен ронять страницу
              const d = b.detail ? ((() => { try { return JSON.parse(b.detail) as { file?: string; delivered?: number; total?: number; errors?: string[] } | string; } catch { return b.detail; } })()) : null;
              const o = typeof d === 'object' && d ? d : null;
              return (
                <tr key={b.id}>
                  <td className="mono small nowrap">{fmtTime(b.created_at)}</td>
                  <td>{b.profile}</td>
                  <td className="mono small">{b.size ? fmtBytes(b.size) : '—'}</td>
                  <td><Tag kind={b.status === 'ok' ? 'ok' : b.status === 'failed' ? 'fail' : 'warn'}>{o?.total ? `${o.delivered} из ${o.total}` : b.status}</Tag>{o?.errors?.length ? <div className="k">{o.errors.join('; ')}</div> : null}{typeof d === 'string' && <div className="k">{d}</div>}</td>
                  <td className="mono k">{o?.file ?? ''}</td>
                </tr>
              );
            })}
            {data && !data.length && <tr><td colSpan={5} className="empty">Бэкапов пока не было</td></tr>}
          </tbody>
        </table>
      </section>
      {can('owner') && <RestoreCard />}
    </>
  );
}

interface Summary { created: string; servers: number; users: number; admins: string[]; templates: number }

/** Восстановление: файл копии + пароль бэкапа (старые .age — приватный ключ age) → проверка и сводка → подтверждение → перезапуск панели. */
function RestoreCard() {
  const [file, setFile] = useState<File | null>(null);
  const [key, setKey] = useState('');
  const [sum, setSum] = useState<Summary | null>(null);
  const [restarting, setRestarting] = useState(false);
  const { busy, error, run } = useAsync();
  const b64 = (f: File) => new Promise<string>((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1] ?? ''); r.onerror = () => rej(new Error('файл не прочитан')); r.readAsDataURL(f); });
  const check = () => run(async () => { setSum(await api.post<Summary>('/api/v1/backups/restore/check', { file: await b64(file!), secret: key })); });
  // старые копии (.age, до v0.37) открываются приватным ключом age, новые — паролем бэкапа
  const legacy = !!file?.name.endsWith('.age');
  const apply = async () => {
    if (!sum || !(await ask(`Заменить данные панели копией от ${fmtTime(sum.created)}? Всё, что изменилось после неё, пропадёт (прежние файлы сохранятся на сервере). Панель перезапустится, войдите учётной записью из копии.`))) return;
    void run(async () => {
      await api.post('/api/v1/backups/restore/apply');
      setRestarting(true);
      // ждём, пока панель поднимется с восстановленными данными
      for (let i = 0; i < 90; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        try { await api.get('/api/v1/auth/state'); location.reload(); return; } catch { /* ещё перезапускается */ }
      }
    });
  };
  return (
    <section className="card pad stack restore-anchor">
      <h2>Восстановить из бэкапа <Info>Нужны файл копии (.tar.gz.enc — из Telegram или с сервера) и пароль бэкапа из «Настроек». Старые копии (.tar.gz.age) открываются приватным ключом age. Пароль используется только для расшифровки.</Info></h2>
      {restarting ? <span className="flex small" style={{ gap: 8 }}><span className="spin" aria-hidden="true" />Панель перезапускается с восстановленными данными…</span> : !sum ? (
        <>
          <div className="grid g2">
            <label className="fld">Файл копии<input className="inp" type="file" accept=".enc,.age" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setSum(null); }} style={{ paddingTop: 8 }} /></label>
            {legacy
              ? <label className="fld">Приватный ключ age<textarea className="inp mono" rows={2} value={key} onChange={(e) => setKey(e.target.value)} placeholder="AGE-SECRET-KEY-1…" autoComplete="off" spellCheck={false} /></label>
              : <label className="fld">Пароль бэкапа<input className="inp" type="password" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" aria-label="Пароль бэкапа" /></label>}
          </div>
          <div><button className="btn" disabled={busy || !file || (legacy ? !key.includes('AGE-SECRET-KEY-') : !key)} onClick={() => void check()}>{busy ? 'Проверяю…' : 'Проверить копию'}</button></div>
        </>
      ) : (
        <>
          <div className="alert ok small">{`Копия цела и расшифрована. Создана ${fmtTime(sum.created)}`}<br />{`Серверов: ${sum.servers}, конфигураций: ${sum.templates}, пользователей: ${sum.users}`}<br />{`Администраторы: ${sum.admins.join(', ')}`}</div>
          <div className="flex">
            <button className="btn danger" disabled={busy} onClick={() => void apply()}>Восстановить и перезапустить</button>
            <button className="btn ghost" disabled={busy} onClick={() => { setSum(null); setKey(''); }}>Отмена</button>
          </div>
        </>
      )}
      <ErrorBox error={error} />
    </section>
  );
}
