import { api, fmtBytes, fmtTime } from '../api';
import { ErrorBox, Tag, useAsync, usePoll } from '../ui';

interface Backup { id: number; created_at: string; profile: string; size: number | null; status: string; detail: string | null }

export function BackupsPage() {
  const { data, reload } = usePoll(() => api.get<Backup[]>('/api/v1/backups'), 30_000);
  const { busy, error, run } = useAsync();
  return (
    <>
      <div className="page-head">
        <div><h1>Бэкапы</h1><p>Зашифрованные копии панели: отправляются ботом получателям, локально хранятся последние 14</p></div>
        <div className="flex"><a className="btn" href="#/settings">Настройки бэкапов</a><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.post('/api/v1/backups/run'); void reload(); })}>{busy ? 'Создаю…' : 'Бэкап сейчас'}</button></div>
      </div>
      <ErrorBox error={error} />
      <section className="card table-wrap">
        <table>
          <thead><tr><th>Время</th><th>Профиль</th><th>Размер</th><th>Доставка</th><th>Файл</th></tr></thead>
          <tbody>
            {data?.map((b) => {
              const d = b.detail ? (JSON.parse(b.detail) as { file?: string; delivered?: number; total?: number; errors?: string[] } | string) : null;
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
    </>
  );
}
