import { api, fmtTime } from '../api';
import { usePoll } from '../ui';

interface Audit { chain: { ok: boolean; brokenAt?: number }; items: Array<{ id: number; ts: string; actor: string; action: string; target: string | null; detail: string | null }> }

export function AuditPage() {
  const { data } = usePoll(() => api.get<Audit>('/api/v1/audit'), 30_000);
  return (
    <>
      <div className="page-head"><div><h1>Аудит</h1><p>Неизменяемый журнал с цепочкой хэшей</p></div></div>
      {data && (
        <>
          <div className={`alert ${data.chain.ok ? 'ok' : 'fail'}`}>{data.chain.ok ? 'Цепочка хэшей цела' : `Цепочка нарушена на записи #${data.chain.brokenAt}`}</div>
          <section className="card table-wrap">
            <table>
              <thead><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Объект</th><th>Детали</th></tr></thead>
              <tbody>{data.items.map((a) => (
                <tr key={a.id}><td className="mono small nowrap">{fmtTime(a.ts)}</td><td>{a.actor}</td><td className="mono small">{a.action}</td><td className="mono small">{a.target ?? ''}</td><td className="mono k" style={{ maxWidth: 420, overflowWrap: 'anywhere' }}>{a.detail ?? ''}</td></tr>
              ))}</tbody>
            </table>
          </section>
        </>
      )}
    </>
  );
}
