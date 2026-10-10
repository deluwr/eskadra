import { api, ago, fmtBytes, fmtTime, type Server } from '../api';
import { ErrorBox, Level, StagePip, Tag, roleLabel, usePoll } from '../ui';

interface Overview {
  servers: Server[];
  counts: { servers: number; online: number; users: number; activeUsers: number };
  trafficBytes: number;
  lastBackup: { created_at: string; status: string; detail: string | null } | null;
  attention: Array<{ level: 'fail' | 'warn' | 'info'; title: string; detail: string; serverId?: string }>;
  recent: Array<{ id: number; ts: string; actor: string; action: string; target: string | null }>;
}

export function OverviewPage() {
  const { data: d, error } = usePoll(() => api.get<Overview>('/api/v1/overview'), 30_000);
  const backupDetail = d?.lastBackup?.detail ? (JSON.parse(d.lastBackup.detail) as { delivered?: number; total?: number }) : null;
  return (
    <>
      <div className="page-head">
        <div><h1>Обзор</h1><p>Состояние эскадры, что требует внимания и последние операции</p></div>
        <div className="flex"><a className="btn" href="#/users">Новый пользователь</a><a className="btn pri" href="#/servers">Добавить сервер</a></div>
      </div>
      <ErrorBox error={error} />
      {d && (
        <>
          <div className="grid g4">
            <div className="card stat"><span className="k">Узлы</span><b>{d.counts.servers}</b><span className="flex"><Tag kind="ok">{d.counts.online} на связи</Tag>{d.counts.servers - d.counts.online > 0 && <Tag kind="warn">{d.counts.servers - d.counts.online} без связи</Tag>}</span></div>
            <div className="card stat"><span className="k">Пользователи</span><b>{d.counts.users}</b><span className="k">активны: {d.counts.activeUsers}</span></div>
            <div className="card stat"><span className="k">Трафик за месяц</span><b>{fmtBytes(d.trafficBytes)}</b><span className="k">по всем узлам (Xray)</span></div>
            <div className="card stat"><span className="k">Последний бэкап</span><b>{d.lastBackup ? fmtTime(d.lastBackup.created_at).slice(11) || '—' : '—'}</b>
              <span className="flex">{d.lastBackup ? <Tag kind={d.lastBackup.status === 'ok' ? 'ok' : 'warn'}>{backupDetail?.total ? `доставлен ${backupDetail.delivered} из ${backupDetail.total}` : d.lastBackup.status}</Tag> : <a href="#/settings">настроить</a>}</span></div>
          </div>

          <div className="split">
            <section className="card wide">
              <div className="card-head"><h2>Узлы</h2><a href="#/servers">Все серверы</a></div>
              <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
                <table>
                  <thead><tr><th>Узел</th><th>Роль</th><th>Этап</th><th>Защита</th><th>Связь</th></tr></thead>
                  <tbody>
                    {d.servers.map((s) => (
                      <tr key={s.id} className="clickable" onClick={() => (location.hash = `#/server/${s.id}`)}>
                        <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a><div className="k mono">{s.host}</div></td>
                        <td>{roleLabel(s)}</td>
                        <td><StagePip stage={s.stage} /></td>
                        <td><Level value={s.protection_current} /></td>
                        <td>{s.fail_since ? <Tag kind="fail" dot>нет связи</Tag> : <Tag kind={s.last_seen_at ? 'ok' : undefined} dot>{ago(s.last_seen_at)}</Tag>}</td>
                      </tr>
                    ))}
                    {!d.servers.length && <tr><td colSpan={5} className="empty">Серверов пока нет</td></tr>}
                  </tbody>
                </table>
              </div>
            </section>
            <section className="card narrow">
              <div className="card-head"><h2>Требует внимания <Tag kind={d.attention.length ? 'warn' : 'ok'}>{d.attention.length}</Tag></h2></div>
              {d.attention.map((a, i) => (
                <div key={i} className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
                  <Tag kind={a.level}>{a.level === 'info' ? 'i' : '!'}</Tag>
                  <div className="row-text"><span style={{ fontWeight: 500 }}>{a.title}</span><span className="k">{a.detail} {a.serverId && <a href={`#/server/${a.serverId}`}>Открыть</a>}</span></div>
                </div>
              ))}
              {!d.attention.length && <div className="row k">Всё в порядке</div>}
            </section>
          </div>

          <section className="card">
            <div className="card-head"><h2>Последние операции</h2><a href="#/audit">Журнал аудита</a></div>
            <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
              <table><tbody>
                {d.recent.map((r) => <tr key={r.id}><td className="mono k nowrap">{fmtTime(r.ts)}</td><td>{r.actor}</td><td className="mono small">{r.action}</td><td className="mono small">{r.target ?? ''}</td></tr>)}
              </tbody></table>
            </div>
          </section>
        </>
      )}
    </>
  );
}
