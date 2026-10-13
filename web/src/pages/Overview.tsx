import { api, ago, fmtBytes, fmtTime, type Server } from '../api';
import { ErrorBox, Info, usePoll } from '../ui';
import { RouteMap, exitView } from '../RouteMap';
import { HostStatsPanel } from '../HostStats';
import { ServerTable } from '../ServerTable';

type Health = { rtt_ms: number | null; mbps: number | null; ok: number; error: string | null };
interface Route { id: string; name: string; entryId: string; autoMode: string; selected: string | null; exits: Array<{ id: string; health: Health | null }> }

interface Overview {
  servers: Server[];
  counts: { servers: number; online: number; users: number; activeUsers: number };
  trafficBytes: number;
  lastBackup: { created_at: string; status: string; detail: string | null } | null;
  attention: Array<{ level: 'fail' | 'warn' | 'info'; title: string; detail: string; serverId?: string }>;
  routes: Route[];
}

const MODE: Record<string, string> = { smart: 'по качеству', order: 'по порядку', spread: 'по нагрузке', random: 'случайно' };

export function OverviewPage() {
  const { data: d, error } = usePoll(() => api.get<Overview>('/api/v1/overview'), 30_000);
  const byId = new Map(d?.servers.map((s) => [s.id, s]));
  const inRoutes = new Set(d?.routes.flatMap((r) => [r.entryId, ...r.exits.map((x) => x.id)]));
  const loose = d?.servers.filter((s) => !inRoutes.has(s.id)) ?? [];
  return (
    <>
      <ErrorBox error={error} />
      {d && (
        <>
          <section className="card">
            <div className="route-head" style={{ padding: '20px 20px 0' }}>
              <h1>{d.counts.servers ? `Флот в строю: ${d.counts.online} из ${d.counts.servers}` : 'Флот пока пуст'}</h1>
              <div className="flex"><a className="btn" href="#/users">Новый пользователь</a><a className="btn pri" href="#/servers">Добавить сервер</a></div>
            </div>
            <p className="small muted" style={{ padding: '6px 20px 0' }}>
              {`Пользователей: ${d.counts.users}, активны ${d.counts.activeUsers}`} · {`трафик за месяц ${fmtBytes(d.trafficBytes)}`} · {d.lastBackup ? `последний бэкап ${fmtTime(d.lastBackup.created_at)}` : <a href="#/settings">бэкапы не настроены</a>}
            </p>
            <div className="routes">
              {d.routes.map((r) => {
                const entry = byId.get(r.entryId);
                return (
                  <div key={r.id}>
                    <div className="route-title"><b>{r.name}</b><span>«Авто» выбирает выход {MODE[r.autoMode] ?? r.autoMode}</span><a href="#/configs" style={{ marginLeft: 'auto' }}>Настроить</a></div>
                    <RouteMap
                      entry={<><b>{entry?.name ?? '?'}</b>{entry?.fail_since ? <span className="k" style={{ color: 'var(--fail)' }}>Relay · нет связи</span> : <span className="k">{`Relay · ${ago(entry?.last_seen_at ?? null)}`}</span>}</>}
                      exits={r.exits.map((x) => {
                        const s = byId.get(x.id);
                        const lead = r.autoMode !== 'random' && (r.selected ? r.selected === x.id : r.exits.find((e) => e.health?.ok)?.id === x.id);
                        return { id: x.id, name: s?.name ?? x.id, href: `#/server/${x.id}`, ...exitView(x.health, { lead, failSince: s?.fail_since, mode: r.autoMode, ago }) };
                      })}
                      ordered={r.autoMode === 'order' || r.autoMode === 'spread'}
                      empty="Выходов пока нет: выкатите конфигурацию на серверы-выходы."
                    />
                  </div>
                );
              })}
              {!!loose.length && (
                <div>
                  <div className="route-title"><b>{d.routes.length ? 'Без входа' : 'Серверы'}</b><span>пользователи подключаются к ним напрямую</span></div>
                  <div className="flex">{loose.map((s) => (
                    <a key={s.id} className={`rm-exit ${s.fail_since ? 'fail' : 'ok'}`} href={`#/server/${s.id}`} style={{ padding: '0 14px', gap: 10, color: 'var(--text)', textDecoration: 'none' }}>
                      <span className="rm-name">{s.name}</span><span className="rm-note">{s.fail_since ? 'нет связи' : ago(s.last_seen_at)}</span>
                    </a>
                  ))}</div>
                </div>
              )}
              {!d.servers.length && <div className="empty">Добавьте первый сервер — здесь появится схема флота.</div>}
            </div>
            {!!d.attention.length && (
              <div className="flex" style={{ padding: '0 20px 18px', gap: 8 }}>
                {d.attention.map((a, i) => {
                  const chip = <span className={`tag ${a.level}`} title={a.detail} style={{ fontWeight: 500, padding: '6px 10px' }}>{a.title}</span>;
                  return a.serverId ? <a key={i} href={`#/server/${a.serverId}`} style={{ textDecoration: 'none' }}>{chip}</a> : <span key={i}>{chip}</span>;
                })}
              </div>
            )}
          </section>

          <section className="card">
            <div className="card-head"><h2>Главный сервер <Info>Хост, где работает панель (он же исполнитель, если панель ходит на узлы отсюда). Обновляется каждые 3 секунды.</Info></h2><span className="k">вживую</span></div>
            <div style={{ padding: '0 20px 18px' }}><HostStatsPanel url="/api/v1/stats/main" /></div>
          </section>

          <section className="card">
            <div className="card-head"><h2>Узлы</h2><a href="#/servers">Все серверы</a></div>
            <div style={{ borderTop: '1px solid var(--line)' }}><ServerTable servers={d.servers} /></div>
          </section>

        </>
      )}
    </>
  );
}
