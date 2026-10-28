import { useState, type MouseEvent } from 'react';
import { api, can, fmtTime } from '../api';
import { ErrorBox, Info, Tag, toast, useAsync, usePoll } from '../ui';

interface Stat { avg: number; max: number }
interface Point { at: string; cpu: number | null; net: number | null }
interface ServerSummary {
  id: string; name: string; role: string; down: boolean; points: number;
  cpu: Stat | null; load1: Stat | null; mem: Stat | null; disk: Stat | null; rx: Stat | null; tx: Stat | null;
  outages: { count: number; worstMin: number } | null; series: Point[];
}
interface Summary { hours: number; stepMin: number; servers: ServerSummary[] }

/** Линия за 48 ч: один ряд (подпись называет показатель), разрывы — где срезов не было; наведение — время и значение. */
function Spark({ points, pick, max, unit, label }: { points: Point[]; pick: (p: Point) => number | null; max: number; unit: string; label: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 240, H = 44, pad = 3;
  if (!points.length) return <div className="k small" style={{ height: H }}>данных пока нет</div>;
  const t0 = Date.parse(points[0]!.at), t1 = Date.parse(points.at(-1)!.at) || t0 + 1;
  const x = (p: Point) => pad + ((Date.parse(p.at) - t0) / Math.max(1, t1 - t0)) * (W - pad * 2);
  const y = (v: number) => H - pad - (Math.min(v, max) / max) * (H - pad * 2);
  // разрывы: пропуск больше трёх шагов (сервер был недоступен) — линия прерывается
  const segs: string[] = [];
  let cur = '';
  points.forEach((p, i) => {
    const v = pick(p);
    const gap = i > 0 && Date.parse(p.at) - Date.parse(points[i - 1]!.at) > 16 * 60_000;
    if (v == null || gap) { if (cur) segs.push(cur); cur = ''; }
    if (v != null) cur += `${cur ? 'L' : 'M'}${x(p).toFixed(1)},${y(v).toFixed(1)}`;
  });
  if (cur) segs.push(cur);
  const onMove = (e: MouseEvent<SVGRectElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const fx = ((e.clientX - r.left) / r.width) * W;
    let best = 0;
    points.forEach((p, i) => { if (Math.abs(x(p) - fx) < Math.abs(x(points[best]!) - fx)) best = i; });
    setHover(best);
  };
  const hp = hover != null ? points[hover]! : null;
  const hv = hp ? pick(hp) : null;
  return (
    <div className="spark">
      <div className="flex small" style={{ justifyContent: 'space-between', gap: 8 }}>
        <span className="muted">{label}</span>
        <span className="mono">{hp ? `${fmtTime(hp.at)} · ${hv == null ? '—' : `${hv} ${unit}`}` : ''}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" role="img" aria-label={`${label} за 48 часов`}>
        <line x1={pad} x2={W - pad} y1={H - pad} y2={H - pad} className="spark-base" />
        {segs.map((d, i) => <path key={i} d={d} className="spark-line" vectorEffect="non-scaling-stroke" />)}
        {hp && hv != null && <>
          <line x1={x(hp)} x2={x(hp)} y1={pad} y2={H - pad} className="spark-cross" vectorEffect="non-scaling-stroke" />
          <circle cx={x(hp)} cy={y(hv)} r={3.5} className="spark-dot" />
        </>}
        <rect x={0} y={0} width={W} height={H} fill="transparent" onMouseMove={onMove} onMouseLeave={() => setHover(null)} />
      </svg>
    </div>
  );
}

const fmt = (s: Stat | null, unit = '') => (s ? `${s.avg}${unit} / ${s.max}${unit}` : '—');

export function AnalyticsPage() {
  const { data, error } = usePoll(() => api.get<Summary>('/api/v1/analytics'), 5 * 60_000);
  const [hours, setHours] = useState('48');
  const dl = useAsync();
  const download = () => dl.run(async () => {
    const name = await api.download(`/api/v1/analytics/export?hours=${hours}`);
    toast(`Скачан ${name}`);
  });
  return (
    <>
      <div className="page-head">
        <div><h1>Аналитика</h1><p>Нагрузка серверов за двое суток и выгрузка журналов для разбора</p></div>
      </div>
      <section className="card pad stack" style={{ gap: 10 }}>
        <h2>Диагностика для разбора <Info>Один файл Markdown: серверы и конфигурации (без ключей и паролей), события панели, проверки выходов, нагрузка по часам и журналы служб с каждого сервера. Журналы сжимаются на самих серверах: одинаковые строки схлопнуты («N× первый…последний»), адреса пользователей замаскированы, строки подключений пропущены. Файл можно целиком передать нейросети с вопросом, что пошло не так.</Info></h2>
        <div className="flex">
          <select className="inp" style={{ width: 'auto' }} value={hours} onChange={(e) => setHours(e.target.value)} aria-label="За сколько часов">
            <option value="6">за 6 часов</option><option value="24">за сутки</option><option value="48">за двое суток</option>
          </select>
          {can('servers.manage') && <button className="btn pri" disabled={dl.busy} onClick={() => void download()}>{dl.busy ? 'Собираю с серверов…' : 'Скачать для анализа'}</button>}
          <span className="k">Собирается по запросу, 10–60 секунд: журналы читаются с каждого сервера, в фоне ничего не копируется.</span>
        </div>
        <ErrorBox error={dl.error} />
      </section>
      <ErrorBox error={error} />
      <section className="card">
        <div className="card-head"><h2>Нагрузка за 48 часов <Info>Срез раз в 5 минут с каждого подключённого сервера: процессор, нагрузка, память, диск, сеть. Хранится двое суток. В таблице — среднее / пик; график сети — бо́льшее из входящего и исходящего. Разрывы линии — сервер не отвечал.</Info></h2></div>
        <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
          <table>
            <thead><tr><th>Сервер</th><th style={{ minWidth: 200 }}>Процессор</th><th style={{ minWidth: 200 }}>Сеть</th><th>CPU % ср/пик</th><th>Память %</th><th>Диск %</th><th>Сеть Мбит/с вх / исх (пик)</th><th>Потери связи</th></tr></thead>
            <tbody>
              {data?.servers.map((s) => {
                const netMax = Math.max(10, ...s.series.map((p) => p.net ?? 0));
                return (
                  <tr key={s.id}>
                    <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a><div className="k">{s.role === 'exit' ? 'выход' : 'relay'}{s.down && <> · <Tag kind="fail" dot>нет связи</Tag></>}</div></td>
                    <td><Spark points={s.series} pick={(p) => p.cpu} max={100} unit="%" label="CPU" /></td>
                    <td><Spark points={s.series} pick={(p) => p.net} max={netMax} unit="Мбит/с" label={`сеть, до ${Math.round(netMax)} Мбит/с`} /></td>
                    <td className="mono">{fmt(s.cpu)}</td>
                    <td className="mono">{fmt(s.mem)}</td>
                    <td className="mono">{s.disk ? `${s.disk.max}` : '—'}</td>
                    <td className="mono">{s.rx && s.tx ? `${s.rx.max} / ${s.tx.max}` : '—'}</td>
                    <td>{s.outages ? <Tag kind="warn">{`${s.outages.count} раз, до ${s.outages.worstMin} мин`}</Tag> : <span className="k">нет</span>}</td>
                  </tr>
                );
              })}
              {data && !data.servers.length && <tr><td colSpan={8} className="empty">Подключённых серверов нет.</td></tr>}
              {data?.servers.length && data.servers.every((s) => !s.points) ? <tr><td colSpan={8} className="k">Первые срезы появятся в течение 5–10 минут после обновления панели.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
