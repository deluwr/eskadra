import { useEffect, useRef, useState } from 'react';
import { api, fmtBytes } from './api';
import { Addr } from './ui';

export interface HostStats {
  at: string; cpuPct: number | null; cpus: number; load: [number, number, number] | null;
  mem: { used: number; total: number } | null; disk: { used: number; total: number } | null;
  net: { rxBps: number | null; txBps: number | null; rxTotal: number; txTotal: number } | null;
  uptimeSec: number | null; ips: string[];
}

const mbit = (bps: number | null | undefined) => (bps === null || bps === undefined ? '—' : `${((bps * 8) / 1e6).toFixed(bps * 8 >= 1e8 ? 0 : 1)} Мбит/с`);
const upFor = (s: number | null) => {
  if (!s) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} дн ${h} ч` : h ? `${h} ч ${m} мин` : `${m} мин`;
};

function Meter({ label, pct, value }: { label: string; pct: number | null; value: string }) {
  const hot = pct !== null && pct >= 85;
  return (
    <div className="hs-m">
      <span className="k">{label}</span>
      <b className="mono">{value}</b>
      <div className={`bar ${hot ? 'hot' : ''}`}><span style={{ width: `${Math.max(0, Math.min(100, pct ?? 0))}%` }} /></div>
    </div>
  );
}

/** Живая статистика хоста: опрос, пока блок на экране; при ошибке — понятное сообщение без лишних запросов. */
export function HostStatsPanel({ url, pollMs = 3000 }: { url: string; pollMs?: number }) {
  const [st, setSt] = useState<HostStats | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    let t: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try { const s = await api.get<HostStats>(url); if (alive.current) { setSt(s); setErr(null); } }
      catch (e) { if (alive.current) setErr((e as Error).message); }
      // вкладка скрыта — опрашиваем реже
      if (alive.current) t = setTimeout(() => void tick(), document.hidden ? pollMs * 5 : pollMs);
    };
    void tick();
    return () => { alive.current = false; clearTimeout(t); };
  }, [url, pollMs]);
  if (!st) return <div className="hs k">{err ?? 'Загружаю статистику…'}</div>;
  const pct = (x: { used: number; total: number } | null) => (x && x.total ? Math.round((x.used / x.total) * 100) : null);
  return (
    <div className="hs">
      <div className="hs-grid">
        <Meter label={`ЦП · ${st.cpus} ядр.`} pct={st.cpuPct} value={st.cpuPct === null ? '…' : `${st.cpuPct}%`} />
        <Meter label="Память" pct={pct(st.mem)} value={st.mem ? `${fmtBytes(st.mem.used)} / ${fmtBytes(st.mem.total)}` : '—'} />
        <Meter label="Диск" pct={pct(st.disk)} value={st.disk ? `${fmtBytes(st.disk.used)} / ${fmtBytes(st.disk.total)}` : '—'} />
        <div className="hs-m">
          <span className="k">Сеть сейчас</span>
          <b className="mono"><span className="hs-dn">↓</span> {mbit(st.net?.rxBps)} <span className="hs-up">↑</span> {mbit(st.net?.txBps)}</b>
          <span className="k">{st.net ? `с загрузки: ↓ ${fmtBytes(st.net.rxTotal)} · ↑ ${fmtBytes(st.net.txTotal)}` : 'нет данных'}</span>
        </div>
      </div>
      <div className="hs-foot k">
        <span>{`работает ${upFor(st.uptimeSec)}`}</span>
        {st.load && <span>{`нагрузка ${st.load.map((x) => x.toFixed(2)).join(' ')}`}</span>}
        {st.ips.length > 0 && <span className="flex" style={{ gap: 6 }}>адреса {st.ips.map((ip) => <Addr key={ip} value={ip} />)}</span>}
        {err && <span style={{ color: 'var(--warn)' }}>{err}</span>}
      </div>
    </div>
  );
}
