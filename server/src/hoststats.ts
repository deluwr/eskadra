/**
 * Живая статистика хостов: ЦП, память, диск, сеть (скорость и итог с загрузки), аптайм, адреса.
 * Главный сервер читает /proc сам; узлы отдают те же сырые счётчики командой fleet-core hoststat.
 * Скорости — по разнице двух последних замеров каждого хоста.
 */
import fs from 'node:fs';
import os from 'node:os';

export interface HostStats {
  at: string;
  cpuPct: number | null;
  cpus: number;
  load: [number, number, number] | null;
  mem: { used: number; total: number } | null;
  disk: { used: number; total: number } | null;
  net: { rxBps: number | null; txBps: number | null; rxTotal: number; txTotal: number } | null;
  uptimeSec: number | null;
  ips: string[];
}

interface Raw { cpu: { busy: number; total: number } | null; rx: number; tx: number; t: number }

const prev = new Map<string, Raw>();

function sections(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let cur = '';
  for (const line of text.split('\n')) {
    if (line.startsWith('@')) { cur = line.slice(1).trim(); out.set(cur, []); continue; }
    if (cur && line.trim()) out.get(cur)!.push(line);
  }
  return out;
}

/** Разбор вывода hoststat; key — чей это хост (для расчёта скоростей по прошлому замеру). */
export function parseHostStat(key: string, text: string, now = Date.now()): HostStats {
  const s = sections(text);
  const cpuLine = s.get('stat')?.[0]?.trim().split(/\s+/).slice(1).map(Number);
  // user nice system idle iowait irq softirq steal: занято — всё, кроме idle и iowait
  const cpu = cpuLine && cpuLine.length >= 4 ? { busy: cpuLine.reduce((a, b) => a + b, 0) - cpuLine[3]! - (cpuLine[4] ?? 0), total: cpuLine.slice(0, 8).reduce((a, b) => a + b, 0) } : null;
  const kb = (name: string) => Number(s.get('meminfo')?.find((l) => l.startsWith(name + ':'))?.match(/(\d+)/)?.[1] ?? NaN) * 1024;
  const memTotal = kb('MemTotal'), memAvail = kb('MemAvailable');
  let rx = 0, tx = 0, hasNet = false;
  for (const l of s.get('netdev') ?? []) {
    const [iface, rest] = l.split(':');
    if (!rest || iface!.trim() === 'lo') continue;
    const f = rest.trim().split(/\s+/).map(Number);
    rx += f[0] ?? 0; tx += f[8] ?? 0; hasNet = true;
  }
  const df = s.get('df')?.[0]?.trim().split(/\s+/);
  const load = s.get('loadavg')?.[0]?.split(/\s+/).slice(0, 3).map(Number);
  const p = prev.get(key);
  const dt = p ? (now - p.t) / 1000 : 0;
  const cpuPct = cpu && p?.cpu && cpu.total > p.cpu.total ? Math.round(((cpu.busy - p.cpu.busy) / (cpu.total - p.cpu.total)) * 1000) / 10 : null;
  prev.set(key, { cpu, rx, tx, t: now });
  return {
    at: new Date(now).toISOString(),
    cpuPct,
    cpus: Number(s.get('nproc')?.[0] ?? 1) || 1,
    load: load && load.length === 3 && load.every((x) => !Number.isNaN(x)) ? (load as [number, number, number]) : null,
    mem: Number.isFinite(memTotal) && Number.isFinite(memAvail) ? { used: memTotal - memAvail, total: memTotal } : null,
    disk: df && df.length >= 3 ? { used: Number(df[2]), total: Number(df[1]) } : null,
    net: hasNet ? { rxBps: p && dt > 0 && rx >= p.rx ? Math.round((rx - p.rx) / dt) : null, txBps: p && dt > 0 && tx >= p.tx ? Math.round((tx - p.tx) / dt) : null, rxTotal: rx, txTotal: tx } : null,
    uptimeSec: Number(s.get('uptime')?.[0]?.split(/\s+/)[0] ?? NaN) || null,
    ips: (s.get('ip') ?? []).map((x) => x.trim()).filter(Boolean),
  };
}

/** Тот же формат, что hoststat на узле, — с самого главного сервера (Linux: /proc; иначе — что даёт os). */
export function localRaw(): string {
  const read = (f: string) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
  const parts: string[] = [];
  const stat = read('/proc/stat');
  if (stat) {
    parts.push('@stat', stat.split('\n')[0]!, '@meminfo', ...read('/proc/meminfo').split('\n').filter((l) => /^(MemTotal|MemAvailable):/.test(l)),
      '@netdev', ...read('/proc/net/dev').split('\n').slice(2), '@uptime', read('/proc/uptime'), '@loadavg', read('/proc/loadavg'));
  } else {
    // не Linux (разработка): ЦП и память из os
    const t = os.cpus().reduce((a, c) => ({ user: a.user + c.times.user, nice: a.nice + c.times.nice, sys: a.sys + c.times.sys, idle: a.idle + c.times.idle, irq: a.irq + c.times.irq }), { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 });
    parts.push('@stat', `cpu ${t.user} ${t.nice} ${t.sys} ${t.idle} 0 ${t.irq} 0 0`, '@meminfo', `MemTotal: ${Math.round(os.totalmem() / 1024)} kB`, `MemAvailable: ${Math.round(os.freemem() / 1024)} kB`,
      '@uptime', String(os.uptime()), '@loadavg', os.loadavg().join(' '));
  }
  parts.push('@nproc', String(os.cpus().length));
  try { const st = fs.statfsSync('/'); parts.push('@df', `/ ${st.blocks * st.bsize} ${(st.blocks - st.bfree) * st.bsize} ${st.bavail * st.bsize} 0% /`); } catch { /* нет statfs */ }
  parts.push('@ip', ...Object.values(os.networkInterfaces()).flat().filter((i) => i && !i.internal && !/^(fe80|169\.254)/.test(i.address)).map((i) => i!.address));
  return parts.join('\n');
}
