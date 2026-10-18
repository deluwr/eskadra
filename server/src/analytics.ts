/**
 * Аналитика: нагрузка серверов за последние двое суток и выгрузка диагностики (для человека или нейросети).
 *
 * Дёшево по устройству: раз в 5 минут — один короткий срез счётчиков с каждого сервера (та же команда host-stat,
 * что у живой статистики; главный сервер — прямо из /proc), одна строка в базе; старше 48 часов удаляется.
 * Журналы серверов панель не копирует: они и так лежат в journald на самих серверах и забираются только по кнопке
 * «Скачать» — уже сжатыми на сервере (nodekit diag: повторы схлопнуты, адреса клиентов замаскированы).
 */
import type { Ctx, TemplateRow } from './ctx.js';
import { getSetting } from './db.js';
import { localRaw, parseHostStat, type HostStats } from './hoststats.js';
import { paidDaysLeft } from './billing.js';
import { json } from './vpn.js';
import { specOf } from './protocols.js';
import { panelVersion } from './version.js';
import { Ops } from './ops.js';

export const KEEP_HOURS = 48;
const STEP_MIN = 5;

export interface MetricRow { server_id: string; at: string; cpu: number | null; load1: number | null; mem_pct: number | null; disk_pct: number | null; rx_mbps: number | null; tx_mbps: number | null }

/** Строка метрик из разобранного host-stat (скорости — по разнице с прошлым срезом того же сервера). */
export function metricOf(serverId: string, st: HostStats): MetricRow {
  const pct = (a?: { used: number; total: number } | null) => (a && a.total > 0 ? Math.round((a.used / a.total) * 1000) / 10 : null);
  const mbps = (bps: number | null | undefined) => (bps == null ? null : Math.round((bps * 8) / 1e5) / 10);
  return {
    server_id: serverId, at: st.at, cpu: st.cpuPct, load1: st.load?.[0] ?? null, mem_pct: pct(st.mem), disk_pct: pct(st.disk),
    rx_mbps: mbps(st.net?.rxBps), tx_mbps: mbps(st.net?.txBps),
  };
}

/** Серверы для аналитики: подключённые к панели (и главный сервер, если он узел). */
const monitored = (ctx: Ctx) => ctx.servers().filter((s) => s.sudo_mode === 'restricted' && s.host_key_fp);

/** Срез со всех серверов (воркер раз в 5 минут) и удаление старше 48 часов. Недоступный сервер просто пропускается. */
export async function collectMetrics(ctx: Ctx): Promise<number> {
  const ins = ctx.db.prepare(`INSERT OR REPLACE INTO host_metrics (server_id, at, cpu, load1, mem_pct, disk_pct, rx_mbps, tx_mbps) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  let n = 0;
  for (const s of monitored(ctx)) {
    if (s.fail_since) continue;
    try {
      const raw = s.mgmt_mode === 'local' ? localRaw() : (await ctx.onNode(s, (x) => x.op(['host-stat'], { timeoutMs: 20_000 }))).stdout;
      const m = metricOf(s.id, parseHostStat(`metrics:${s.id}`, raw));
      ins.run(m.server_id, m.at, m.cpu, m.load1, m.mem_pct, m.disk_pct, m.rx_mbps, m.tx_mbps);
      n++;
    } catch { /* сервер недоступен — это ловит heartbeat */ }
  }
  ctx.db.prepare(`DELETE FROM host_metrics WHERE at < ?`).run(new Date(Date.now() - KEEP_HOURS * 3600_000).toISOString());
  return n;
}

export const METRICS_EVERY_MS = STEP_MIN * 60_000;

/** Сводка для страницы «Аналитика»: по серверу — ряд точек за 48 ч, средние и пики, события связи. */
export function analyticsSummary(ctx: Ctx) {
  const since = new Date(Date.now() - KEEP_HOURS * 3600_000).toISOString();
  const rows = ctx.db.prepare(`SELECT * FROM host_metrics WHERE at >= ? ORDER BY at`).all(since) as unknown as MetricRow[];
  const downs = ctx.db.prepare(`SELECT target, COUNT(*) n, MAX(json_extract(detail, '$.downMin')) worst FROM audit_log WHERE action = 'server.recovered' AND ts >= datetime('now', ?) GROUP BY target`)
    .all(`-${KEEP_HOURS} hours`) as Array<{ target: string; n: number; worst: number | null }>;
  return {
    hours: KEEP_HOURS, stepMin: STEP_MIN,
    servers: monitored(ctx).map((s) => {
      const r = rows.filter((x) => x.server_id === s.id);
      const stat = (k: keyof MetricRow) => {
        const v = r.map((x) => x[k] as number | null).filter((x): x is number => x != null);
        return v.length ? { avg: Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 10) / 10, max: Math.max(...v) } : null;
      };
      const d = downs.find((x) => x.target === s.id);
      return {
        id: s.id, name: s.name, role: s.role, down: !!s.fail_since, points: r.length,
        cpu: stat('cpu'), load1: stat('load1'), mem: stat('mem_pct'), disk: stat('disk_pct'), rx: stat('rx_mbps'), tx: stat('tx_mbps'),
        outages: d ? { count: d.n, worstMin: d.worst ?? 0 } : null,
        series: r.map((x) => ({ at: x.at, cpu: x.cpu, net: x.rx_mbps == null && x.tx_mbps == null ? null : Math.max(x.rx_mbps ?? 0, x.tx_mbps ?? 0) })),
      };
    }),
  };
}

const mdCell = (v: unknown) => String(v ?? '—').replace(/\|/g, '/').replace(/\n/g, ' ');
const table = (head: string[], rows: unknown[][]) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.map(mdCell).join(' | ')} |`)].join('\n');
const maskIp = (v: string) => v.replace(/\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b/g, '$1.$2.x.x');

/**
 * Файл диагностики за hours часов (Markdown): серверы и конфигурации без секретов, события панели, проверки выходов,
 * нагрузка по часам, сжатые журналы служб с каждого сервера (по 3 сервера параллельно). Адреса пользователей замаскированы.
 */
export async function buildDiagnostics(ctx: Ctx, hours: number, log: (l: string) => void = () => undefined): Promise<string> {
  const db = ctx.db;
  const now = new Date();
  const servers = ctx.servers();
  const name = (id: string | null) => servers.find((s) => s.id === id)?.name ?? id ?? '—';
  const out: string[] = [];
  out.push(`# Эскадра — диагностика за ${hours} ч`, '',
    `Собрано: ${now.toISOString()} · панель ${panelVersion()} · серверов: ${servers.length}`, '',
    'Как читать: «N× первый…последний | сообщение» — одинаковые строки журнала схлопнуты; адреса пользователей замаскированы (a.b.x.x), UUID — <uuid>. ' +
    'Время в журналах серверов — по часам сервера, в событиях панели — UTC.', '');

  out.push('## Серверы', '', table(['имя', 'id', 'роль', 'адрес', 'канал управления', 'nodekit', 'ядра', 'связь', 'оплачен до'],
    servers.map((s) => {
      const cores = json<Record<string, { version: string }>>(s.cores, {});
      const left = paidDaysLeft(s.paid_until);
      return [s.name, s.id, s.role, s.host, s.mgmt_mode, s.kit_version ?? '—', Object.entries(cores).map(([k, v]) => `${k} ${v.version}`).join(', ') || '—',
        s.fail_since ? `нет с ${s.fail_since}` : `ok (${s.last_seen_at ?? '—'})`, s.paid_until ? `${s.paid_until} (${left} дн.)` : '—'];
    })), '');

  const templates = db.prepare('SELECT * FROM templates ORDER BY created_at').all() as unknown as TemplateRow[];
  out.push('## Конфигурации', '', table(['имя', 'протокол', 'защита/транспорт', 'порт', 'вход', 'выходы', 'авто'],
    templates.map((t) => {
      const sp = specOf(t);
      const auto = !t.entry_id ? '—' : !sp.autoEnabled ? 'выключен' : sp.autoMode === 'spread' ? `по нагрузке (групп ${sp.spreadGroups}, порог ${sp.spreadHighPct}%)` : sp.autoMode;
      return [t.name, t.protocol, `${sp.security}/${sp.transport}${sp.flow ? ` ${sp.flow}` : ''}`, t.port, t.entry_id ? `${name(t.entry_id)}:${t.entry_port}` : 'напрямую',
        json<string[]>(t.node_ids, []).map(name).join(', '), auto];
    })), '');

  const health = db.prepare(`SELECT h.template_id, h.exit_id, h.rtt_ms, h.mbps, h.ok, h.error, h.exit_loc, h.checked_at FROM exit_health h`).all() as Array<Record<string, unknown>>;
  if (health.length) {
    out.push('## Проверки выходов (последние)', '', table(['конфигурация', 'выход', 'задержка, мс', 'Мбит/с', 'ok', 'ошибка', 'страна', 'когда'],
      health.map((h) => [templates.find((t) => t.id === h.template_id)?.name ?? h.template_id, name(h.exit_id as string), h.rtt_ms, h.mbps, h.ok ? 'да' : 'нет', h.error, h.exit_loc, h.checked_at])), '');
    for (const t of templates) {
      const st = getSetting<{ at: string; exits: Array<{ id: string; cap: number; load: number }>; groups: Array<{ g: number; home: string; cur: string; mbps: number; users: number }> } | null>(db, `spread.state.${t.id}`, null);
      if (!st) continue;
      out.push(`«${t.name}», по нагрузке на ${st.at}: ` + st.exits.map((e) => `${name(e.id)} ${Math.round(e.load)}/${e.cap || '?'} Мбит/с`).join(', ') + '; группы: ' +
        st.groups.map((g) => `${g.g + 1}:${name(g.cur)}${g.cur !== g.home ? `(дом ${name(g.home)})` : ''} ${g.users} польз. ${g.mbps} Мбит/с`).join('; '), '');
    }
  }

  // события панели: без входов в подписку («knock») и действий с пользователями — только серверы, конфигурации, система
  const events = db.prepare(`SELECT ts, actor, action, target, detail FROM audit_log WHERE ts >= datetime('now', ?) AND action NOT IN ('knock') AND action NOT LIKE 'user.%' ORDER BY ts`)
    .all(`-${hours} hours`) as Array<{ ts: string; actor: string; action: string; target: string | null; detail: string | null }>;
  const userEvents = db.prepare(`SELECT action, COUNT(*) n FROM audit_log WHERE ts >= datetime('now', ?) AND action LIKE 'user.%' GROUP BY action`).all(`-${hours} hours`) as Array<{ action: string; n: number }>;
  out.push(`## События панели (${events.length})`, '');
  for (const e of events.slice(-400)) out.push(`- ${e.ts} ${e.actor} ${e.action} ${name(e.target)} ${maskIp((e.detail ?? '').slice(0, 160))}`);
  if (userEvents.length) out.push('', 'События с пользователями (только количество): ' + userEvents.map((u) => `${u.action} ×${u.n}`).join(', '));
  out.push('');

  // нагрузка по часам: среднее и пик — компактнее 5-минутного ряда, а картину видно
  const rows = db.prepare(`SELECT * FROM host_metrics WHERE at >= ? ORDER BY at`).all(new Date(Date.now() - hours * 3600_000).toISOString()) as unknown as MetricRow[];
  out.push('## Нагрузка по часам (среднее/пик)', '');
  for (const s of monitored(ctx)) {
    const r = rows.filter((x) => x.server_id === s.id);
    if (!r.length) continue;
    const byHour = new Map<string, MetricRow[]>();
    for (const x of r) { const h = x.at.slice(0, 13); byHour.set(h, [...(byHour.get(h) ?? []), x]); }
    const agg = (xs: MetricRow[], k: keyof MetricRow) => {
      const v = xs.map((x) => x[k] as number | null).filter((x): x is number => x != null);
      return v.length ? `${Math.round(v.reduce((a, b) => a + b, 0) / v.length)}/${Math.round(Math.max(...v))}` : '—';
    };
    out.push(`### ${s.name}`, '', table(['час (UTC)', 'CPU %', 'load', 'память %', 'диск %', 'вход Мбит/с', 'выход Мбит/с'],
      [...byHour.entries()].map(([h, xs]) => [h.replace('T', ' '), agg(xs, 'cpu'), agg(xs, 'load1'), agg(xs, 'mem_pct'), agg(xs, 'disk_pct'), agg(xs, 'rx_mbps'), agg(xs, 'tx_mbps')])), '');
  }

  // журналы с серверов: сжимаются на самих серверах; по 3 параллельно, недоступный — отметка и дальше
  out.push('## Журналы серверов', '');
  const nodes = monitored(ctx);
  const ops = new Ops(ctx);
  const results = new Map<string, string>();
  let i = 0;
  const worker = async () => {
    while (i < nodes.length) {
      const s = nodes[i++]!;
      log(`журналы ${s.name}…`);
      try {
        // diag появился в новом nodekit — старый обновляется здесь же
        const r = await ctx.onNode(s, async (n) => { await ops.ensureKit(s, n, () => undefined); return n.op(['diag', hours], { timeoutMs: 240_000 }); });
        results.set(s.id, r.code === 0 ? r.stdout : `(ошибка: ${(r.stderr || r.stdout).trim().slice(0, 300)})`);
      } catch (e) { results.set(s.id, `(сервер недоступен: ${(e as Error).message})`); }
    }
  };
  await Promise.all([worker(), worker(), worker()]);
  for (const s of nodes) {
    const body = (results.get(s.id) ?? '').replace(/^@host$/m, '#### Хост').replace(/^@services$/m, '#### Службы').replace(/^@log (.+)$/gm, '#### $1');
    out.push(`### ${s.name} (${s.role}, ${s.host})`, '', '```text', body.trim(), '```', '');
  }
  return out.join('\n') + '\n';
}

/** Имя файла выгрузки. */
export const diagFileName = (hours: number, at = new Date()) => `eskadra-diag-${at.toISOString().slice(0, 16).replace(/[:T]/g, '-')}-${hours}h.md`;

