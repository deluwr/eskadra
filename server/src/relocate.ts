/**
 * Экстренный переезд панели: бэкап прежней панели восстановили на другом сервере (прежний главный недоступен).
 *
 * Панель помнит, на какой машине работает (panel.machine: /etc/machine-id и ключ хоста SSH). При запуске на другой
 * машине данные правятся так же, как при плановом переносе (migrate.ts, prepareMovedDb):
 *  - прежний главный сервер-узел (mgmt_mode = 'local') становится обычным relay с SSH по сети: его конфигурации
 *    остаются, пока он не вернётся (тогда — сниппет подключения заново: ключ панели был разрешён только с 127.0.0.1);
 *  - адрес этого сервера — первым в адресах исполнителя, прежний убирается; адрес подписок с прежнего IP — на новый;
 *  - panel.relocated — для «Требует внимания»: этот сервер становится главным одной кнопкой («Главный сервер — вход»),
 *    узлам с прямым SSH нужно разрешить новый адрес.
 * Старые бэкапы без panel.machine: переезд виден по ключу хоста главного сервера-узла.
 */
import fs from 'node:fs';
import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import type { Ctx, ServerRow } from './ctx.js';
import type { ExecResult } from './ssh/executor.js';
type NodeOp = (args: (string | number)[], o?: { stdin?: string; timeoutMs?: number }) => Promise<ExecResult>;
import { getSetting, setSetting } from './db.js';
import { fingerprintOf } from './ssh/executor.js';
import { audit } from './lib/audit.js';

export interface Machine { machineId: string | null; hostKeyFp: string | null; ip: string | null }
export interface Relocated { at: string; fromIp: string | null; fromServer: { id: string; name: string } | null; toIp: string | null }

const read = (p: string) => { try { return fs.readFileSync(p, 'utf8').trim(); } catch { return null; } };

/** Эта машина: machine-id, отпечаток ed25519-ключа хоста SSH (как у серверов флота), публичный адрес панели. */
export function currentMachine(): Machine {
  const mid = read('/etc/machine-id');
  const pub = read('/etc/ssh/ssh_host_ed25519_key.pub');
  let fp: string | null = null;
  try { if (pub) fp = fingerprintOf(Buffer.from(pub.split(/\s+/)[1] ?? '', 'base64')).fp; } catch { fp = null; }
  const host = process.env.FLEET_PUBLIC_HOST?.trim() || null;
  return { machineId: mid && /^[0-9a-f]{32}$/.test(mid) ? mid : null, hostKeyFp: fp, ip: host };
}

/** Та же ли машина: по machine-id (не меняется при смене ключей SSH), иначе по ключу хоста; null — не понять. */
export function sameMachine(a: Machine, b: Machine): boolean | null {
  if (a.machineId && b.machineId) return a.machineId === b.machineId;
  if (a.hostKeyFp && b.hostKeyFp) return a.hostKeyFp === b.hostKeyFp;
  return null;
}

/** Адрес панели доменом (FLEET_PUBLIC_HOST = pnl.example) — IPv4 этого домена: адреса исполнителя — это IP. */
export async function resolveIp(m: Machine): Promise<Machine> {
  if (!m.ip || isIP(m.ip)) return m;
  try { return { ...m, ip: (await dns.lookup(m.ip, { family: 4 })).address }; } catch { return m; }
}

/**
 * Переезд уже был, а IP этого сервера тогда не узнали (адрес панели — домен, до v1.2.2): дописать его в адреса
 * исполнителя первым и перевести на него подписки — как сделал бы переезд.
 */
export function healRelocation(ctx: Ctx, cur: Machine): boolean {
  const r = relocatedOf(ctx);
  if (!r || r.toIp || !cur.ip || !isIP(cur.ip)) return false;
  setSetting(ctx.db, 'executor.ips', [cur.ip, ...ctx.executorIps().filter((x) => x !== cur.ip && x !== r.fromIp)]);
  if (r.fromIp && getSetting<string>(ctx.db, 'sub.host', '') === r.fromIp) setSetting(ctx.db, 'sub.host', cur.ip);
  setSetting(ctx.db, 'panel.relocated', { ...r, toIp: cur.ip });
  audit(ctx.db, 'system', 'panel.relocated_ip', undefined, { ip: cur.ip });
  return true;
}

/** Отметка на сервере прежней панели (ставит новая через nodekit): «панелью теперь управляют отсюда». */
export const SUPERSEDED_FILE = '/etc/fleet/panel-superseded';
const URL_RE = /^https:\/\/[A-Za-z0-9.-]{1,253}(:\d{1,5})?\/[A-Za-z0-9_/-]{0,128}$/;

/** Адрес этой панели для отметки: https://<FLEET_PUBLIC_HOST>:<порт><путь>; null — адрес неизвестен. */
export function panelUrl(host = process.env.FLEET_PUBLIC_HOST?.trim() ?? '', port = Number(process.env.FLEET_PORT ?? 0), base = process.env.FLEET_BASE_PATH ?? '/'): string | null {
  if (!host || !port) return null;
  const u = `https://${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${port}${base.startsWith('/') ? base : `/${base}`}`;
  return URL_RE.test(u) ? u : null;
}

/**
 * Новая панель после переезда: на прежнем главном сервере (теперь relay этой панели) ставится отметка — прежняя
 * панель там видит её и уходит в «перенесена»: бот выключен, бэкапы и уведомления больше не шлёт (их было по два).
 */
export async function retireOldPanel(ctx: Ctx, ensureKit: (s: ServerRow, n: { op: NodeOp }) => Promise<void>, log: (s: string) => void): Promise<boolean> {
  const r = relocatedOf(ctx);
  if (!r?.fromServer || getSetting<boolean>(ctx.db, `panel.retired.${r.fromServer.id}`, false)) return false;
  const url = panelUrl();
  const s = ctx.servers().find((x) => x.id === r.fromServer!.id);
  if (!url || !s || s.sudo_mode !== 'restricted' || s.mgmt_mode === 'local') return false;
  await ctx.onNode(s, async (n) => {
    await ensureKit(s, n);
    const res = await n.op(['panel-retire', url], { timeoutMs: 30_000 });
    if (res.code !== 0) throw new Error((res.stderr || res.stdout).trim() || `exit ${res.code}`);
  });
  setSetting(ctx.db, `panel.retired.${s.id}`, true);
  audit(ctx.db, 'system', 'panel.old_retired', s.id, { url });
  log(`прежняя панель на ${s.name} получила отметку: бэкапы, уведомления и бот там выключатся (панель — ${url})`);
  return true;
}

/**
 * Прежняя панель: на её сервере стоит отметка новой — перейти в «перенесена» (как после планового переноса):
 * фоновые задачи, бэкапы, уведомления и бот здесь больше не работают, в интерфейсе — ссылка на новую панель.
 */
export function checkSuperseded(ctx: Ctx, file = SUPERSEDED_FILE): string | null {
  if (getSetting<string | null>(ctx.db, 'panel.movedTo', null)) return null;
  const url = read(file);
  if (!url || !URL_RE.test(url) || url === panelUrl()) return null;
  setSetting(ctx.db, 'panel.movedTo', url);
  audit(ctx.db, 'system', 'panel.superseded', undefined, { url });
  return url;
}

export const relocatedOf = (ctx: Ctx) => getSetting<Relocated | null>(ctx.db, 'panel.relocated', null);

/** При запуске: панель на другой машине — поправить данные; вернуть, что сделано (null — та же машина или не понять). */
export function checkRelocation(ctx: Ctx, cur: Machine = currentMachine(), log: (s: string) => void = () => undefined): Relocated | null {
  const { db } = ctx;
  // ничего о себе не узнать (не Linux, нет прав) — ничего не трогаем
  if (!cur.machineId && !cur.hostKeyFp) return null;
  const rec = getSetting<Machine | null>(db, 'panel.machine', null);
  const local = ctx.servers().find((s) => s.mgmt_mode === 'local');
  const moved = rec
    ? sameMachine(rec, cur) === false
    // бэкап до этой версии: о машине знает только главный сервер-узел
    : !!(local?.host_key_fp && cur.hostKeyFp && local.host_key_fp !== cur.hostKeyFp);
  if (!moved) {
    if (!rec || rec.machineId !== cur.machineId || rec.hostKeyFp !== cur.hostKeyFp || rec.ip !== cur.ip) setSetting(db, 'panel.machine', cur);
    return null;
  }
  const fromIp = rec?.ip ?? local?.host ?? null;
  const toIp = cur.ip && isIP(cur.ip) ? cur.ip : null;
  // прежний главный сервер-узел — обычный relay (SSH по сети), его конфигурации на месте
  db.prepare(`UPDATE servers SET mgmt_mode = 'direct' WHERE mgmt_mode = 'local'`).run();
  // адрес исполнителя: этот — первым (по нему eskadra выпускает сертификат и сверяет домен), прежний — прочь
  if (toIp) {
    const ips = [toIp, ...ctx.executorIps().filter((x) => x !== toIp && x !== fromIp)];
    setSetting(db, 'executor.ips', ips);
    if (fromIp && getSetting<string>(db, 'sub.host', '') === fromIp) setSetting(db, 'sub.host', toIp);
  }
  // прежняя панель могла быть «перенесена» — здесь управляет эта
  db.prepare(`DELETE FROM settings WHERE key = 'panel.movedTo'`).run();
  const r: Relocated = { at: new Date().toISOString(), fromIp, fromServer: local ? { id: local.id, name: local.name } : null, toIp };
  setSetting(db, 'panel.relocated', r);
  setSetting(db, 'panel.machine', cur);
  audit(db, 'system', 'panel.relocated', local?.id, r);
  log(`панель запущена на другом сервере (${fromIp ?? '?'} → ${toIp ?? cur.ip ?? '?'}): ${local ? `прежний главный «${local.name}» переведён в relay, ` : ''}адрес исполнителя обновлён`);
  return r;
}
