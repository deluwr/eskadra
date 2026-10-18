/**
 * «Авто через вход» с распределением по нагрузке (autoMode 'spread').
 *
 * Пользователи «Авто» делятся на группы (по хешу id — группа пользователя не меняется). У каждой группы свой
 * «домашний» выход: группы раскладываются по выходам пропорционально ёмкости их каналов. Внутри группы — та же
 * цепочка уровней, что «по порядку» (vpn.ts): домашний выход, затем остальные; выход не отвечает — Xray входа сам
 * ведёт группу на следующий за секунды. Уровни всех групп ведут на общие outbound'ы выходов (to-…), так что вход
 * проверяет каждый выход один раз; сколько качает группа, панель считает по счётчикам её пользователей.
 *
 * Раз в минуту панель сравнивает загрузку канала каждого выхода (счётчики интерфейсов сервера) с его ёмкостью.
 * Выход загружен выше порога — самая тяжёлая группа, которая помещается в запас другого выхода, переводится туда
 * (назначение балансировщику первого уровня группы, без перезапуска Xray и без разрыва текущих соединений —
 * на новый выход уходят новые соединения). Нагрузка спала — группа возвращается домой: у пользователя снова
 * привычный IP выхода. Между переводами — пауза, чтобы нагрузка успела перетечь и решения не «качались».
 */
import { createHash } from 'node:crypto';
import type { Db } from './db.js';
import { getSetting } from './db.js';
import type { TemplateRow } from './ctx.js';
import type { Vpn } from './vpn.js';

/** Пауза между переводами групп (кроме возврата с неотвечающего выхода). */
export const SPREAD_COOLDOWN_MIN = 3;
/** Домой группа возвращается, когда домашний выход с ней будет загружен не выше порога минус этот запас. */
export const SPREAD_HOME_MARGIN = 0.2;
/** Группа, качающая меньше, не переводится: перевод ничего не даст, а IP у пользователей сменится. */
export const SPREAD_MIN_GROUP_MBPS = 1;

export const spreadBal = (t: string, g: number, level: number) => `sg-${t}-${g}-${level}`;
export const spreadLoop = (t: string, g: number, level: number) => `sgl-${t}-${g}-${level}`;
export const spreadLoopIn = (t: string, g: number, level: number) => `sgv-${t}-${g}-${level}`;

/** Группа пользователя: стабильна, пока не меняется число групп. */
export function spreadGroupOf(userId: string, groups: number): number {
  return createHash('sha256').update(userId).digest().readUInt32BE(0) % Math.max(1, groups);
}

/**
 * Домашний выход каждой группы. Ёмкости заданы у всех выходов — группы делятся пропорционально им
 * (наибольшие остатки, каждому выходу хотя бы одна группа); иначе — поровну, по кругу в заданном порядке.
 * Группы одного выхода не идут подряд: при смене числа групп меньше пользователей меняют дом.
 */
export function spreadHomes(exits: string[], caps: Record<string, number>, groups: number): string[] {
  if (!exits.length) return [];
  const g = Math.max(1, groups);
  const weighted = exits.every((x) => (caps[x] ?? 0) > 0);
  const counts = new Map<string, number>();
  if (weighted && g >= exits.length) {
    const total = exits.reduce((a, x) => a + caps[x]!, 0);
    const share = exits.map((x) => ({ x, exact: (g * caps[x]!) / total }));
    for (const s of share) counts.set(s.x, Math.max(1, Math.floor(s.exact)));
    let left = g - [...counts.values()].reduce((a, b) => a + b, 0);
    for (const s of [...share].sort((a, b) => (b.exact % 1) - (a.exact % 1) || exits.indexOf(a.x) - exits.indexOf(b.x))) {
      if (left <= 0) break;
      counts.set(s.x, counts.get(s.x)! + 1);
      left--;
    }
    // «хотя бы одна» могла дать лишние — забираем у тех, у кого больше всего
    while (left < 0) {
      const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]!;
      counts.set(top[0], top[1] - 1);
      left++;
    }
  } else exits.forEach((x, i) => counts.set(x, Math.floor(g / exits.length) + (i < g % exits.length ? 1 : 0)));
  const out: string[] = [];
  while (out.length < g) for (const x of exits) if ((counts.get(x) ?? 0) > 0) { out.push(x); counts.set(x, counts.get(x)! - 1); }
  return out.slice(0, g);
}

/** Цепочка выходов группы: домашний, затем остальные в заданном порядке. */
export const spreadChain = (home: string, exits: string[]) => [home, ...exits.filter((x) => x !== home)];

export interface SpreadExit { id: string; cap: number; load: number; alive: boolean }
export interface SpreadGroup { g: number; home: string; cur: string; mbps: number }
export interface SpreadMove { g: number; from: string; to: string; reason: 'dead' | 'overload' | 'home' }

/**
 * Одно решение за проверку. cap = 0 — ёмкость не задана: выход не считается перегруженным, запас у него не ограничен.
 * high — порог загрузки (0..1). cooldownOk — пауза после прошлого перевода прошла.
 */
export function planSpread(exits: SpreadExit[], groups: SpreadGroup[], high: number, cooldownOk: boolean): SpreadMove | null {
  const ex = new Map(exits.map((e) => [e.id, e]));
  const alive = (id: string) => !!ex.get(id)?.alive;
  // 1. группа переведена на выход, который перестал отвечать, — домой сразу, без паузы
  for (const gr of groups)
    if (gr.cur !== gr.home && !alive(gr.cur) && alive(gr.home)) return { g: gr.g, from: gr.cur, to: gr.home, reason: 'dead' };
  if (!cooldownOk) return null;
  const room = (e: SpreadExit) => (e.cap > 0 ? e.cap * high - e.load : Infinity);
  // 2. перегруженный выход: самую тяжёлую группу, которая помещается в запас другого выхода, — туда, где запаса больше
  const over = exits.filter((e) => e.alive && e.cap > 0 && e.load > e.cap * high).sort((a, b) => b.load / b.cap - a.load / a.cap);
  for (const x of over) {
    const on = groups.filter((gr) => gr.cur === x.id && gr.mbps >= SPREAD_MIN_GROUP_MBPS).sort((a, b) => b.mbps - a.mbps);
    const targets = exits.filter((e) => e.alive && e.id !== x.id).sort((a, b) => room(b) - room(a));
    for (const gr of on) {
      const y = targets.find((e) => gr.mbps <= room(e));
      if (y) return { g: gr.g, from: x.id, to: y.id, reason: 'overload' };
    }
  }
  // 3. нагрузка спала — группа домой, если дома ей хватит места с запасом
  for (const gr of groups) {
    if (gr.cur === gr.home || !alive(gr.home)) continue;
    const h = ex.get(gr.home)!;
    if (h.cap <= 0 || h.load + gr.mbps <= h.cap * Math.max(0.1, high - SPREAD_HOME_MARGIN)) return { g: gr.g, from: gr.cur, to: gr.home, reason: 'home' };
  }
  return null;
}

/**
 * Счётчики «Авто» конфигурации из `xray api statsquery -pattern user>>>` (без обнуления): байты по пользователю
 * (вверх + вниз) для e-mail вида `<user>.a-<шаблон>`.
 */
export function parseAutoUserStats(out: string, templateId: string): Map<string, number> {
  const bytes = new Map<string, number>();
  let data: { stat?: Array<{ name: string; value?: string | number }> } = {};
  try { data = JSON.parse(out || '{}'); } catch { return bytes; }
  const suffix = `.a-${templateId}`;
  for (const st of data.stat ?? []) {
    const m = st.name.match(/^user>>>([A-Za-z0-9._-]+)>>>traffic>>>(uplink|downlink)$/);
    if (!m || !m[1]!.endsWith(suffix)) continue;
    const u = m[1]!.slice(0, -suffix.length);
    bytes.set(u, (bytes.get(u) ?? 0) + Number(st.value ?? 0));
  }
  return bytes;
}

/**
 * Прирост счётчиков с прошлого чтения. Учёт трафика (workers.stats) раз в 5 минут обнуляет счётчики — значение
 * меньше прошлого значит обнуление, тогда прирост — само значение (часть до обнуления теряется, для оценки нагрузки не важно).
 */
export function counterDeltas(cur: Map<string, number>, prev: Record<string, number>): Map<string, number> {
  const out = new Map<string, number>();
  for (const [k, v] of cur) out.set(k, v >= (prev[k] ?? 0) ? v - (prev[k] ?? 0) : v);
  return out;
}

/** Замер канала сервера на самом сервере (nodekit link-test): скачивание и отдача, Мбит/с. */
export interface LinkTest { down: number; up: number; at: string; source?: 'ookla' | 'mirrors'; server?: string; note?: string }

export const linkTestOf = (db: Db, serverId: string) => getSetting<LinkTest | null>(db, `link.${serverId}`, null);

/** Ёмкость по замеру: меньшее из направлений (выход и качает из интернета, и отдаёт входу), шагом 10 Мбит/с — без дрожания раскладки. */
export const measuredCap = (l: LinkTest | null) => (l && l.down > 0 && l.up > 0 ? Math.max(10, Math.round(Math.min(l.down, l.up) / 10) * 10) : 0);

/** Разбор вывода link-test. */
export function parseLinkTest(out: string): LinkTest | null {
  const down = Number(out.match(/^down_mbps=(\d+)/m)?.[1] ?? NaN);
  const up = Number(out.match(/^up_mbps=(\d+)/m)?.[1] ?? NaN);
  if (!(Number.isFinite(down) && Number.isFinite(up) && down > 0 && up > 0)) return null;
  const source = out.match(/^source=(ookla|mirrors)$/m)?.[1] as LinkTest['source'];
  const server = out.match(/^server=(.{1,80})$/m)?.[1]?.trim();
  const note = out.match(/^note=(.{1,200})$/m)?.[1]?.trim();
  return { down, up, at: new Date().toISOString(), ...(source ? { source } : {}), ...(server ? { server } : {}), ...(note ? { note } : {}) };
}

/** Ёмкость каналов выходов: своё значение из конфигурации важнее замера; нет ни того, ни другого — 0 (не контролировать). */
export function spreadCaps(db: Db, manual: Record<string, number>, ids: string[]): Record<string, number> {
  return Object.fromEntries(ids.map((id) => [id, (manual[id] ?? 0) > 0 ? manual[id]! : measuredCap(linkTestOf(db, id))]));
}

/** Раскладка групп входа, как её рендерит vpn.ts: выходы с готовым outbound'ом и домашний выход каждой группы. */
export function spreadLayout(vpn: Vpn, db: Db, t: TemplateRow): { ids: string[]; homes: string[] } {
  const sp = vpn.spec(t);
  const ids = vpn.relayTargets(t).filter((x) => {
    const xi = vpn.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct'`, t.id, x.id)[0];
    return !!xi && (sp.security !== 'reality' || !!xi.public_key);
  }).map((x) => x.id);
  return { ids, homes: spreadHomes(ids, spreadCaps(db, sp.exitCapMbps, ids), sp.spreadGroups) };
}
