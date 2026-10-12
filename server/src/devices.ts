/**
 * Лимит устройств (одновременных подключений) на пользователя.
 *
 * Устройство — IP, с которого у пользователя сейчас открыты соединения. Xray (statsUserOnline) ведёт
 * для каждого email список таких IP; панель собирает их со всех узлов и объединяет по пользователю
 * (одно устройство через вход и напрямую — один IP, одно устройство).
 *
 * Первые N устройств по времени появления пропускаются, остальные блокируются правилом Xray
 * «email пользователя + IP источника → block». Правило касается только этого пользователя: другие
 * пользователи с той же конфигурации и даже с того же IP (общий NAT) не затрагиваются.
 * Устройство, пропавшее больше чем на HOLD, освобождает место — короткие паузы между запросами
 * его не отнимают, а смена сети (Wi-Fi → LTE) ждёт не дольше HOLD.
 */
import type { Ctx, UserRow } from './ctx.js';
import { effectiveLimits } from './vpn.js';

export const DEVICE_HOLD_MS = 2 * 60_000;

export interface DeviceRow { user_id: string; ip: string; first_seen: string; last_seen: string; blocked: number }

/** Email Xray → id пользователя (служебные клиенты svc.* — не пользователи). */
export const userOfEmail = (email: string) => email.match(/^(u-[0-9a-f]+)\./)?.[1] ?? null;

/** Какие устройства пропустить: первые limit по времени появления; limit null/0 — без лимита. */
export function decide(rows: Array<Pick<DeviceRow, 'ip' | 'first_seen'>>, limit: number | null): Set<string> {
  if (!limit) return new Set();
  const sorted = [...rows].sort((a, b) => a.first_seen.localeCompare(b.first_seen) || a.ip.localeCompare(b.ip));
  return new Set(sorted.slice(limit).map((r) => r.ip));
}

/**
 * Учесть, кто сейчас онлайн (user → IP), и пересчитать блокировки.
 * Возвращает заблокированные IP по пользователям и тех, у кого блокировка только что появилась.
 */
export function updateDevices(ctx: Ctx, online: Map<string, Set<string>>, now = new Date()): { blocked: Map<string, string[]>; newlyLimited: string[] } {
  const db = ctx.db;
  const ts = now.toISOString();
  const users = new Map((db.prepare(`SELECT * FROM users`).all() as unknown as UserRow[]).map((u) => [u.id, u]));
  const before = new Set((db.prepare('SELECT DISTINCT user_id FROM user_devices WHERE blocked = 1').all() as Array<{ user_id: string }>).map((r) => r.user_id));
  db.exec('BEGIN');
  try {
    const up = db.prepare(`INSERT INTO user_devices (user_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, ip) DO UPDATE SET last_seen = excluded.last_seen`);
    const seen = db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`);
    for (const [uid, ips] of online) if (users.has(uid) && ips.size) {
      for (const ip of ips) up.run(uid, ip, ts, ts);
      seen.run(`seen.${uid}`, JSON.stringify(ts));   // «был в сети» — после того, как строки устройств уйдут
    }
    // ушло дольше HOLD — место свободно; вернётся — станет новым устройством в конце очереди
    db.prepare('DELETE FROM user_devices WHERE last_seen < ?').run(new Date(now.getTime() - DEVICE_HOLD_MS).toISOString());
    const rows = db.prepare('SELECT * FROM user_devices ORDER BY user_id').all() as unknown as DeviceRow[];
    const byUser = new Map<string, DeviceRow[]>();
    for (const r of rows) byUser.set(r.user_id, [...(byUser.get(r.user_id) ?? []), r]);
    const set = db.prepare('UPDATE user_devices SET blocked = ? WHERE user_id = ? AND ip = ?');
    const blocked = new Map<string, string[]>();
    for (const [uid, list] of byUser) {
      const u = users.get(uid)!;
      const over = u.status === 'active' ? decide(list, effectiveLimits(ctx, u).devices) : new Set<string>();
      for (const r of list) if (Number(over.has(r.ip)) !== r.blocked) set.run(over.has(r.ip) ? 1 : 0, uid, r.ip);
      if (over.size) blocked.set(uid, [...over].sort());
    }
    db.exec('COMMIT');
    return { blocked, newlyLimited: [...blocked.keys()].filter((u) => !before.has(u)) };
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

/** Заблокированные сейчас IP по пользователям — из базы (для рендера конфига узла). */
export function blockedDevices(ctx: Ctx): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const r of ctx.db.prepare('SELECT user_id, ip FROM user_devices WHERE blocked = 1 ORDER BY user_id, ip').all() as Array<{ user_id: string; ip: string }>)
    out.set(r.user_id, [...(out.get(r.user_id) ?? []), r.ip]);
  return out;
}

/** Правила Xray: трафик пользователя с лишних устройств — в block. Только этот пользователь (по email), только эти IP. */
export function limitRules(blocked: Map<string, string[]>): object[] {
  return [...blocked].map(([uid, ips]) => ({ type: 'field', user: [`regexp:^${uid}\\.`], source: ips, outboundTag: 'block' }));
}
