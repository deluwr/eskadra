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
import { isIP } from 'node:net';
import type { Ctx } from './ctx.js';
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
