/**
 * Обновление из панели (кнопка «Обновить»): панель работает без root, поэтому кладёт запрос с версией
 * в $DATA/update/request.json, а root-юнит eskadra-update.path запускает `eskadra update` и пишет журнал.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

const dir = () => path.join(config.dataDir, 'update');
const UNIT = '/etc/systemd/system/eskadra-update.path';

export const updateHelperInstalled = () => fs.existsSync(UNIT);

export function requestUpdate(version: string) {
  fs.mkdirSync(dir(), { recursive: true, mode: 0o750 });
  const f = path.join(dir(), 'request.json');
  fs.writeFileSync(f + '.new', JSON.stringify({ version, at: new Date().toISOString() }), { mode: 0o640 });
  fs.renameSync(f + '.new', f);
}

/** Журнал последнего обновления: идёт ли сейчас, код завершения, последние строки. */
export function updateStatus() {
  const f = path.join(dir(), 'log');
  const pending = fs.existsSync(path.join(dir(), 'request.json'));
  if (!fs.existsSync(f)) return { helper: updateHelperInstalled(), pending, running: false, exit: null as number | null, log: [] as string[], at: null as string | null };
  const lines = fs.readFileSync(f, 'utf8').replace(/\x1b\[[0-9;]*m/g, '').split('\n').filter(Boolean);
  const exitLine = lines.findLast((l) => /^exit=\d+$/.test(l));
  const mtime = fs.statSync(f).mtime;
  return {
    helper: updateHelperInstalled(),
    pending,
    running: !exitLine && Date.now() - mtime.getTime() < 30 * 60_000,
    exit: exitLine ? Number(exitLine.slice(5)) : null,
    log: lines.slice(-40),
    at: mtime.toISOString(),
  };
}

// ───── откат на прошлую версию: копия базы перед каждым обновлением ─────

const snapDir = () => path.join(dir(), 'snapshots');
const SNAP_KEEP = 8;
/** Версии, на которые откат возможен вместе с данными: они при запуске подменяют базу подготовленной копией (restorelib). */
export const MIN_ROLLBACK_WITH_DATA = '0.15.0';

export interface Snapshot { version: string; file: string; at: string; bytes: number }

const safeVer = (v: string) => (/^v?\d+\.\d+\.\d+$/.test(v) ? v.replace(/^v?/, 'v') : null);

/**
 * Копия базы, с которой панель уходит на другую версию: при откате на эту версию её данные можно вернуть.
 * VACUUM INTO — согласованная копия работающей базы (WAL учитывается). Хранятся последние SNAP_KEEP.
 */
export function snapshotDb(db: DatabaseSync, version: string): Snapshot | null {
  const v = safeVer(version);
  if (!v) return null;   // dev-сборка — не снимаем
  fs.mkdirSync(snapDir(), { recursive: true, mode: 0o700 });
  const file = path.join(snapDir(), `${v}.db`);
  fs.rmSync(file, { force: true });
  db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`);
  fs.chmodSync(file, 0o600);
  const all = listSnapshots().sort((a, b) => b.at.localeCompare(a.at));
  for (const s of all.slice(SNAP_KEEP)) fs.rmSync(path.join(snapDir(), s.file), { force: true });
  return listSnapshots().find((s) => s.version === v) ?? null;
}

export function listSnapshots(): Snapshot[] {
  if (!fs.existsSync(snapDir())) return [];
  return fs.readdirSync(snapDir()).filter((f) => /^v\d+\.\d+\.\d+\.db$/.test(f)).map((f) => {
    const st = fs.statSync(path.join(snapDir(), f));
    return { version: f.slice(0, -3), file: f, at: st.mtime.toISOString(), bytes: st.size };
  });
}

/**
 * Подготовить данные к откату: копия базы версии version и текущий master.key — в $DATA/restore с меткой APPLY.
 * Старая версия при запуске подменит ими данные (прежние файлы сохранятся с суффиксом .before-restore-…).
 */
export function stageRollbackData(version: string) {
  const v = safeVer(version);
  const snap = v ? path.join(snapDir(), `${v}.db`) : '';
  if (!v || !fs.existsSync(snap)) throw new Error(`нет копии данных версии ${version}`);
  const rd = path.join(config.dataDir, 'restore');
  fs.rmSync(rd, { recursive: true, force: true });
  fs.mkdirSync(rd, { recursive: true, mode: 0o700 });
  fs.copyFileSync(snap, path.join(rd, 'fleet.db'));
  fs.copyFileSync(path.join(config.dataDir, 'master.key'), path.join(rd, 'master.key'));
  for (const f of ['fleet.db', 'master.key']) fs.chmodSync(path.join(rd, f), 0o600);
  fs.writeFileSync(path.join(rd, 'manifest.json'), JSON.stringify({ created: new Date().toISOString(), profile: `rollback ${v}`, contents: [] }));
  fs.writeFileSync(path.join(rd, 'APPLY'), new Date().toISOString());
}
