/**
 * Обновление из панели (кнопка «Обновить»): панель работает без root, поэтому кладёт запрос с версией
 * в $DATA/update/request.json, а root-юнит eskadra-update.path запускает `eskadra update` и пишет журнал.
 */
import fs from 'node:fs';
import path from 'node:path';
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
