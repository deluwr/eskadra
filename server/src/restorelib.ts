/**
 * Восстановление из бэкапа: расшифровка приватным ключом age, проверка sha256 по манифесту, подготовка
 * файлов рядом с данными панели и их подмена при следующем запуске (пока база открыта, менять её нельзя).
 */
import fs from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { Decrypter } from 'age-encryption';
import { tarUnpack } from './lib/tar.js';
import { sha256hex } from './lib/crypto.js';

export interface Manifest { created: string; profile?: string; contents: Array<{ file: string; sha256: string }> }
export interface RestoreSummary { created: string; servers: number; users: number; admins: string[]; templates: number }

const FILES = ['fleet.db', 'master.key'] as const;

export async function decryptBackup(data: Buffer, identityText: string): Promise<{ manifest: Manifest; files: Map<string, Buffer> }> {
  const identity = identityText.split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith('AGE-SECRET-KEY-'));
  if (!identity) throw new Error('нужен приватный ключ age: строка AGE-SECRET-KEY-…');
  const d = new Decrypter();
  try { d.addIdentity(identity); } catch { throw new Error('ключ age повреждён: проверьте, что строка AGE-SECRET-KEY-… скопирована целиком'); }
  let plain: Uint8Array;
  try { plain = await d.decrypt(data); } catch { throw new Error('ключ не подходит к этой копии или файл не является бэкапом Эскадры'); }
  const entries = tarUnpack(gunzipSync(Buffer.from(plain)));
  const m = entries.find((f) => f.name === 'manifest.json');
  if (!m) throw new Error('в копии нет manifest.json');
  const manifest = JSON.parse(m.data.toString()) as Manifest;
  const files = new Map<string, Buffer>();
  for (const name of FILES) {
    const f = entries.find((x) => x.name === name);
    const want = manifest.contents.find((c) => c.file === name);
    if (!f || !want || sha256hex(f.data) !== want.sha256) throw new Error(`копия повреждена: ${name}`);
    files.set(name, f.data);
  }
  return { manifest, files };
}

const stageDir = (dataDir: string) => path.join(dataDir, 'restore');

/** Разложить проверенную копию в $DATA/restore и вернуть, что в ней. */
export function stageRestore(dataDir: string, manifest: Manifest, files: Map<string, Buffer>): RestoreSummary {
  const dir = stageDir(dataDir);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const [name, data] of files) fs.writeFileSync(path.join(dir, name), data, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
  const db = new DatabaseSync(path.join(dir, 'fleet.db'), { readOnly: true });
  try {
    const n = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
    return {
      created: manifest.created,
      servers: n('SELECT COUNT(*) AS n FROM servers'),
      users: n('SELECT COUNT(*) AS n FROM users'),
      templates: n('SELECT COUNT(*) AS n FROM templates'),
      admins: (db.prepare('SELECT username FROM admins ORDER BY id').all() as Array<{ username: string }>).map((a) => a.username),
    };
  } finally { db.close(); }
}

/** Пометить подготовленную копию к подмене при перезапуске. */
export function armRestore(dataDir: string) {
  const dir = stageDir(dataDir);
  if (!FILES.every((f) => fs.existsSync(path.join(dir, f)))) throw new Error('нет подготовленной копии — загрузите бэкап заново');
  fs.writeFileSync(path.join(dir, 'APPLY'), new Date().toISOString());
}

/** При запуске, до открытия базы: подменить данные подготовленной копией; прежние файлы сохраняются рядом. */
export function applyStagedRestore(dataDir: string, log: (s: string) => void) {
  const dir = stageDir(dataDir);
  if (!fs.existsSync(path.join(dir, 'APPLY'))) return;
  const stamp = Date.now();
  for (const f of ['fleet.db', 'fleet.db-wal', 'fleet.db-shm', 'master.key']) {
    const p = path.join(dataDir, f);
    if (fs.existsSync(p)) fs.renameSync(p, `${p}.before-restore-${stamp}`);
  }
  for (const f of FILES) fs.renameSync(path.join(dir, f), path.join(dataDir, f));
  fs.rmSync(dir, { recursive: true, force: true });
  log(`данные восстановлены из бэкапа; прежние файлы сохранены с суффиксом .before-restore-${stamp}`);
}
