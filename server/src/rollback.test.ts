import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// данные панели — во временной папке (config читает FLEET_DATA при загрузке)
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-rb-'));
process.env.FLEET_DATA = dataDir;

test('откат: копия базы при уходе с версии → подготовка → подмена при запуске старой версией', async () => {
  const { openDb } = await import('./db.js');
  const { snapshotDb, listSnapshots, stageRollbackData } = await import('./update.js');
  const { applyStagedRestore } = await import('./restorelib.js');
  fs.writeFileSync(path.join(dataDir, 'master.key'), 'KEY');
  let db = openDb(dataDir);
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u-1', 'до обновления', 's', 'k')`).run();
  // обновление с v0.25.0: копия данных этой версии
  const snap = snapshotDb(db, '0.25.0');
  assert.equal(snap?.version, 'v0.25.0');
  assert.equal(snapshotDb(db, 'dev'), null, 'dev-сборка — без копии');
  // на новой версии данные поменялись
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u-2', 'после обновления', 's2', 'k2')`).run();
  // откат на v0.25.0 с данными
  stageRollbackData('v0.25.0');
  assert.ok(fs.existsSync(path.join(dataDir, 'restore', 'APPLY')));
  assert.throws(() => stageRollbackData('v0.1.0'), /нет копии данных/);
  db.close();
  // запуск старой версии: подмена до открытия базы
  const logs: string[] = [];
  applyStagedRestore(dataDir, (m) => logs.push(m));
  db = openDb(dataDir);
  const names = (db.prepare('SELECT name FROM users ORDER BY id').all() as Array<{ name: string }>).map((u) => u.name);
  assert.deepEqual(names, ['до обновления']);
  assert.equal(fs.readFileSync(path.join(dataDir, 'master.key'), 'utf8'), 'KEY');
  assert.ok(fs.readdirSync(dataDir).some((f) => f.startsWith('fleet.db.before-restore-')), 'текущие данные сохранены рядом');
  assert.match(logs[0]!, /восстановлены/);
  // копии хранятся последние 8
  for (let i = 0; i < 10; i++) snapshotDb(db, `0.30.${i}`);
  assert.equal(listSnapshots().length, 8);
  db.close();
});
