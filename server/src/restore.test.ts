import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { openDb, setSetting } from './db.js';
import { config } from './config.js';
import { loadOrCreateMasterKey, Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Backups } from './backup.js';
import { applyStagedRestore, armRestore, decryptBackup, stageRestore } from './restorelib.js';

test('восстановление: копия → проверка → подмена данных при запуске', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-rs-'));
  (config as { dataDir: string }).dataDir = dir;
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(loadOrCreateMasterKey(dir)));
  const id = await generateIdentity();
  setSetting(db, 'backup', { recipients: [await identityToRecipient(id)], time: '03:00', enabled: true });
  db.prepare(`INSERT INTO admins (username, pw_hash, role) VALUES ('owner1', 'x', 'owner')`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u1', 'anna', 's', 'k')`).run();
  const bot = { sendBackup: async () => ({ ok: 0, total: 0, errors: [] }) } as never;
  const b = new Backups(ctx, bot);
  const r = await b.run('manual');
  const file = fs.readFileSync(path.join(dir, 'backups', r.file));

  await assert.rejects(decryptBackup(file, 'AGE-SECRET-KEY-1' + 'Q'.repeat(58)), /повреждён/);
  await assert.rejects(decryptBackup(file, await generateIdentity()), /ключ не подходит/);
  const { manifest, files } = await decryptBackup(file, `# key\n${id}\n`);
  db.prepare(`DELETE FROM users`).run();   // «после бэкапа» данные изменились
  const sum = stageRestore(dir, manifest, files);
  assert.deepEqual([sum.users, sum.admins], [1, ['owner1']]);
  armRestore(dir);
  db.close();
  applyStagedRestore(dir, () => undefined);
  const back = openDb(dir);
  assert.equal((back.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n, 1);
  assert.ok(fs.readdirSync(dir).some((f) => f.startsWith('fleet.db.before-restore-')));
  assert.ok(!fs.existsSync(path.join(dir, 'restore')));
});
