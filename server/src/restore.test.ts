import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { DatabaseSync } from 'node:sqlite';
import { getSetting, openDb, setSetting } from './db.js';
import { config } from './config.js';
import { loadOrCreateMasterKey, Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { backupPassword, backupSettings, Backups, saveBackupSettings, snapshotArchive } from './backup.js';
import { applyStagedRestore, armRestore, decryptBackup, stageRestore } from './restorelib.js';
import { decryptWithPassword, encryptWithPassword } from './lib/backupcrypt.js';
import { prepareMovedDb } from './migrate.js';

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-rs-'));
  (config as { dataDir: string }).dataDir = dir;
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(loadOrCreateMasterKey(dir)));
  db.prepare(`INSERT INTO admins (username, pw_hash, role, tg_id, backup_recipient) VALUES ('owner1', 'x', 'owner', '111111', 1)`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u1', 'anna', 's', 'k')`).run();
  return { dir, db, ctx };
}

test('бэкап: шифрование паролем — тот же пароль расшифровывает, другой нет', () => {
  const ct = encryptWithPassword(Buffer.from('данные'), 'длинный-пароль-1');
  assert.equal(decryptWithPassword(ct, 'длинный-пароль-1').toString(), 'данные');
  assert.throws(() => decryptWithPassword(ct, 'другой-пароль-22'), /пароль не подходит/);
  assert.notEqual(encryptWithPassword(Buffer.from('x'), 'p'.repeat(10)).toString('hex'), encryptWithPassword(Buffer.from('x'), 'p'.repeat(10)).toString('hex'), 'соль и IV — каждый раз новые');
});

test('бэкап: без пароля не делается; получатели — Telegram ID из настроек (прежние — из админов-получателей)', async () => {
  const { ctx, db } = fixture();
  // до v0.37 получатели — админы с отметкой: их Telegram становится списком
  assert.deepEqual(backupSettings(db).tgIds, ['111111']);
  const sent: Array<{ ids: string[] }> = [];
  const bot = { sendBackup: async (_n: string, _d: Buffer, ids: string[]) => { sent.push({ ids }); return { ok: ids.length, total: ids.length, errors: [] }; } } as never;
  const b = new Backups(ctx, bot);
  await assert.rejects(b.run('manual'), /пароль бэкапа/);
  saveBackupSettings(ctx, { tgIds: ['222222', '-1001234567'], time: '03:00', enabled: true }, 'пароль-бэкапа-1');
  assert.equal(backupPassword(ctx), 'пароль-бэкапа-1');
  assert.notEqual(getSetting<string>(db, 'backup.password', ''), 'пароль-бэкапа-1', 'пароль хранится зашифрованным');
  const r = await b.run('manual');
  assert.deepEqual(sent.at(-1)!.ids, ['222222', '-1001234567']);
  assert.equal(r.delivered, 2);
  assert.match(r.file, /\.tar\.gz\.enc$/);
  // null — пароль не меняется
  saveBackupSettings(ctx, { tgIds: ['222222'], time: '04:00', enabled: true }, null);
  assert.equal(backupPassword(ctx), 'пароль-бэкапа-1');
});

test('восстановление: копия → проверка паролем → подмена данных при запуске', async () => {
  const { dir, db, ctx } = fixture();
  saveBackupSettings(ctx, { tgIds: [], time: '03:00', enabled: true }, 'пароль-бэкапа-1');
  const bot = { sendBackup: async () => ({ ok: 0, total: 0, errors: [] }) } as never;
  const r = await new Backups(ctx, bot).run('manual');
  assert.equal(r.total, 0, 'без получателей — только локально');
  const file = fs.readFileSync(path.join(dir, 'backups', r.file));
  await assert.rejects(decryptBackup(file, 'не-тот-пароль'), /пароль не подходит/);
  const { manifest, files } = await decryptBackup(file, 'пароль-бэкапа-1');
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

test('восстановление: старые копии age (до v0.37) — по-прежнему приватным ключом age', async () => {
  const { db } = fixture();
  const id = await generateIdentity();
  const enc = new Encrypter();
  enc.addRecipient(await identityToRecipient(id));
  const file = Buffer.from(await enc.encrypt(snapshotArchive(db, 'full').archive));
  await assert.rejects(decryptBackup(file, 'какой-то пароль'), /старая копия \(age\)/);
  await assert.rejects(decryptBackup(file, await generateIdentity()), /ключ не подходит/);
  const { files } = await decryptBackup(file, `# key\n${id}\n`);
  assert.ok(files.get('fleet.db')!.length > 0);
});

test('перенос панели: копия базы — главный сервер становится узлом, подписки на новый адрес, флаг и сессии сняты', async () => {
  const { db } = fixture();
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, mgmt_mode) VALUES ('main', 'main', '198.51.100.1', 'entry', 'k', 'x', 'local')`).run();
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, mgmt_mode) VALUES ('pl', 'pl', '203.0.113.5', 'exit', 'k', 'x', 'direct')`).run();
  setSetting(db, 'sub.host', '198.51.100.1');
  setSetting(db, 'panel.movedTo', 'https://old/');
  db.prepare(`INSERT INTO sessions (token_hash, admin_id, expires_at) VALUES ('t', 1, datetime('now', '+1 hour'))`).run();
  const snap = snapshotArchive(db, 'move', (f) => prepareMovedDb(f, '198.51.100.1', '192.0.2.50'));
  const { files } = await decryptBackup(snap.archive, 'move');   // архив переноса не зашифрован
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-mv-')), 'fleet.db');
  fs.writeFileSync(out, files.get('fleet.db')!);
  const copy = new DatabaseSync(out, { readOnly: true });
  assert.deepEqual(copy.prepare(`SELECT id, mgmt_mode FROM servers ORDER BY id`).all().map((r) => ({ ...r })), [{ id: 'main', mgmt_mode: 'direct' }, { id: 'pl', mgmt_mode: 'direct' }]);
  assert.equal(JSON.parse((copy.prepare(`SELECT value FROM settings WHERE key = 'sub.host'`).get() as { value: string }).value), '192.0.2.50');
  assert.equal(copy.prepare(`SELECT 1 FROM settings WHERE key = 'panel.movedTo'`).get(), undefined);
  assert.equal((copy.prepare('SELECT COUNT(*) AS n FROM sessions').get() as { n: number }).n, 0);
  // живая база не тронута
  assert.equal((db.prepare(`SELECT mgmt_mode FROM servers WHERE id = 'main'`).get() as { mgmt_mode: string }).mgmt_mode, 'local');
  // подписки на домене остаются как есть
  setSetting(db, 'sub.host', 'sub.example.com');
  const snap2 = snapshotArchive(db, 'move', (f) => prepareMovedDb(f, '198.51.100.1', '192.0.2.50'));
  const f2 = path.join(path.dirname(out), 'b.db');
  fs.writeFileSync(f2, (await decryptBackup(snap2.archive, 'move')).files.get('fleet.db')!);
  assert.equal(JSON.parse((new DatabaseSync(f2, { readOnly: true }).prepare(`SELECT value FROM settings WHERE key = 'sub.host'`).get() as { value: string }).value), 'sub.example.com');
});

test('перенесённая панель: изменения запрещены (кроме возврата управления), просмотр работает', async () => {
  const { ctx, db } = fixture();
  const { default: Fastify } = await import('fastify');
  const { default: cookie } = await import('@fastify/cookie');
  const { requireAdmin, COOKIE } = await import('./routes/auth.js');
  const { sha256hex } = await import('./lib/crypto.js');
  db.prepare(`INSERT INTO sessions (token_hash, admin_id, expires_at) VALUES (?, 1, datetime('now', '+1 hour'))`).run(sha256hex('tok'));
  const app = Fastify();
  await app.register(cookie);
  const hook = requireAdmin(ctx);
  for (const url of ['/api/v1/x', '/api/v1/panel/move/cancel']) {
    app.get(url, { preHandler: hook }, async () => ({ ok: true }));
    app.post(url, { preHandler: hook }, async () => ({ ok: true }));
  }
  const call = (method: 'GET' | 'POST', url = '/api/v1/x') => app.inject({ method, url, headers: { cookie: `${COOKIE}=tok`, 'x-fleet': '1' } });
  assert.equal((await call('POST')).statusCode, 200);
  setSetting(db, 'panel.movedTo', 'https://192.0.2.50:7070/abc/');
  const no = await call('POST');
  assert.equal(no.statusCode, 409);
  assert.match(no.body, /перенесена на https:\/\/192\.0\.2\.50/);
  assert.equal((await call('GET')).statusCode, 200, 'просмотр работает');
  assert.equal((await call('POST', '/api/v1/panel/move/cancel')).statusCode, 200, 'вернуть управление можно');
  await app.close();
});
