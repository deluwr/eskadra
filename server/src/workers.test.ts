import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { FastifyBaseLogger } from 'fastify';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { renderHash } from './ops.js';
import { Vpn } from './vpn.js';
import { Workers } from './workers.js';
import type { Backups } from './backup.js';
import type { Bot } from './bot.js';

function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-wk-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 5)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp) VALUES ('fi', 'fi-1', '203.0.113.7', 'exit', 'k', 'x', 'restricted', 'fp')`).run();
  let up = true;
  const calls: string[] = [];
  (ctx as unknown as { onNode: unknown }).onNode = async (s: { id: string }, fn: (n: unknown) => Promise<unknown>) => {
    calls.push(s.id);
    if (!up) throw new Error('Timed out while waiting for handshake');
    return fn({ op: async () => ({ code: 0, stdout: 'pong\n', stderr: '' }), must: async () => 'ok' });
  };
  const sent: string[] = [];
  const bot = { notifyAdmins: async (text: string) => { sent.push(text); } } as unknown as Bot;
  const log = { info: () => undefined, warn: () => undefined } as unknown as FastifyBaseLogger;
  const w = new Workers(ctx, log, {} as Backups, bot);
  const actions = () => (db.prepare(`SELECT action FROM audit_log WHERE target = 'fi' ORDER BY rowid`).all() as Array<{ action: string }>).map((r) => r.action);
  return { db, ctx, w, sent, calls, actions, setUp: (v: boolean) => { up = v; } };
}

test('heartbeat: одиночный сбой SSH — без уведомлений, в аудите server.blip', async () => {
  const f = fixture();
  f.setUp(false);
  await f.w.heartbeat();
  assert.ok(f.ctx.server('fi').fail_since, 'сбой отмечен');
  f.setUp(true);
  await f.w.heartbeat();
  assert.deepEqual(f.sent, [], 'бот молчит');
  assert.deepEqual(f.actions(), ['server.blip']);
  assert.equal(f.ctx.server('fi').fail_since, null);
});

test('heartbeat: три сбоя подряд — одно «не отвечает», после связи — «снова на связи» и server.recovered', async () => {
  const f = fixture();
  f.setUp(false);
  for (let i = 0; i < 4; i++) await f.w.heartbeat();
  assert.equal(f.sent.length, 1);
  assert.match(f.sent[0]!, /fi-1 не отвечает панели/);
  f.setUp(true);
  await f.w.heartbeat();
  assert.equal(f.sent.length, 2);
  assert.match(f.sent[1]!, /fi-1 снова на связи/);
  assert.deepEqual(f.actions(), ['server.recovered']);
  // счётчик сброшен: следующий одиночный сбой снова тихий
  f.setUp(false);
  await f.w.heartbeat();
  f.setUp(true);
  await f.w.heartbeat();
  assert.equal(f.sent.length, 2);
});

test('heartbeat: долгий сбой, начатый до перезапуска панели, — восстановление по длительности', async () => {
  const f = fixture();
  f.ctx.updateServer('fi', { fail_since: new Date(Date.now() - 10 * 60_000).toISOString() });
  await f.w.heartbeat();
  assert.equal(f.sent.length, 1);
  assert.match(f.sent[0]!, /снова на связи \(не отвечал 10 мин\)/);
  assert.deepEqual(f.actions(), ['server.recovered']);
});

test('syncDirty: конфиг не изменился — узел не трогаем, отметку снимаем; изменился — применяем', async () => {
  const f = fixture();
  f.ctx.updateServer('fi', { config_dirty: 1 });
  setSetting(f.db, 'applied.fi', renderHash(new Vpn(f.ctx), f.ctx.server('fi')));
  await f.w.syncDirty();
  assert.deepEqual(f.calls, [], 'без SSH и перезапуска ядер');
  assert.equal(f.ctx.server('fi').config_dirty, 0);

  f.ctx.updateServer('fi', { config_dirty: 1 });
  setSetting(f.db, 'applied.fi', 'старый отпечаток');
  await f.w.syncDirty();
  assert.deepEqual(f.calls, ['fi'], 'другой отпечаток — переприменение');
});
