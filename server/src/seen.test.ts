import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { attentionOf, seenByEntries } from './attention.js';

/** Вход ufo, выход nl-1: панель на nl-1 не заходит (fail_since), а пробы «Авто» с ufo через nl-1 проходят. */
function fixture(checkedAgo: string) {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-seen-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 3)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, fail_since) VALUES ('nl', 'nl-1', '203.0.113.9', 'exit', 'k', 'x', '2026-10-27T10:16:58Z')`).run();
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed) VALUES ('ufo', 'ufo', '198.51.100.3', 'entry', 'k', 'x')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port) VALUES ('t', 'ru-hy', 'xray', 'vless', 443, '[]', '["nl"]', 'ufo', 9443)`).run();
  db.prepare(`INSERT INTO exit_health (template_id, exit_id, rtt_ms, ok, checked_at) VALUES ('t', 'nl', 205, 1, datetime('now', ?))`).run(checkedAgo);
  return { ctx, db };
}

test('панель не видит сервер, а вход видит — предупреждение вместо «нет связи»', () => {
  const { ctx } = fixture('-2 minutes');
  assert.deepEqual(seenByEntries(ctx, 'nl'), ['ufo']);
  const a = attentionOf(ctx, new Vpn(ctx)).filter((x) => x.serverId === 'nl');
  assert.equal(a.length, 1);
  assert.equal(a[0]!.level, 'warn');
  assert.match(a[0]!.title, /панель не видит сервер, а вход ufo видит/);
  assert.match(a[0]!.detail, /канал управления/);
});

test('давняя проверка входа (больше 30 минут) или неудачная — по-прежнему «нет связи»', () => {
  const { ctx, db } = fixture('-45 minutes');
  assert.deepEqual(seenByEntries(ctx, 'nl'), []);
  assert.equal(attentionOf(ctx, new Vpn(ctx)).find((x) => x.serverId === 'nl')?.level, 'fail');
  db.prepare(`UPDATE exit_health SET checked_at = datetime('now'), ok = 0`).run();
  assert.deepEqual(seenByEntries(ctx, 'nl'), []);
});
