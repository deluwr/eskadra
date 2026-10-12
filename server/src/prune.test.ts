import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, setSetting, getSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { coreMode, Ctx, type ServerRow } from './ctx.js';
import { pruneServerRefs } from './prune.js';

test('удалённый сервер: ссылки на него убираются из конфигураций, порядка «Авто», доменов, пользователей, ролей и прокси бота', () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-prune-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 2)));
  for (const id of ['srv-pl', 'srv-fi', 'srv-relay'])
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed) VALUES (?, ?, '203.0.113.1', 'exit', 'k', 'x')`).run(id, id);
  // как «quadro» на боевой панели: удалённый srv-old — в серверах и первым в порядке «Авто»
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'quadro', 'xray', 'vless', 443, '[]', ?, 'srv-relay', 8443, ?)`)
    .run(JSON.stringify(['srv-pl', 'srv-fi', 'srv-old']), JSON.stringify({ autoMode: 'order', exitOrder: ['srv-old', 'srv-pl', 'srv-fi'], domains: { 'srv-old': 'old.example', 'srv-pl': 'pl.example' } }));
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port) VALUES ('t2', 'via-old', 'xray', 'vless', 443, '[]', '["srv-pl"]', 'srv-gone', 9443)`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, node_ids) VALUES ('u-1', 'ann', 's', 'k', '["srv-old","srv-pl"]')`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, node_ids) VALUES ('u-2', 'bob', 's2', 'k2', '["srv-old"]')`).run();
  db.prepare(`INSERT INTO roles (id, name, scope) VALUES ('r', 'seller', '{"servers":["srv-old","srv-fi"]}')`).run();
  setSetting(db, 'bot.proxy', { enabled: true, serverId: 'srv-old', templateId: 't', port: 41000 });
  setSetting(db, 'applied.srv-old', 'x');

  const fixed = pruneServerRefs(ctx);
  assert.deepEqual(fixed.sort(), ['конфигурация quadro', 'конфигурация via-old', 'пользователь ann', 'пользователь bob', 'прокси бота', 'роль seller'].sort());
  const t = db.prepare(`SELECT * FROM templates WHERE id = 't'`).get() as { node_ids: string; settings: string; revision: number };
  assert.deepEqual(JSON.parse(t.node_ids), ['srv-pl', 'srv-fi']);
  assert.deepEqual(JSON.parse(t.settings).exitOrder, ['srv-pl', 'srv-fi']);
  assert.deepEqual(JSON.parse(t.settings).domains, { 'srv-pl': 'pl.example' });
  assert.equal(t.revision, 2, 'черновик изменился — его видно как невыкаченный');
  const t2 = db.prepare(`SELECT entry_id, entry_port FROM templates WHERE id = 't2'`).get() as { entry_id: string | null; entry_port: number | null };
  assert.deepEqual({ ...t2 }, { entry_id: null, entry_port: null });
  const nodes = (id: string) => JSON.parse((db.prepare('SELECT node_ids FROM users WHERE id = ?').get(id) as { node_ids: string }).node_ids);
  assert.deepEqual(nodes('u-1'), ['srv-pl']);
  assert.deepEqual(nodes('u-2'), [], 'был только удалённый сервер — «ни одного», а не «все»');
  assert.deepEqual(JSON.parse((db.prepare(`SELECT scope FROM roles WHERE id = 'r'`).get() as { scope: string }).scope).servers, ['srv-fi']);
  assert.equal(getSetting<{ enabled: boolean }>(db, 'bot.proxy', { enabled: true }).enabled, false);
  assert.equal(getSetting(db, 'applied.srv-old', null), null);
  assert.deepEqual(pruneServerRefs(ctx), [], 'повторно — ничего');
});

test('3x-ui: режим «внутри 3x-ui» только при работающей службе — остатки после удаления не в счёт', () => {
  const s = (active: string) => ({ core_mode: 'auto', external_cores: JSON.stringify([{ name: '3x-ui', active, version: '' }]) }) as unknown as ServerRow;
  assert.equal(coreMode(s('active')), 'xui');
  assert.equal(coreMode(s('inactive')), 'own');
  assert.equal(coreMode(s('')), 'own');
  assert.equal(coreMode({ ...s('inactive'), core_mode: 'xui' } as ServerRow), 'xui', 'выбранный вручную режим — как выбран');
});
