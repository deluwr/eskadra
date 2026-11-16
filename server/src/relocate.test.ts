import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { attentionOf } from './attention.js';
import { checkRelocation, sameMachine, type Machine } from './relocate.js';

const OLD: Machine = { machineId: 'a'.repeat(32), hostKeyFp: 'SHA256:old', ip: '198.51.100.1' };
const NEW: Machine = { machineId: 'b'.repeat(32), hostKeyFp: 'SHA256:new', ip: '203.0.113.50' };

/** Главный сервер-узел main (local) на OLD, relay ru и выход pl по прямому SSH; подписки на IP старой панели. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-reloc-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 12)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, mgmt_mode, host_key_fp) VALUES ('main', 'relay', '198.51.100.1', 'entry', 'k', 'x', 'restricted', 'local', 'SHA256:old')`).run();
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp) VALUES ('pl', 'pl', '203.0.113.9', 'exit', 'k', 'x', 'restricted', 'SHA256:pl')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'duo', 'xray', 'vless', 8443, '["www.apple.com"]', '["pl"]', 'main', 9443, '{"security":"reality"}')`).run();
  setSetting(db, 'executor.ips', ['198.51.100.1', '192.0.2.7']);
  setSetting(db, 'sub.host', '198.51.100.1');
  return { db, ctx };
}

test('та же машина: ничего не меняется, панель запоминает, где работает', () => {
  const { db, ctx } = fixture();
  assert.equal(checkRelocation(ctx, OLD), null);
  assert.deepEqual(getSetting(db, 'panel.machine', null), OLD);
  // ключи SSH пересоздали, machine-id тот же — та же машина
  assert.equal(checkRelocation(ctx, { ...OLD, hostKeyFp: 'SHA256:regen' }), null);
  assert.equal(ctx.server('main').mgmt_mode, 'local');
  assert.deepEqual(ctx.executorIps(), ['198.51.100.1', '192.0.2.7']);
});

test('бэкап восстановили на другом сервере: прежний главный — relay, этот — исполнитель, подписки — на новый адрес', () => {
  const { db, ctx } = fixture();
  checkRelocation(ctx, OLD);
  const r = checkRelocation(ctx, NEW)!;
  assert.ok(r);
  assert.deepEqual([r.fromIp, r.toIp, r.fromServer], ['198.51.100.1', '203.0.113.50', { id: 'main', name: 'relay' }]);
  const main = ctx.server('main');
  assert.equal(main.mgmt_mode, 'direct', 'прежний главный — обычный узел с SSH по сети');
  assert.equal(main.role, 'entry');
  assert.equal((db.prepare(`SELECT entry_id FROM templates WHERE id = 't'`).get() as { entry_id: string }).entry_id, 'main', 'его конфигурации на месте');
  assert.deepEqual(ctx.executorIps(), ['203.0.113.50', '192.0.2.7']);
  assert.equal(getSetting(db, 'sub.host', ''), '203.0.113.50');
  assert.deepEqual(getSetting(db, 'panel.machine', null), NEW);
  // повторный запуск на новой машине — уже ничего не делает
  assert.equal(checkRelocation(ctx, NEW), null);
  // «Требует внимания»: сделать этот сервер главным
  const a = attentionOf(ctx, new Vpn(ctx)).find((x) => x.title.startsWith('Панель восстановлена на новом сервере'));
  assert.ok(a);
  assert.match(a.detail, /Сделать главный сервер входом/);
  assert.match(a.detail, /Прежний главный «relay» теперь relay/);
  // узел, на который панель не заходит, — в списке с командой
  ctx.updateServer('pl', { fail_since: new Date().toISOString() });
  assert.match(attentionOf(ctx, new Vpn(ctx)).find((x) => x.title.startsWith('Панель восстановлена'))!.detail, /pl\. Разрешите им новый адрес панели — в консоли хостера: fleetctl allow 203\.0\.113\.50/);
});

test('бэкап до этой версии (о машине не записано): переезд виден по ключу хоста главного сервера-узла', () => {
  const { ctx } = fixture();
  assert.ok(checkRelocation(ctx, NEW));
  assert.equal(ctx.server('main').mgmt_mode, 'direct');
  // а на той же машине — не переезд
  const f = fixture();
  assert.equal(checkRelocation(f.ctx, { machineId: null, hostKeyFp: 'SHA256:old', ip: null }), null);
  assert.equal(f.ctx.server('main').mgmt_mode, 'local');
});

test('о машине ничего не узнать — ничего не трогаем; домен вместо IP — адреса исполнителя не меняются', () => {
  const { db, ctx } = fixture();
  assert.equal(checkRelocation(ctx, { machineId: null, hostKeyFp: null, ip: '203.0.113.50' }), null);
  assert.equal(getSetting(db, 'panel.machine', null), null);
  assert.equal(sameMachine({ machineId: null, hostKeyFp: null, ip: null }, OLD), null);
  checkRelocation(ctx, OLD);
  assert.ok(checkRelocation(ctx, { ...NEW, ip: 'panel.example.net' }));
  assert.deepEqual(ctx.executorIps(), ['198.51.100.1', '192.0.2.7']);
});
