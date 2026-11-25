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

test('переезд без IP (адрес панели — домен): при следующем запуске IP дописывается в адреса исполнителя', async () => {
  const { db, ctx } = fixture();
  checkRelocation(ctx, OLD);
  const r = checkRelocation(ctx, { ...NEW, ip: 'pnl.example.net' })!;
  assert.equal(r.toIp, null);
  assert.deepEqual(ctx.executorIps(), ['198.51.100.1', '192.0.2.7'], 'IP не узнали — адреса не трогали');
  const { healRelocation, resolveIp } = await import('./relocate.js');
  assert.deepEqual(await resolveIp({ ...NEW, ip: '203.0.113.50' }), { ...NEW, ip: '203.0.113.50' }, 'IP остаётся как есть');
  assert.equal(healRelocation(ctx, { ...NEW, ip: '203.0.113.50' }), true);
  assert.deepEqual(ctx.executorIps(), ['203.0.113.50', '192.0.2.7']);
  assert.equal(getSetting(db, 'sub.host', ''), '203.0.113.50');
  assert.equal(getSetting<{ toIp: string } | null>(db, 'panel.relocated', null)?.toIp, '203.0.113.50');
  // второй раз — уже нечего
  assert.equal(healRelocation(ctx, { ...NEW, ip: '203.0.113.50' }), false);
});

test('переезд: новая панель ставит отметку на прежнем главном; прежняя по ней — «перенесена» (бот, бэкапы, уведомления молчат)', async () => {
  const { retireOldPanel, checkSuperseded, panelUrl } = await import('./relocate.js');
  assert.equal(panelUrl('pnl.example.net', 43495, '/abc123/'), 'https://pnl.example.net:43495/abc123/');
  assert.equal(panelUrl('', 43495, '/'), null);
  // новая панель: переезд с главным-узлом «main» → отметка через nodekit на нём, один раз
  const { db, ctx } = fixture();
  checkRelocation(ctx, OLD);
  checkRelocation(ctx, NEW);
  const calls: string[][] = [];
  (ctx as unknown as { onNode: unknown }).onNode = async (_s: unknown, fn: (n: unknown) => Promise<unknown>) =>
    fn({ op: async (a: string[]) => { calls.push(a); return { code: 0, stdout: 'ok', stderr: '' }; } });
  const env = { h: process.env.FLEET_PUBLIC_HOST, p: process.env.FLEET_PORT, b: process.env.FLEET_BASE_PATH };
  Object.assign(process.env, { FLEET_PUBLIC_HOST: 'pnl.example.net', FLEET_PORT: '43495', FLEET_BASE_PATH: '/abc123/' });
  try {
    let kit = 0;
    assert.equal(await retireOldPanel(ctx, async () => { kit++; }, () => undefined), true);
    assert.deepEqual(calls, [['panel-retire', 'https://pnl.example.net:43495/abc123/']]);
    assert.equal(kit, 1, 'nodekit на прежнем главном обновляется (новая команда)');
    assert.equal(await retireOldPanel(ctx, async () => undefined, () => undefined), false, 'второй раз — нет');
    assert.equal(getSetting(db, 'panel.retired.main', false), true);
  } finally {
    for (const [k, v] of [['FLEET_PUBLIC_HOST', env.h], ['FLEET_PORT', env.p], ['FLEET_BASE_PATH', env.b]] as const) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }

  // прежняя панель: отметка на её сервере — «перенесена», бот молчит
  const old = fixture();
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-sup-')), 'panel-superseded');
  assert.equal(checkSuperseded(old.ctx, file), null, 'отметки нет');
  fs.writeFileSync(file, 'https://pnl.example.net:43495/abc123/\n');
  assert.equal(checkSuperseded(old.ctx, file), 'https://pnl.example.net:43495/abc123/');
  assert.equal(getSetting(old.db, 'panel.movedTo', null), 'https://pnl.example.net:43495/abc123/');
  assert.equal(checkSuperseded(old.ctx, file), null, 'уже перенесена');
  const { Bot } = await import('./bot.js');
  setSetting(old.db, 'bot.token', old.ctx.seal('123:abc'));
  old.db.prepare(`INSERT INTO admins (username, pw_hash, role, tg_id) VALUES ('a', 'x', 'owner', '42')`).run();
  const bot = new Bot(old.ctx, { info: () => undefined, warn: () => undefined } as never);
  let sent = 0;
  (bot as unknown as { send: unknown }).send = async () => { sent++; };
  await bot.notifyAdmins('тест');
  assert.equal(sent, 0, 'уведомления с перенесённой панели не уходят');
  assert.deepEqual(await bot.sendBackup('x', Buffer.from('x'), ['42']), { ok: 0, total: 0, errors: ['панель перенесена — бэкапы шлёт новая'] });
  // мусор в отметке — не трогаем
  const f2 = fixture();
  fs.writeFileSync(file, 'javascript:alert(1)\n');
  assert.equal(checkSuperseded(f2.ctx, file), null);
});
