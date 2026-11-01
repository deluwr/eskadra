import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { attentionOf } from './attention.js';
import { Ops } from './ops.js';
import { mergeTwins, twinOf } from './twins.js';
import { Vpn } from './vpn.js';

/**
 * Панель переехала на сервер флота «gate» (вход, адрес — IP), потом главный сервер добавили во флот ещё раз —
 * запись «main» (local, адрес — домен панели). Это одна машина: ключ хоста одинаковый.
 */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-twins-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 7)));
  const add = (id: string, name: string, host: string, mode: string, created: string) =>
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, mgmt_mode, host_key_fp, ssh_port, created_at) VALUES (?, ?, ?, 'entry', ?, ?, ?, 'SHA256:same', ?, ?)`)
      .run(id, name, host, `pub-${name}`, `priv-${name}`, mode, mode === 'local' ? 2222 : 22, created);
  add('srv-gate', 'gate', '203.0.113.10', 'direct', '2026-01-01 00:00:00');
  add('srv-main', 'main', 'panel.example.com', 'local', '2026-02-01 00:00:00');
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, host_key_fp) VALUES ('srv-x', 'exit-1', '198.51.100.20', 'exit', 'k', 'x', 'SHA256:other')`).run();
  // старая конфигурация — через gate (сертификат на IP), новая — через main (свой домен)
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t-old', 'old', 'xray', 'vless', 22366, '[]', '["srv-x"]', 'srv-gate', 21810, ?)`)
    .run(JSON.stringify({ security: 'tls', certMode: 'ip' }));
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t-new', 'new', 'xray', 'vless', 35612, '[]', '["srv-x","srv-main"]', 'srv-main', 54259, ?)`)
    .run(JSON.stringify({ security: 'tls', certMode: 'domain', domains: { 'srv-main': 'vpn.example.com', 'srv-x': 'x.example.com' }, exitOrder: ['srv-main', 'srv-x'] }));
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('ib-old', 't-old', 'srv-gate', 'relay', 21810, 'tcp', 'active')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('ib-new', 't-new', 'srv-main', 'relay', 54259, 'tcp', 'active')`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, node_ids, excluded_profiles) VALUES ('u-1', 'ann', 's', 'k', '["srv-main","srv-gate"]', '["d:t-new:srv-main"]')`).run();
  db.prepare(`INSERT INTO user_creds (user_id, key, secret_sealed) VALUES ('u-1', 'hy:t-new:srv-main', 'sec')`).run();
  db.prepare(`INSERT INTO service_creds (key, secret_sealed) VALUES ('relay:t-new:srv-main:srv-x', 'svc')`).run();
  setSetting(db, 'tls.domain.srv-main', 'vpn.example.com');
  setSetting(db, 'applied.srv-main', 'x');
  setSetting(db, 'applied.srv-gate', 'y');
  setSetting(db, 'bot.proxy', { enabled: true, serverId: 'srv-main' });
  return { db, ctx };
}

test('один сервер двумя записями: видно в «Требует внимания», выкат на него не запускается', async () => {
  const { ctx } = fixture();
  assert.equal(twinOf(ctx, ctx.server('srv-gate'))?.id, 'srv-main');
  const att = attentionOf(ctx, new Vpn(ctx)).filter((a) => a.title.includes('один сервер двумя записями'));
  assert.equal(att.length, 1, 'одна карточка на пару');
  assert.equal(att[0]!.serverId, 'srv-gate');
  await assert.rejects(new Ops(ctx).applyServer(ctx.server('srv-main'), {} as never, () => undefined), /один и тот же сервер/);
});

test('объединение: остаётся запись с IP и выбранным именем — входы, конфигурации, пароли и доступ главного обеих', () => {
  const { db, ctx } = fixture();
  const r = mergeTwins(ctx, ctx.server('srv-main'), ctx.server('srv-gate'), 'main');
  assert.deepEqual(r, { id: 'srv-gate', clash: [] });
  assert.deepEqual(ctx.servers().map((s) => s.id).sort(), ['srv-gate', 'srv-x']);
  const s = ctx.server('srv-gate');
  assert.deepEqual([s.name, s.host], ['main', '203.0.113.10'], 'имя — выбранное, адрес — IP');
  assert.deepEqual([s.mgmt_mode, s.ssh_port, s.key_pub], ['local', 2222, 'pub-main'], 'доступ главного сервера перешёл к оставшейся записи');
  assert.equal(s.config_dirty, 1, 'конфиг сервера собирается заново из всех входов');
  assert.equal(twinOf(ctx, s), undefined);
  assert.deepEqual(db.prepare(`SELECT id, server_id, state FROM inbounds ORDER BY id`).all().map((x) => ({ ...x })),
    [{ id: 'ib-new', server_id: 'srv-gate', state: 'active' }, { id: 'ib-old', server_id: 'srv-gate', state: 'active' }]);
  const t = db.prepare(`SELECT node_ids, entry_id, settings FROM templates WHERE id = 't-new'`).get() as { node_ids: string; entry_id: string; settings: string };
  assert.equal(t.entry_id, 'srv-gate');
  assert.deepEqual(JSON.parse(t.node_ids), ['srv-x', 'srv-gate']);
  assert.deepEqual(JSON.parse(t.settings).domains, { 'srv-gate': 'vpn.example.com', 'srv-x': 'x.example.com' });
  assert.deepEqual(JSON.parse(t.settings).exitOrder, ['srv-gate', 'srv-x']);
  const u = db.prepare(`SELECT node_ids, excluded_profiles FROM users WHERE id = 'u-1'`).get() as { node_ids: string; excluded_profiles: string };
  assert.deepEqual(JSON.parse(u.node_ids), ['srv-gate']);
  assert.deepEqual(JSON.parse(u.excluded_profiles), ['d:t-new:srv-gate']);
  assert.ok(db.prepare(`SELECT 1 FROM user_creds WHERE key = 'hy:t-new:srv-gate'`).get(), 'пароли пользователей — те же');
  assert.ok(db.prepare(`SELECT 1 FROM service_creds WHERE key = 'relay:t-new:srv-gate:srv-x'`).get());
  assert.equal(getSetting(db, 'tls.domain.srv-gate', ''), 'vpn.example.com');
  assert.equal(getSetting(db, 'applied.srv-gate', null), null, 'отметка «выкачено» снята — конфиг применится заново');
  assert.equal(getSetting<{ serverId: string }>(db, 'bot.proxy', { serverId: '' }).serverId, 'srv-gate');
  assert.equal((db.prepare(`SELECT COUNT(*) AS n FROM settings WHERE instr(key, 'srv-main') > 0 OR instr(value, 'srv-main') > 0`).get() as { n: number }).n, 0);

  // куда идут клиенты: «свой домен» — на домен из конфигурации, сертификат на IP — на IP, REALITY — на адрес сервера
  const vpn = new Vpn(ctx);
  const spec = (id: string) => vpn.spec(vpn.template(id)!);
  assert.equal(vpn.clientHost(spec('t-new'), s), 'vpn.example.com');
  assert.equal(vpn.clientHost(spec('t-old'), s), '203.0.113.10');
  assert.equal(vpn.clientHost({ ...spec('t-new'), security: 'reality' }, s), '203.0.113.10');
});

test('объединение: разные серверы — отказ; совпавшие порты входов — в ответе', () => {
  const { db, ctx } = fixture();
  assert.throws(() => mergeTwins(ctx, ctx.server('srv-gate'), ctx.server('srv-x'), 'gate'), /разные серверы/);
  db.prepare(`UPDATE inbounds SET port = 21810 WHERE id = 'ib-new'`).run();
  assert.deepEqual(mergeTwins(ctx, ctx.server('srv-gate'), ctx.server('srv-main'), 'gate').clash, ['21810/tcp']);
});
