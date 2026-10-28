import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, expectedPanelIps } from './ctx.js';
import { clientConfig } from './mgmt.js';
import { Vpn } from './vpn.js';
import { viaOutbound } from './via.js';

/** nl-1 (203.0.113.9): панель на него не заходит; на нём VLESS REALITY «speedy» (6443) и Hysteria2 «hy». Вход ufo доходит. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-mgin-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 4)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, fail_since) VALUES ('nl', 'nl-1', '203.0.113.9', 'exit', 'k', ?, 'restricted', '2026-10-27T10:16:58Z')`).run(ctx.seal('KEY'));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES ('ufo', 'ufo', '198.51.100.3', 'entry', 'k', 'x', 'restricted')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('sp', 'speedy', 'xray', 'vless', 6443, '["www.apple.com"]', '["nl","ufo"]', '{"security":"reality"}')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('hy', 'hy', 'sing-box', 'hysteria2', 8444, '["hy.example"]', '["nl"]', '{"certMode":"self"}')`).run();
  for (const [id, t, s, port] of [['sp-nl', 'sp', 'nl', 6443], ['sp-ufo', 'sp', 'ufo', 6443], ['hy-nl', 'hy', 'nl', 8444]] as const)
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES (?, ?, ?, 'direct', ?, 'tcp', 'active', 'PUB', 'aa')`).run(id, t, s, port);
  return { db, ctx };
}

test('через конфигурацию: на узле SSH приходит от svc.mgmt того же inbound-а, клиент панели — VLESS к узлу, SSH на адрес узла', () => {
  const { ctx } = fixture();
  // svc.mgmt уже есть среди клиентов inbound-а узла — менять конфиг узла не нужно
  const x = new Vpn(ctx).renderXray(ctx.server('nl')) as any;
  assert.ok(x.inbounds.find((i: any) => i.tag === 'in-sp-nl').settings.clients.some((c: any) => c.email === 'svc.mgmt'));
  const out = viaOutbound(ctx, { kind: 'fleet', serverId: 'nl', templateId: 'sp' }).outbound;
  const via = viaOutbound(ctx, { kind: 'fleet', serverId: 'ufo', templateId: 'sp' }).outbound;
  const cfg = clientConfig([{ id: 'nl', host: '203.0.113.9', sshPort: 22, localPort: 45001, outbound: out, dest: '203.0.113.9', via }]) as any;
  const inb = cfg.inbounds.find((i: any) => i.tag === 'in-nl');
  assert.equal(inb.port, 45001);
  assert.deepEqual(inb.settings, { address: '203.0.113.9', port: 22, network: 'tcp' }, 'SSH — на адрес самого узла');
  const o = cfg.outbounds.find((i: any) => i.tag === 'out-nl');
  assert.equal(o.protocol, 'vless');
  assert.equal(o.settings.vnext[0].address, '203.0.113.9');
  assert.equal(o.settings.vnext[0].port, 6443, 'порт конфигурации, уже открытый');
  assert.equal(o.streamSettings.security, 'reality');
  assert.equal(o.streamSettings.sockopt.dialerProxy, 'via-nl', 'цепочка через другой сервер');
  assert.equal(cfg.outbounds.find((i: any) => i.tag === 'via-nl').settings.vnext[0].address, '198.51.100.3');
  // адрес узла считается адресом панели (firewall и проверка «видит панель с …»)
  assert.ok(expectedPanelIps({ ...ctx.server('nl'), mgmt_mode: 'inbound' }, ['192.0.2.1']).includes('203.0.113.9'));
});

test('через конфигурацию: переключение канала — сервер недоступен, значит подсказка для консоли; Hysteria2 нельзя', async () => {
  const { ctx, db } = fixture();
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { serverRoutes } = await import('./routes/servers.js');
  await serverRoutes(app, ctx);
  const patch = (payload: object) => app.inject({ method: 'PATCH', url: '/api/v1/servers/nl', payload });
  assert.match((await patch({ mgmtMode: 'inbound' })).body, /выберите конфигурацию/);
  assert.match((await patch({ mgmtMode: 'inbound', mgmtTemplate: 'hy' })).body, /Xray-конфигурация/);
  const r = await patch({ mgmtMode: 'inbound', mgmtTemplate: 'sp' });
  assert.equal(r.statusCode, 200, r.body);
  assert.equal(r.json().consoleHint, 'fleetctl allow 203.0.113.9');
  const s = db.prepare(`SELECT mgmt_mode, mgmt_template, mgmt_local_port FROM servers WHERE id = 'nl'`).get() as { mgmt_mode: string; mgmt_template: string; mgmt_local_port: number };
  assert.deepEqual([s.mgmt_mode, s.mgmt_template], ['inbound', 'sp']);
  assert.ok(s.mgmt_local_port >= 40000);
  // SSH панели теперь идёт на локальный порт клиента
  const t = ctx.target(ctx.server('nl'));
  assert.deepEqual([t.host, t.port], ['127.0.0.1', s.mgmt_local_port]);
  assert.match(t.via!, /конфигурацию на 203\.0\.113\.9/);
  // обратно напрямую
  setSetting(db, 'executor.ips', ['192.0.2.1']);
  assert.equal((await patch({ mgmtMode: 'direct' })).statusCode, 200);
  assert.equal(ctx.server('nl').mgmt_mode, 'direct');
  await app.close();
});
