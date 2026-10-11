import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, expectedPanelIps } from './ctx.js';
import { clientConfig, credsFields, credsOf, extractFromZip, newTunnel, nodeConfig } from './mgmt.js';
import { bootstrapSnippet } from './bootstrap.js';
import { renderPlan } from './firewall.js';
import { PRIVATE_NETS, Vpn } from './vpn.js';
import { Ops } from './ops.js';

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-mgmt-'));
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 2)));
  setSetting(db, 'executor.ips', ['198.51.100.65']);
  db.prepare(`INSERT INTO servers (id, name, host, ssh_port, role, key_pub, key_priv_sealed, sudo_mode, ssh_ports, seen_from_ip)
    VALUES ('n1', 'n1', '203.0.113.7', 22, 'entry', 'k', ?, 'restricted', '[22]', '127.0.0.1')`).run(ctx.seal('PRIVATE-SSH-KEY'));
  const t = newTunnel([]);
  ctx.updateServer('n1', { mgmt_mode: 'tunnel', ...credsFields(ctx, t) });
  return { db, ctx, t };
}

test('tunnel keys: x25519 in Xray format, public key matches private', () => {
  const t = newTunnel([45000]);
  assert.match(t.privateKey, /^[A-Za-z0-9_-]{43}$/);
  assert.match(t.publicKey, /^[A-Za-z0-9_-]{43}$/);
  const priv = createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: t.privateKey, x: t.publicKey }, format: 'jwk' });
  assert.equal(createPublicKey(priv).export({ format: 'jwk' }).x, t.publicKey);
  assert.match(t.uuid, /^[0-9a-f-]{36}$/);
  assert.match(t.shortId, /^[0-9a-f]{16}$/);
  assert.ok(t.port >= 20000 && t.port < 60000);
  assert.ok(t.localPort >= 40000 && t.localPort < 50000 && t.localPort !== 45000);
});

test('node config only reaches local SSH; client config maps local port to node', () => {
  const t = newTunnel([]);
  const n = nodeConfig(t, 3333) as any;
  assert.equal(n.outbounds.length, 1, 'единственный outbound');
  assert.deepEqual(n.outbounds[0], { tag: 'ssh', protocol: 'freedom', settings: { redirect: '127.0.0.1:3333' } });
  assert.equal(n.inbounds[0].port, t.port);
  assert.equal(n.inbounds[0].streamSettings.realitySettings.privateKey, t.privateKey);
  assert.deepEqual(n.inbounds[0].settings.clients, [{ id: t.uuid, flow: 'xtls-rprx-vision' }]);
  const c = clientConfig([{ id: 'n1', host: '203.0.113.7', sshPort: 3333, creds: t }]) as any;
  assert.equal(c.inbounds[0].listen, '127.0.0.1');
  assert.equal(c.inbounds[0].port, t.localPort);
  const out = c.outbounds.find((o: any) => o.tag === 'out-n1');
  assert.equal(out.settings.vnext[0].address, '203.0.113.7');
  assert.equal(out.settings.vnext[0].port, t.port);
  assert.equal(out.streamSettings.realitySettings.publicKey, t.publicKey);
  assert.equal(JSON.stringify(c).includes(t.privateKey), false, 'приватный ключ узла не попадает в клиента');
  assert.deepEqual(c.routing.rules, [{ type: 'field', inboundTag: ['in-n1'], outboundTag: 'out-n1' }]);
});

/** Минимальный zip-писатель для теста: stored и deflate. */
function makeZip(files: Array<{ name: string; data: Buffer; deflate: boolean }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let off = 0;
  for (const f of files) {
    const body = f.deflate ? zlib.deflateRawSync(f.data) : f.data;
    const name = Buffer.from(f.name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(f.deflate ? 8 : 0, 8);
    lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(f.deflate ? 8 : 0, 10);
    ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, body);
    centrals.push(ch, name);
    off += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

test('zip extraction (stored and deflate)', () => {
  const bin = Buffer.alloc(50_000, 7);
  const zip = makeZip([
    { name: 'README.md', data: Buffer.from('hello'), deflate: false },
    { name: 'xray', data: bin, deflate: true },
  ]);
  assert.deepEqual(extractFromZip(zip, 'xray'), bin);
  assert.equal(extractFromZip(zip, 'README.md').toString(), 'hello');
  assert.throws(() => extractFromZip(zip, 'geoip.dat'), /нет geoip\.dat/);
});

test('tunnel bootstrap snippet: valid bash, from= has 127.0.0.1, embedded config parses', () => {
  const t = newTunnel([]);
  const snip = bootstrapSnippet({
    panelIps: ['198.51.100.65'], pubkey: 'ssh-ed25519 AAAA test',
    mgmt: { creds: t, sshPort: 22, xray: { version: '25.10.15', sha: { amd64: 'a'.repeat(64), arm64: 'b'.repeat(64) } } },
  });
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'snip-')), 'b.sh');
  fs.writeFileSync(p, snip);
  execFileSync('bash', ['-n', p]);
  assert.match(snip, /PANEL_IPS="127\.0\.0\.1,198\.51\.100\.65"/);
  assert.match(snip, new RegExp(`MGMT_PORT=${t.port}\\n`));
  assert.match(snip, /XRAY_SHA=a{64}/);
  const cfg = snip.split("<<'MGMT_EOF'\n")[1]!.split('\nMGMT_EOF')[0]!;
  assert.equal(JSON.parse(cfg).inbounds[0].settings.clients[0].id, t.uuid);
  // прямой режим не меняется
  const direct = bootstrapSnippet({ panelIps: ['198.51.100.65'], pubkey: 'ssh-ed25519 AAAA test' });
  assert.doesNotMatch(direct, /fleet-mgmt/);
  assert.match(direct, /PANEL_IPS="198\.51\.100\.65"/);
});

test('tunnel node: SSH target is the local port, firewall opens the tunnel port, 127.0.0.1 is expected', async () => {
  const { ctx, db, t } = fixture();
  const r = ctx.server('n1');
  assert.deepEqual(credsOf(ctx, r), t);
  const tg = ctx.target(r);
  assert.equal(tg.host, '127.0.0.1');
  assert.equal(tg.port, t.localPort);
  await assert.rejects(tg.prepare!(), /не запущен/);
  assert.ok(expectedPanelIps(r, ['198.51.100.65']).includes('127.0.0.1'));

  const plan = renderPlan(ctx, r, 'P3');
  assert.deepEqual(plan.lint, [], 'узел видит панель с 127.0.0.1 — для туннеля это норма');
  assert.match(plan.text, new RegExp(`^\\s+tcp dport ${t.port} accept$`, 'm'));

  const ops = new Ops(ctx);
  assert.match(ops.lintPort(r, t.port, 'tcp') ?? '', /служебный туннель/);
  assert.equal(ops.lintPort(r, t.port, 'udp'), null);

  db.prepare(`UPDATE servers SET mgmt_mode = 'direct' WHERE id = 'n1'`).run();
  const d = ctx.server('n1');
  assert.equal(ctx.target(d).host, '203.0.113.7');
  assert.ok(renderPlan(ctx, d, 'P3').lint.some((l) => l.includes('127.0.0.1')), 'для прямого канала 127.0.0.1 — подозрительно');
});

test('user cores block local and private destinations', () => {
  const { ctx, db } = fixture();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES ('t1', 'rv', 'xray', 'vless-reality', 8443, '["sni.example"]', '["n1"]')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib1', 't1', 'n1', 'direct', 8443, 'tcp', 'active', ?, 'PUB', 'aa11')`).run(ctx.seal('PRIV'));
  const x = new Vpn(ctx).renderXray(ctx.server('n1')) as any;
  assert.equal(x.routing.domainStrategy, 'IPOnDemand');
  const block = x.routing.rules.findIndex((r: any) => r.ip && r.outboundTag === 'block');
  assert.equal(block, 1, 'сразу после правила API, раньше правил пользователей');
  for (const n of ['127.0.0.0/8', '::1/128', '10.0.0.0/8', '169.254.0.0/16']) assert.ok(x.routing.rules[block].ip.includes(n), n);
  assert.ok(PRIVATE_NETS.includes('127.0.0.0/8'));
});

test('bot proxy: service client on the chosen inbound, HTTP proxy in the main server client', async () => {
  const { ctx, db } = fixture();
  const { saveBotProxy, botProxyClientPart, botProxyOptions } = await import('./botproxy.js');
  db.prepare(`UPDATE servers SET mgmt_mode = 'direct' WHERE id = 'n1'`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('t1', 'tr', 'xray', 'trojan', 8443, '["www.apple.com"]', '["n1"]', '{"security":"reality"}')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib1', 't1', 'n1', 'direct', 8443, 'tcp', 'active', ?, 'PUB', 'aa11')`).run(ctx.seal('PRIV'));
  assert.deepEqual(botProxyOptions(ctx).map((o) => `${o.serverId}/${o.templateId}`), ['n1/t1']);
  assert.equal(botProxyClientPart(ctx), null, 'выключен — прокси нет');
  saveBotProxy(ctx, { enabled: true, serverId: 'n1', templateId: 't1' });
  const part = botProxyClientPart(ctx) as any;
  assert.equal(part.inbound.protocol, 'http');
  assert.equal(part.inbound.listen, '127.0.0.1');
  assert.equal(part.outbound.protocol, 'trojan');
  assert.equal(part.outbound.settings.servers[0].address, '203.0.113.7');
  const x = new Vpn(ctx).renderXray(ctx.server('n1')) as any;
  const bot = x.inbounds.find((i: any) => i.tag === 'in-ib1').settings.clients.find((c: any) => c.email === 'svc.bot');
  assert.equal(bot.password, part.outbound.settings.servers[0].password, 'секрет бота совпадает на узле и в клиенте');
  const cfg = clientConfig([], part) as any;
  assert.deepEqual(cfg.routing.rules[0], { type: 'field', inboundTag: ['bot-in'], outboundTag: 'bot-out' });
});

test('ядро, остановленное вручную, выкат не запускает', async () => {
  const { ctx, db } = fixture();
  db.prepare(`UPDATE servers SET cores = '{"xray":{"version":"26.3.27"}}' WHERE id = 'n1'`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES ('t1', 'rv', 'xray', 'vless-reality', 8443, '["sni.example"]', '["n1"]')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib1', 't1', 'n1', 'direct', 8443, 'tcp', 'active', ?, 'PUB', 'aa11')`).run(ctx.seal('PRIV'));
  const calls: string[] = [];
  const n = {
    op: async (a: (string | number)[]) => { calls.push(String(a[0])); return { code: 0, stdout: '', stderr: '' }; },
    must: async (a: (string | number)[]) => { calls.push(String(a[0])); return 'ok'; },
    stage: async () => 'hash',
  } as any;
  const { setSetting } = await import('./db.js');
  setSetting(db, 'core.off.n1', ['xray']);
  await new Ops(ctx).applyServer(ctx.server('n1'), n, () => undefined);
  assert.deepEqual(calls.slice(calls.indexOf('core-apply')), ['core-apply', 'core-stop'], 'после выката ядро снова остановлено');
  setSetting(db, 'core.off.n1', []);
  calls.length = 0;
  await new Ops(ctx).applyServer(ctx.server('n1'), n, () => undefined);
  assert.ok(!calls.includes('core-stop'));
});

test('первичный доступ через конфигурацию флота: служебный клиент svc.mgmt в inbound и outbound к нему', async () => {
  const { ctx, db } = fixture();
  db.prepare(`UPDATE servers SET mgmt_mode = 'direct' WHERE id = 'n1'`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES ('t1', 'rv', 'xray', 'vless-reality', 8443, '["sni.example"]', '["n1"]')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib1', 't1', 'n1', 'direct', 8443, 'tcp', 'active', ?, 'PUB', 'aa11')`).run(ctx.seal('PRIV'));
  const { viaOutbound } = await import('./onboard.js');
  const o = viaOutbound(ctx, { kind: 'fleet', serverId: 'n1', templateId: 't1' }).outbound as any;
  const x = new Vpn(ctx).renderXray(ctx.server('n1')) as any;
  const svc = x.inbounds.find((i: any) => i.tag === 'in-ib1').settings.clients.find((c: any) => c.email === 'svc.mgmt');
  assert.ok(svc, 'svc.mgmt есть в inbound узла');
  assert.equal(o.settings.vnext[0].users[0].id, svc.id, 'секрет совпадает');
  assert.equal(o.settings.vnext[0].address, '203.0.113.7');
  assert.throws(() => viaOutbound(ctx, { kind: 'fleet', serverId: 'n1', templateId: 'nope' }), /не выкачена/);
});

test('пользователь получает профили только выбранных конфигураций', () => {
  const { ctx, db } = fixture();
  db.prepare(`UPDATE servers SET mgmt_mode = 'direct' WHERE id = 'n1'`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES ('t1', 'rv', 'xray', 'vless-reality', 8443, '["sni.example"]', '["n1"]')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib1', 't1', 'n1', 'direct', 8443, 'tcp', 'active', ?, 'PUB', 'aa11')`).run(ctx.seal('PRIV'));
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, template_ids) VALUES ('u1', 'a', 's1', 'k1', NULL), ('u2', 'b', 's2', 'k2', '["t-other"]')`).run();
  const vpn = new Vpn(ctx);
  const u = (id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
  assert.equal(vpn.profiles(u('u1')).length, 1);
  assert.equal(vpn.profiles(u('u2')).length, 0, 'конфигурация не выбрана — профиля нет');
  const emails = (vpn.renderXray(ctx.server('n1')) as any).inbounds.find((i: any) => i.tag === 'in-ib1').settings.clients.map((c: any) => c.email);
  assert.ok(emails.includes('u1.d-t1'));
  assert.ok(!emails.some((e: string) => e.startsWith('u2.')), 'и на сервере его клиента нет');
});
