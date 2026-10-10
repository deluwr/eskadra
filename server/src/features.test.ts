import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { base32Encode, totpAt, verifyTotp } from './lib/totp.js';
import { normalizeCidr } from './access.js';
import { tarPack, tarUnpack } from './lib/tar.js';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { renderPlan } from './firewall.js';
import { readKitFile, buildKitBundle } from './nodekit.js';

test('TOTP matches RFC 6238 vector', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(totpAt(secret, 59_000), '287082');
  assert.equal(totpAt(secret, 1111111109_000), '081804');
  assert.ok(verifyTotp(secret, totpAt(secret, Date.now())));
  assert.ok(!verifyTotp(secret, '000000', 59_000 + 10 * 60_000));
});

test('whitelist granularity', () => {
  assert.equal(normalizeCidr('94.25.170.33', 'exact'), '94.25.170.33/32');
  assert.equal(normalizeCidr('94.25.170.33', 'prefix'), '94.25.170.0/24');
  assert.equal(normalizeCidr('94.25.170.33', 'asn'), '94.25.0.0/16');
  assert.equal(normalizeCidr('2001:db8:1:2:3:4:5:6', 'exact'), '2001:0db8:0001:0002::/64');
  assert.equal(normalizeCidr('2001:db8::1', 'prefix'), '2001:0db8:0000::/48');
});

test('tar roundtrip', () => {
  const files = [{ name: 'a.txt', data: Buffer.from('hello') }, { name: 'b.bin', data: Buffer.alloc(1500, 7) }];
  const back = tarUnpack(tarPack(files));
  assert.deepEqual(back.map((f) => [f.name, f.data.length]), [['a.txt', 5], ['b.bin', 1500]]);
  assert.equal(back[1]!.data[1499], 7);
});

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-'));
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 1)));
  setSetting(db, 'executor.ips', ['198.51.100.65']);
  const add = (id: string, host: string, role: string, extra = '') =>
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, ssh_ports, seen_from_ip, direct_access${extra ? ', admin_ips' : ''})
      VALUES (?, ?, ?, ?, 'k', 'x', 'restricted', '[3333]', '198.51.100.65', ?${extra ? ', ?' : ''})`).run(id, id, host, role, role === 'exit' ? 0 : 1, ...(extra ? [extra] : []));
  add('entry', '203.0.113.1', 'entry', '["198.51.100.20"]');
  add('de', '203.0.113.2', 'exit');
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port) VALUES ('t1', 'rv', 'xray', 'vless-reality', 8443, '["sni.example"]', '["de"]', 'entry', 9443)`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib1', 't1', 'de', 'direct', 8443, 'tcp', 'active', ?, 'PUBDE', 'aa11')`).run(ctx.seal('PRIVDE'));
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key, short_id) VALUES ('ib2', 't1', 'entry', 'relay', 9443, 'tcp', 'active', ?, 'PUBEN', 'bb22')`).run(ctx.seal('PRIVEN'));
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u-00000001', 'alex', 's1', 'k1')`).run();
  return { db, ctx };
}

test('xray render: direct inbound + relay routing by user', () => {
  const { ctx } = fixture();
  const vpn = new Vpn(ctx);
  const de = vpn.renderXray(ctx.server('de')) as any;
  const deIn = de.inbounds.find((i: any) => i.tag === 'in-ib1');
  assert.equal(deIn.port, 8443);
  assert.equal(deIn.streamSettings.realitySettings.privateKey, 'PRIVDE');
  // exit скрыт (direct_access = 0): пользователи напрямую не добавляются, только служебный клиент входа
  assert.deepEqual(deIn.settings.clients.map((c: any) => c.email), ['svc.relay-entry-t1']);
  const en = vpn.renderXray(ctx.server('entry')) as any;
  const out = en.outbounds.find((o: any) => o.tag === 'to-t1-de');
  assert.equal(out.streamSettings.realitySettings.publicKey, 'PUBDE');
  assert.equal(out.settings.vnext[0].users[0].id, deIn.settings.clients[0].id, 'служебный UUID совпадает на входе и выходе');
  const rule = en.routing.rules.find((r: any) => r.outboundTag === 'to-t1-de');
  assert.deepEqual(rule.user, ['u-00000001.v-de']);
  assert.ok(en.routing.balancers[0].selector[0] === 'to-t1-');
});

test('profiles and links', () => {
  const { ctx, db } = fixture();
  const vpn = new Vpn(ctx);
  const u = db.prepare(`SELECT * FROM users WHERE id = 'u-00000001'`).get() as any;
  const ps = vpn.profiles(u);
  assert.deepEqual(ps.map((p) => p.name).sort(), ['de · через вход', 'Авто · через вход'].sort());
  const link = vpn.link(u, ps.find((p) => p.mode === 'via')!);
  assert.match(link, /^vless:\/\/[0-9a-f-]{36}@203\.0\.113\.1:9443\?/);
  assert.match(link, /pbk=PUBEN/);
  assert.match(link, /sid=bb22/);
  const via = ps.find((p) => p.mode === 'via')!;
  assert.equal(vpn.link(u, via), link, 'ссылка стабильна');
  vpn.rotateCreds(u.id);
  assert.notEqual(vpn.link(u, via), link, 'после перевыпуска UUID другой');
});

test('firewall plan: P3 restricts SSH to panel/admin, P2 opens it; lint catches unknown egress', () => {
  const { ctx, db } = fixture();
  const p3 = renderPlan(ctx, ctx.server('entry'), 'P3');
  assert.deepEqual(p3.lint, []);
  assert.match(p3.text, /policy drop;/);
  assert.match(p3.text, /ip  saddr @panel4 tcp dport \{ 3333 \} accept/);
  assert.match(p3.text, /set panel4  \{ type ipv4_addr; elements = \{ 198.51.100.65 \} \}/);
  assert.match(p3.text, /set admin4  \{ type ipv4_addr; elements = \{ 198\.51\.100\.20 \} \}/);
  assert.match(p3.text, /set fleet4  \{ type ipv4_addr; elements = \{ 203\.0\.113\.2 \} \}/);
  assert.match(p3.text, /set svc_tcp \{ type inet_service; elements = \{ 9443 \} \}/);
  assert.match(p3.shadow, /policy accept;/);
  assert.match(p3.shadow, /FLEET-WOULD-DROP/);
  const p2 = renderPlan(ctx, ctx.server('entry'), 'P2');
  assert.match(p2.text, /^\s+tcp dport \{ 3333 \} accept$/m);
  db.prepare(`UPDATE servers SET seen_from_ip = '9.9.9.9' WHERE id = 'entry'`).run();
  assert.ok(renderPlan(ctx, ctx.server('entry'), 'P3').lint.some((l) => l.includes('9.9.9.9')));
  db.prepare(`UPDATE servers SET ufw_active = 1 WHERE id = 'de'`).run();
  assert.ok(renderPlan(ctx, ctx.server('de'), 'P3').lint.some((l) => l.includes('ufw')));
});

test('new nodekit scripts are valid bash/python, kit bundle lists only allowed paths', () => {
  for (const f of ['fleet-core', 'fleet-gate', 'fleet-sshd-harden', 'fleet-exec', 'fleetctl']) {
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'k-')), f);
    fs.writeFileSync(p, readKitFile(`sbin/${f}`));
    execFileSync('bash', ['-n', p]);
  }
  const bundle = JSON.parse(buildKitBundle()) as { files: Array<{ dest: string }> };
  const allowed = readKitFile('sbin/fleet-kit-install');
  for (const f of bundle.files) assert.ok(allowed.includes(`"${f.dest}"`), `${f.dest} есть в ALLOWED`);
});

test('3x-ui: core detection, mode and inbound format', async () => {
  const { coresFrom, parseSections } = await import('./preflight.js');
  const { coreMode, foreignCore } = await import('./ctx.js');
  const cores = coresFrom(parseSections('\n### cores\nname=3x-ui active=active version=v2.6.0\nname=eskadra-xray active=active version=25.1.1\n'));
  assert.deepEqual(cores, [{ name: '3x-ui', active: 'active', version: 'v2.6.0' }], 'свои ядра eskadra-* не считаются чужими');
  const { ctx, db } = fixture();
  db.prepare(`UPDATE servers SET external_cores = ? WHERE id = 'de'`).run(JSON.stringify(cores));
  const de = ctx.server('de');
  assert.equal(coreMode(de), 'xui');
  assert.equal(foreignCore(de, 'xray')?.name, '3x-ui');
  assert.equal(foreignCore(de, 'sing-box'), undefined, 'sing-box рядом с 3x-ui не конфликтует');
  db.prepare(`UPDATE servers SET core_mode = 'own' WHERE id = 'de'`).run();
  assert.equal(coreMode(ctx.server('de')), 'own');
  const vpn = new Vpn(ctx);
  const ib = vpn.inbounds(`id = 'ib1'`)[0]!;
  const x = vpn.xuiInbound(ctx.server('de'), ib) as any;
  assert.equal(x.remark, 'eskadra-rv-ib1');
  assert.equal(x.port, 8443);
  const stream = JSON.parse(x.streamSettings);
  assert.equal(stream.realitySettings.privateKey, 'PRIVDE');
  assert.equal(stream.realitySettings.settings.publicKey, 'PUBDE');
  const settings = JSON.parse(x.settings);
  assert.equal(settings.clients[0].email, 'svc.relay-entry-t1');
  assert.equal(settings.clients[0].enable, true);
});

test('fleet-xui is valid python', (t) => {
  const cands = [process.env.PYTHON, 'python3', 'python'].filter(Boolean) as string[];
  const py = cands.find((c) => { try { execFileSync(c, ['-c', 'import sys; assert sys.version_info >= (3, 8)'], { stdio: 'ignore' }); return true; } catch { return false; } });
  if (!py) return t.skip('python не найден');
  execFileSync(py, ['-c', 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())', path.join(process.cwd(), '..', 'nodekit', 'sbin', 'fleet-xui')]);
});
