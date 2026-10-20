import { test } from 'node:test';
import assert from 'node:assert/strict';
import { certName, hopRange, hy2InboundExtra, link, mtSecret, singboxOutbound, specOf, ssKey, telemtConfig, tlsServerName, xrayClient, xrayInbound, xrayOutbound } from './protocols.js';
import type { InboundRow } from './ctx.js';

const ib = (over: Partial<InboundRow> = {}): InboundRow => ({
  id: 'ib1', template_id: 't1', server_id: 'n1', kind: 'direct', port: 8443, proto: 'tcp', state: 'active',
  private_key_sealed: null, public_key: 'PUB', short_id: 'ab12', tls_pin: null, error: null, applied_at: null, ext_id: null, ...over,
});
const tpl = (protocol: string, settings: object, sni: string[] = ['www.apple.com']) =>
  specOf({ protocol: protocol as never, sni: JSON.stringify(sni), fingerprint: 'chrome', settings: JSON.stringify(settings) });
const U = '11111111-2222-4333-8444-555555555555';
const to = (over = {}) => ({ host: '203.0.113.7', port: 8443, name: 'de · напрямую', serverId: 'n1', inbound: ib(), ...over });

test('legacy vless-reality = VLESS + REALITY + Vision', () => {
  const sp = specOf({ protocol: 'vless-reality' as never, sni: '["www.apple.com"]', fingerprint: 'chrome', settings: '{}' });
  assert.equal(sp.protocol, 'vless');
  assert.equal(sp.security, 'reality');
  assert.equal(sp.flow, 'xtls-rprx-vision');
  const l = link(sp, U, to());
  assert.match(l, /^vless:\/\/.+\?encryption=none&type=tcp&security=reality&sni=www\.apple\.com&fp=chrome&pbk=PUB&sid=ab12&flow=xtls-rprx-vision#/);
});

test('VLESS over WebSocket + TLS with IP certificate', () => {
  const sp = tpl('vless', { security: 'tls', transport: 'ws', path: '/ws', certMode: 'ip' });
  assert.equal(sp.flow, '', 'Vision только для TCP');
  const name = certName(sp, 't1', 'n1', '203.0.113.7');
  assert.equal(name, 'ip');
  assert.equal(certName(sp, 't1', 'n1', 'node.example.com'), null, 'на домене сертификат на IP невозможен');
  const x = xrayInbound(sp, ib(), 'in-ib1', [xrayClient(sp, U, 'u.d-t1')], { cert: name }) as any;
  assert.equal(x.protocol, 'vless');
  assert.deepEqual(x.streamSettings.wsSettings, { path: '/ws' });
  assert.equal(x.streamSettings.tlsSettings.certificates[0].certificateFile, '/etc/eskadra/tls/ip/fullchain.pem');
  assert.deepEqual(x.settings.clients, [{ id: U, email: 'u.d-t1' }]);
  const l = link(sp, U, to());
  assert.match(l, /type=ws/);
  assert.match(l, /path=%2Fws/);
  assert.doesNotMatch(l, /sni=/, 'сертификат на IP — клиент проверяет адрес');
  assert.throws(() => xrayInbound(sp, ib(), 'x', [], { cert: null }), /нет сертификата/);
});

test('VMess over gRPC + TLS with per-node domain: vmess:// JSON link', () => {
  const sp = tpl('vmess', { security: 'tls', transport: 'grpc', serviceName: 'svc', certMode: 'domain', domains: { n1: 'de.example.com' } });
  assert.equal(certName(sp, 't1', 'n1', '203.0.113.7'), 'dom-de.example.com');
  assert.equal(tlsServerName(sp, 'n1'), 'de.example.com');
  const x = xrayInbound(sp, ib(), 'in', [xrayClient(sp, U, 'e')], { cert: 'dom-de.example.com' }) as any;
  assert.deepEqual(x.streamSettings.grpcSettings, { serviceName: 'svc' });
  assert.deepEqual(x.settings, { clients: [{ id: U, email: 'e' }] });
  const v = JSON.parse(Buffer.from(link(sp, U, to()).slice('vmess://'.length), 'base64').toString());
  assert.equal(v.net, 'grpc');
  assert.equal(v.path, 'svc');
  assert.equal(v.tls, 'tls');
  assert.equal(v.sni, 'de.example.com');
  assert.equal(v.add, '203.0.113.7');
});

test('Trojan + REALITY and Shadowsocks-2022 multi-user', () => {
  const tr = tpl('trojan', { security: 'reality' });
  const xi = xrayInbound(tr, ib(), 'in', [xrayClient(tr, U, 'e')], { privateKey: 'PRIV' }) as any;
  assert.equal(xi.streamSettings.realitySettings.privateKey, 'PRIV');
  assert.deepEqual(xi.settings.clients, [{ password: U, email: 'e' }]);
  assert.match(link(tr, U, to()), /^trojan:\/\/11111111-2222-4333-8444-555555555555@203\.0\.113\.7:8443\?type=tcp&security=reality/);

  const ss = tpl('shadowsocks', { ssMethod: '2022-blake3-aes-256-gcm' });
  const key = ssKey(U, ss.ssMethod);
  assert.equal(Buffer.from(key, 'base64').length, 32);
  assert.equal(Buffer.from(ssKey(U, '2022-blake3-aes-128-gcm'), 'base64').length, 16);
  const xs = xrayInbound(ss, ib({ public_key: 'SERVERKEY' }), 'in', [xrayClient(ss, U, 'e')], { ssServerKey: 'SERVERKEY' }) as any;
  assert.equal(xs.settings.method, '2022-blake3-aes-256-gcm');
  assert.equal(xs.settings.password, 'SERVERKEY');
  assert.equal(xs.settings.clients[0].password, key);
  assert.equal(xs.streamSettings, undefined);
  assert.equal(decodeURIComponent(link(ss, U, to({ inbound: ib({ public_key: 'SERVERKEY' }) })).split('@')[0]!.slice(5)), `2022-blake3-aes-256-gcm:SERVERKEY:${key}`);
});

test('relay outbound matches the exit inbound for each protocol', () => {
  for (const [p, st] of [['vless', { security: 'tls', certMode: 'ip' }], ['vmess', { security: 'none', transport: 'ws' }], ['trojan', { security: 'reality' }], ['shadowsocks', {}]] as const) {
    const sp = tpl(p, st);
    const o = xrayOutbound(sp, ib({ public_key: 'K' }), 'to-x', '203.0.113.9', U, 'n9') as any;
    assert.equal(o.protocol, p);
    if (p === 'trojan') assert.equal(o.settings.servers[0].password, U);
    if (p === 'shadowsocks') assert.equal(o.settings.servers[0].password, `K:${ssKey(U, sp.ssMethod)}`);
    if (p === 'vless') assert.equal(o.streamSettings.tlsSettings.serverName, '203.0.113.9');
  }
  assert.throws(() => xrayOutbound(tpl('hysteria2', {}), ib(), 'x', 'a', U, 'n'), /не поддерживается/);
});

test('Hysteria2 links: self-signed with pin, LE certificate without insecure, obfs', () => {
  const self = tpl('hysteria2', {}, ['hy.example']);
  assert.equal(self.certMode, 'self');
  const l1 = link(self, U, to({ inbound: ib({ tls_pin: 'aa'.repeat(32) }) }));
  assert.match(l1, /^hysteria2:\/\/.+\/\?sni=hy\.example&insecure=1&pinSHA256=a{64}#/);
  const le = tpl('hysteria2', { certMode: 'ip', hy2Obfs: 'secret' });
  const l2 = link(le, U, to());
  assert.doesNotMatch(l2, /insecure/);
  assert.match(l2, /obfs=salamander&obfs-password=secret/);
  const sb = singboxOutbound(le, U, to()) as any;
  assert.equal(sb.type, 'hysteria2');
  assert.deepEqual(sb.obfs, { type: 'salamander', password: 'secret' });
});

test('Hysteria2: client bandwidth (Brutal), port hopping, server side', () => {
  const sp = tpl('hysteria2', { certMode: 'ip', hy2UpMbps: 50, hy2DownMbps: 200, hy2Hop: '20000-30000', hy2HopInterval: 45 });
  const q = new URL(link(sp, U, to()).replace('hysteria2://', 'https://')).searchParams;
  assert.equal(q.get('upmbps'), '50');
  assert.equal(q.get('downmbps'), '200');
  assert.equal(q.get('mport'), '20000-30000');
  const sb = singboxOutbound(sp, U, to()) as any;
  assert.equal(sb.up_mbps, 50);
  assert.equal(sb.down_mbps, 200);
  assert.deepEqual(sb.server_ports, ['20000:30000']);
  assert.equal(sb.hop_interval, '45s');
  assert.equal(sb.server_port, 8443, 'основной порт остаётся');
  // без полосы и диапазона — ничего лишнего
  const plain = singboxOutbound(tpl('hysteria2', {}), U, to()) as any;
  assert.equal(plain.up_mbps, undefined);
  assert.equal(plain.server_ports, undefined);
  assert.doesNotMatch(link(tpl('hysteria2', {}), U, to()), /upmbps|mport/);

  assert.deepEqual(hy2InboundExtra(tpl('hysteria2', { hy2ServerUpMbps: 300, hy2Masquerade: 'https://www.bing.com/' })),
    { up_mbps: 300, masquerade: 'https://www.bing.com/' });
  assert.deepEqual(hy2InboundExtra(tpl('hysteria2', { hy2IgnoreClientBw: true, hy2ServerUpMbps: 300, hy2Obfs: 'o' })),
    { obfs: { type: 'salamander', password: 'o' }, ignore_client_bandwidth: true }, 'BBR — без потолка полосы');

  assert.deepEqual(hopRange('20000-30000'), [20000, 30000]);
  assert.equal(hopRange('30000-20000'), null);
  assert.equal(hopRange('80-1000'), null, 'системные порты не трогаем');
  assert.equal(hopRange(''), null);
});

test('MTProto: fake-TLS link and telemt config', () => {
  const sp = tpl('mtproto', { mtDomain: 'www.apple.com' });
  const l = link(sp, U, to({ port: 443 }));
  const secret = new URL(l.replace('tg://', 'https://x/')).searchParams.get('secret')!;
  assert.equal(secret, 'ee' + mtSecret(U) + Buffer.from('www.apple.com').toString('hex'));
  assert.match(mtSecret(U), /^[0-9a-f]{32}$/);
  const toml = telemtConfig(sp, 443, [{ name: 'u-1.d-t1', secret: U, maxIps: 3 }], '203.0.113.7');
  assert.match(toml, /^port = 443$/m);
  assert.match(toml, /^tls_domain = "www\.apple\.com"$/m);
  assert.match(toml, new RegExp(`^"u-1\\.d-t1" = "${mtSecret(U)}"$`, 'm'));
  assert.match(toml, /\[access\.user_max_unique_ips\]\n"u-1\.d-t1" = 3/);
  assert.ok(toml.indexOf('[access.users]') > toml.indexOf('[censorship]'), 'access — последней секцией (перезагрузка без рестарта)');
  assert.equal(singboxOutbound(sp, U, to()), null, 'MTProto в sing-box нет');
});

test('sing-box subscription: transports map, XHTTP skipped', () => {
  const ws = singboxOutbound(tpl('vless', { security: 'tls', transport: 'ws', path: '/p', host: 'cdn.example', certMode: 'custom', domain: 'v.example.com' }), U, to()) as any;
  assert.deepEqual(ws.transport, { type: 'ws', path: '/p', headers: { Host: 'cdn.example' } });
  assert.equal(ws.tls.server_name, 'v.example.com');
  assert.equal(singboxOutbound(tpl('vless', { security: 'reality', transport: 'xhttp' }), U, to()), null);
  const r = singboxOutbound(tpl('vless', { security: 'reality' }), U, to()) as any;
  assert.equal(r.tls.reality.public_key, 'PUB');
  assert.equal(r.flow, 'xtls-rprx-vision');
});
