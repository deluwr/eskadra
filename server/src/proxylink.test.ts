import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProxyLink } from './proxylink.js';

test('ссылка vless REALITY → outbound Xray', () => {
  const o = parseProxyLink('vless://0b2c-uuid@203.0.113.5:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12#pl-1') as any;
  assert.equal(o.protocol, 'vless');
  assert.deepEqual(o.settings.vnext[0], { address: '203.0.113.5', port: 443, users: [{ id: '0b2c-uuid', encryption: 'none', flow: 'xtls-rprx-vision' }] });
  assert.deepEqual(o.streamSettings.realitySettings, { serverName: 'www.apple.com', fingerprint: 'chrome', publicKey: 'PUBKEY', shortId: 'ab12', spiderX: '' });
  assert.throws(() => parseProxyLink('vless://u@1.2.3.4:443?security=reality&sni=x'), /pbk/);
});

test('trojan ws tls, vmess, ss и JSON', () => {
  const t = parseProxyLink('trojan://p%40ss@[2001:db8::1]:8443?type=ws&security=tls&path=%2Fws&host=cdn.example&sni=cdn.example#x') as any;
  assert.equal(t.settings.servers[0].password, 'p@ss');
  assert.equal(t.settings.servers[0].address, '2001:db8::1');
  assert.deepEqual(t.streamSettings.wsSettings, { path: '/ws', host: 'cdn.example' });
  assert.equal(t.streamSettings.tlsSettings.serverName, 'cdn.example');
  const vm = parseProxyLink('vmess://' + Buffer.from(JSON.stringify({ v: '2', add: '198.51.100.7', port: '8080', id: 'vid', net: 'ws', path: '/v', tls: '' })).toString('base64')) as any;
  assert.equal(vm.settings.vnext[0].port, 8080);
  assert.equal(vm.streamSettings.network, 'ws');
  const ss = parseProxyLink('ss://' + Buffer.from('2022-blake3-aes-128-gcm:a:b').toString('base64url') + '@198.51.100.8:8388#s') as any;
  assert.deepEqual(ss.settings.servers[0], { address: '198.51.100.8', port: 8388, method: '2022-blake3-aes-128-gcm', password: 'a:b' });
  const j = parseProxyLink(JSON.stringify({ outbounds: [{ protocol: 'freedom' }, { protocol: 'vless', settings: {} }] }), 'boot') as any;
  assert.equal(j.protocol, 'vless'); assert.equal(j.tag, 'boot');
  assert.throws(() => parseProxyLink('hysteria2://x@1.2.3.4:1'), /нужна ссылка/);
});
