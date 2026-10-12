import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainTunnel, openScript, parseTunnelDiag } from './tunnelcheck.js';

const out = (ipt: string, nft = '', listen = 'LISTEN 0 4096 *:34611 *:*') => `@active
active
@listen
${listen}
@ipt
${ipt}
@nft
${nft}
`;

test('туннель: iptables с политикой DROP и без правила для порта — режет; с правилом — нет', () => {
  const deny = '-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT';
  const d = parseTunnelDiag(out(deny), 34611);
  assert.deepEqual([d.active, d.listening, d.iptablesBlocks], [true, true, true]);
  assert.match(openScript(34611, d), /iptables -I INPUT -p tcp --dport 34611 -j ACCEPT/);
  assert.equal(parseTunnelDiag(out(`${deny}\n-A INPUT -p tcp -m tcp --dport 34611 -j ACCEPT`), 34611).iptablesBlocks, false);
  // итоговое «-A INPUT -j REJECT» тоже запрет
  assert.equal(parseTunnelDiag(out('-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT --reject-with icmp-host-prohibited'), 34611).iptablesBlocks, true);
  assert.equal(parseTunnelDiag(out('-P INPUT ACCEPT'), 34611).iptablesBlocks, false);
});

test('туннель: цепочки nftables с hook input и policy drop — кроме таблицы панели', () => {
  const nft = 'table inet filter { # handle 1\n\tchain input { # handle 1\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\ntable inet fleet { # handle 2\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;';
  const d = parseTunnelDiag(out('', nft), 34611);
  assert.deepEqual(d.nftChains, ['inet filter input']);
  assert.match(openScript(34611, d), /nft insert rule inet filter input tcp dport 34611 accept/);
});

test('туннель: объяснение причины — служба, порт, firewall хостера', () => {
  const base = parseTunnelDiag(out('-P INPUT ACCEPT'), 34611);
  assert.match(explainTunnel(base, '31.58.46.61', 34611, 'fi-1 · duo-pl-fi'), /firewall хостера/);
  assert.match(explainTunnel({ ...base, listening: false }, 'h', 34611, null), /не слушается/);
  assert.match(explainTunnel({ ...base, active: false }, 'h', 34611, null), /не работает/);
  assert.equal(parseTunnelDiag(out('', '', ''), 34611).listening, false);
});
