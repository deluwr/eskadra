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

test('туннель: сайт маскировки с узла не открывается — рукопожатие REALITY не пройдёт', async () => {
  const { parseDest, snippetFailure } = await import('./tunnelcheck.js');
  const base = out('-P INPUT ACCEPT');
  assert.equal(parseTunnelDiag(`${base}@dest\n200\n`, 34611).destOk, true);
  const bad = parseTunnelDiag(`${base}@dest\ncurl: (28) Connection timed out after 8001 milliseconds\n@log started\n`, 34611);
  assert.deepEqual([bad.destOk, bad.log], [false, ['started']]);
  assert.equal(parseTunnelDiag(`${base}@dest\n000\n`, 34611).destOk, false);
  assert.equal(parseTunnelDiag(base, 34611).destOk, true, 'старый вывод без секции — не ошибка');
  const m = parseDest('www.apple.com=curl: (6) Could not resolve host\ndl.google.com=ok\n');
  assert.equal(m.get('dl.google.com'), 'ok');
  assert.match(m.get('www.apple.com')!, /resolve/);
  // из вывода сниппета — настоящая причина, а не общий «Failed with result»
  const fail = 'x\nOct 13 xray[1]: Failed to start: main: failed to listen TCP on 2087 > listen tcp [::]:2087: bind: address already in use\nOct 13 systemd[1]: fleet-mgmt.service: Failed with result \'exit-code\'.\nслужба туннеля fleet-mgmt не запустилась';
  assert.match(snippetFailure(fail), /address already in use.*не запустилась/);
});

test('подбор порта: засчитывается только ответ маячка узла — «молчащий» приём (как у прокси без узла за ним) нет', async () => {
  const { beaconAnswers, beaconScript, TUNNEL_PORT_CANDIDATES } = await import('./tunnelcheck.js');
  const net = await import('node:net');
  const listen = (onConn: (s: import('node:net').Socket) => void) => new Promise<import('node:net').Server>((res) => { const srv = net.createServer(onConn); srv.listen(0, '127.0.0.1', () => res(srv)); });
  const port = (srv: import('node:net').Server) => (srv.address() as import('node:net').AddressInfo).port;
  const beacon = await listen((s) => s.end('fleet-probe 2083\n'));
  const silent = await listen(() => undefined);
  const other = await listen((s) => s.end('SSH-2.0-OpenSSH\n'));
  try {
    assert.equal(await beaconAnswers('127.0.0.1', port(beacon), 2083), true);
    assert.equal(await beaconAnswers('127.0.0.1', port(beacon), 2087), false, 'метка другого порта — не тот маячок');
    assert.equal(await beaconAnswers('127.0.0.1', port(silent), 2083, 500), false);
    assert.equal(await beaconAnswers('127.0.0.1', port(other), 2083), false);
  } finally { for (const s of [beacon, silent, other]) s.close(); }
  assert.match(beaconScript([2083, 443]), /python3 - 2083 443 <<'PY'/);
  assert.ok(TUNNEL_PORT_CANDIDATES.indexOf(443) > TUNNEL_PORT_CANDIDATES.indexOf(2083), '443 — в конце: он нужнее пользовательским конфигурациям');
});
