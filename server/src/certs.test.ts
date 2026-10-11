import { test } from 'node:test';
import assert from 'node:assert/strict';
import { certProblems, parseCertStatus } from './certs.js';

const now = Date.parse('2026-10-11T12:00:00Z');
const at = (h: number) => Math.floor((now + h * 3600_000) / 1000);
const srv = (out: string) => ({ id: 's1', name: 'de-1', tls_state: JSON.stringify(parseCertStatus(out, new Date(now))) });

test('certs: разбор статуса узла', () => {
  const st = parseCertStatus(`cert ip ${at(100)} 1\ncert tpl-ab12 ${at(500)} 0\nrenew_at=${at(-1)}\nrenew_code=1\nrenew_err=Timeout during connect\ntimer=active\n`, new Date(now));
  assert.equal(st.certs.length, 2);
  assert.equal(st.certs[0]!.le, true);
  assert.equal(st.renew?.code, 1);
  assert.equal(st.renew?.err, 'Timeout during connect');
  assert.equal(st.timer, true);
});

test('certs: всё в порядке — предупреждений нет', () => {
  assert.deepEqual(certProblems(srv(`cert ip ${at(100)} 1\nrenew_at=${at(-1)}\nrenew_code=0\nrenew_err=\ntimer=active`), undefined, now), []);
});

test('certs: продление не прошло — предупреждение, срок подходит — сбой, истёк — сбой', () => {
  const failRenew = certProblems(srv(`cert ip ${at(80)} 1\nrenew_code=1\nrenew_at=${at(-1)}\nrenew_err=port 80 blocked\ntimer=active`), undefined, now);
  assert.deepEqual(failRenew.map((p) => [p.key, p.level]), [['s1:renew', 'warn']]);
  assert.match(failRenew[0]!.detail, /port 80 blocked/);
  const soon = certProblems(srv(`cert ip ${at(20)} 1\nrenew_code=1\nrenew_at=${at(-1)}\nrenew_err=x\ntimer=active`), undefined, now);
  assert.deepEqual(soon.map((p) => [p.key, p.level]), [['s1:ip:soon', 'fail']]);
  const expired = certProblems(srv(`cert dom-vpn.example.com ${at(-1)} 1\ntimer=active`), undefined, now);
  assert.equal(expired[0]!.key, 's1:dom-vpn.example.com:expired');
  assert.match(expired[0]!.title, /vpn\.example\.com истёк/);
});

test('certs: загруженный сертификат и выключенный таймер', () => {
  const p = certProblems(srv(`cert tpl-ab12 ${at(24 * 10)} 0\ncert ip ${at(100)} 1\ntimer=inactive`), (id) => (id === 'tpl-ab12' ? 'main' : undefined), now);
  assert.deepEqual(p.map((x) => x.key), ['s1:tpl-ab12:upload', 's1:timer']);
  assert.match(p[0]!.title, /«main» истекает через 10 дн/);
});

test('страница подписки: браузер видит страницу, приложения — подписку', async () => {
  const { wantsPage, renderSubPage } = await import('./subpage.js');
  const chrome = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130 Safari/537.36';
  assert.equal(wantsPage('text/html,application/xhtml+xml', chrome), true);
  assert.equal(wantsPage('*/*', 'v2rayN/7.0'), false);
  assert.equal(wantsPage('text/html', 'Mozilla/5.0 HiddifyNext/2.0'), false);
  assert.equal(wantsPage(undefined, chrome), false);
  const html = renderSubPage({ lang: 'ru', name: 'anna<script>', active: true, subUrl: 'https://s.example/s/tok', expireAt: '2026-12-31T23:59:59Z',
    usedBytes: 5 * 1024 ** 3, limitGb: 50, devices: 3, nodes: ['relay', 'de-1'], links: [{ name: 'relay → авто', uri: 'vless://x@1.2.3.4:443?a=1&b=2#relay' }] });
  assert.ok(!html.includes('anna<script>'), 'имя экранировано');
  assert.match(html, /<svg/);
  assert.match(html, /2026-12-31/);
  assert.match(html, /из 50 ГБ/);
  assert.match(html, /vless:\/\/x@1\.2\.3\.4:443\?a=1&amp;b=2#relay/);
  assert.match(html, /hiddify:\/\/import\/https:\/\/s\.example\/s\/tok/);
});

test('статистика хоста: разбор счётчиков и скорости по двум замерам', async () => {
  const { parseHostStat } = await import('./hoststats.js');
  const raw = (cpuBusy: number, idle: number, rx: number, tx: number) => `@stat\ncpu  ${cpuBusy} 0 0 ${idle} 0 0 0 0 0 0\n@meminfo\nMemTotal:  2000000 kB\nMemAvailable:  500000 kB\n@netdev\n    lo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\n  eth0: ${rx} 10 0 0 0 0 0 0 ${tx} 10 0 0 0 0 0 0\n@uptime\n3600.5 100\n@loadavg\n0.50 0.40 0.30 1/100 1\n@nproc\n2\n@df\n/dev/vda1 40000000000 10000000000 30000000000 25% /\n@ip\n203.0.113.5\n2001:db8::5`;
  const a = parseHostStat('x', raw(100, 900, 1000, 2000), 0);
  assert.equal(a.cpuPct, null, 'первый замер — без скоростей');
  assert.deepEqual(a.mem, { used: 1500000 * 1024, total: 2000000 * 1024 });
  const b = parseHostStat('x', raw(150, 950, 3000, 2500), 2000);
  assert.equal(b.cpuPct, 50);
  assert.deepEqual(b.net, { rxBps: 1000, txBps: 250, rxTotal: 3000, txTotal: 2500 });
  assert.deepEqual(b.disk, { used: 10000000000, total: 40000000000 });
  assert.deepEqual(b.ips, ['203.0.113.5', '2001:db8::5']);
  assert.equal(b.uptimeSec, 3600.5);
  assert.deepEqual(b.load, [0.5, 0.4, 0.3]);
});
