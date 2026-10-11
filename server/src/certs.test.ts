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
