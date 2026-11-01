import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createPrivateKey } from 'node:crypto';
import { cfCertName, covers, makeCsr, validHostname } from './tlsissue.js';
import { certLabel } from './certs.js';

test('имена в сертификате Cloudflare: точное и wildcard на один уровень', () => {
  assert.ok(covers(['cdn.example.com'], 'CDN.example.com'));
  assert.ok(!covers(['cdn.example.com'], 'x.cdn.example.com'));
  assert.ok(covers(['*.example.com'], 'cdn.example.com'));
  assert.ok(!covers(['*.example.com'], 'a.b.example.com'), 'wildcard не покрывает второй уровень');
  assert.ok(!covers(['*.example.com'], 'example.com'));
  assert.ok(!covers(['cdn.example.com'], ''));
});

test('имя каталога на узле: проходит name_ok fleet-exec вместе с .crt', () => {
  assert.equal(cfCertName('cdn.example.com'), 'cf-cdn.example.com');
  assert.equal(cfCertName('*.example.com'), 'cf-_.example.com');
  const long = cfCertName('a'.repeat(60) + '.example.com');
  assert.ok(/^[A-Za-z0-9._-]{1,64}$/.test(long + '.crt'));
  assert.equal(certLabel('cf-_.example.com'), 'сертификат Cloudflare *.example.com');
});

test('проверка имён', () => {
  assert.ok(validHostname('cdn.example.com'));
  assert.ok(validHostname('*.example.com'));
  assert.ok(!validHostname('example'));
  assert.ok(!validHostname('a..example.com'));
  assert.ok(!validHostname('*.*.example.com'));
});

test('CSR: ECDSA P-256, подпись и SAN проверяет openssl', (t) => {
  const { csr, key } = makeCsr(['cdn.example.com', '*.example.com']);
  assert.match(csr, /^-----BEGIN CERTIFICATE REQUEST-----\n/);
  assert.equal(createPrivateKey(key).asymmetricKeyDetails?.namedCurve, 'prime256v1');
  let ok = true;
  try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { ok = false; }
  if (!ok) { t.skip('нет openssl'); return; }
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'csr-')), 'req.pem');
  fs.writeFileSync(f, csr);
  const out = execFileSync('openssl', ['req', '-in', f, '-noout', '-verify', '-text'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.match(out, /CN\s*=\s*cdn\.example\.com/);
  assert.match(out, /DNS:cdn\.example\.com, DNS:\*\.example\.com/);
});

test('сертификат панели и адрес подписок: имя покрыто точно или *.зона на один уровень', async () => {
  const { certCovers } = await import('./update.js');
  assert.ok(certCovers(['panel.example.com'], 'PANEL.example.com'));
  assert.ok(!certCovers(['panel.example.com'], 'sub.example.com'), 'подписки на другом имени');
  assert.ok(certCovers(['panel.example.com', 'sub.example.com'], 'sub.example.com'));
  assert.ok(certCovers(['*.example.com'], 'sub.example.com'));
  assert.ok(!certCovers(['*.example.com'], 'a.sub.example.com'));
  assert.ok(certCovers(['203.0.113.7'], '203.0.113.7'));
});
