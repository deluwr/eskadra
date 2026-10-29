import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Ops } from './ops.js';
import { certProblems, parseCertStatus } from './certs.js';

/** Флот: ufo и pl-1 доступны, nl-1 — уже нет. Панель 192.0.2.1. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-peer-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 8)));
  setSetting(db, 'executor.ips', ['192.0.2.1']);
  for (const [id, host, fail] of [['ufo', '198.51.100.3', null], ['pl', '203.0.113.5', null], ['nl', '203.0.113.9', '2026-10-29T10:16:00Z']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp, fail_since) VALUES (?, ?, ?, 'exit', 'k', ?, 'restricted', 'SHA256:x', ?)`).run(id, id, host, ctx.seal('KEY'), fail);
  const calls: string[] = [];
  (ctx as unknown as { onNode: unknown }).onNode = async (r: { name: string }, fn: (n: unknown) => Promise<unknown>) => fn({
    op: async (a: (string | number)[]) => { calls.push(`${r.name}: ${a.join(' ')}`); return { code: 0, stdout: a[0] === 'version' ? '' : 'OK', stderr: '' }; },
    must: async () => '', stage: async () => 'sha',
  });
  return { db, ctx, calls };
}

test('адреса флота заранее: доступные узлы получают allow для панели и всех серверов, повторно не шлётся', async () => {
  const { ctx, db, calls } = fixture();
  const ops = new Ops(ctx);
  await ops.syncPeerAccess(() => undefined);
  for (const node of ['ufo', 'pl'])
    for (const ip of ['192.0.2.1', '198.51.100.3', '203.0.113.5', '203.0.113.9']) assert.ok(calls.includes(`${node}: allow ${ip}`), `${node} ← ${ip}`);
  assert.ok(!calls.some((c) => c.startsWith('nl-1') || c.startsWith('nl:')), 'недоступный узел не трогаем');
  assert.deepEqual(getSetting<string[]>(db, 'peers.allowed.pl', []).sort(), ['192.0.2.1', '198.51.100.3', '203.0.113.5', '203.0.113.9']);
  calls.length = 0;
  await ops.syncPeerAccess(() => undefined);
  assert.equal(calls.length, 0, 'всё уже разрешено');
  // новый сервер во флоте — его адрес дописывается на остальные
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed) VALUES ('es', 'es', '203.0.113.7', 'exit', 'k', 'x')`).run();
  await ops.syncPeerAccess(() => undefined);
  assert.deepEqual(calls.sort(), ['pl: allow 203.0.113.7', 'ufo: allow 203.0.113.7']);
});

test('адрес посредника уже разрешён заранее — переключение на «через сервер» без команды в консоли', async () => {
  const { ctx, db } = fixture();
  setSetting(db, 'peers.allowed.nl', ['192.0.2.1', '198.51.100.3', '203.0.113.5', '203.0.113.9']);   // разрешили, пока nl-1 был доступен
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { serverRoutes } = await import('./routes/servers.js');
  await serverRoutes(app, ctx);
  const r = await app.inject({ method: 'PATCH', url: '/api/v1/servers/nl', payload: { mgmtMode: 'jump', mgmtJump: 'ufo' } });
  assert.equal(r.statusCode, 200, r.body);
  assert.equal(r.json().consoleHint, null);
  // адреса не было в списке — команда для консоли, как раньше
  setSetting(db, 'peers.allowed.nl', ['192.0.2.1']);
  assert.equal((await app.inject({ method: 'PATCH', url: '/api/v1/servers/nl', payload: { mgmtMode: 'jump', mgmtJump: 'pl' } })).json().consoleHint, 'fleetctl allow 203.0.113.5');
  await app.close();
});

test('сертификат: продление не прошло из-за порта 80 — видно, какая служба его держит', () => {
  const st = parseCertStatus(['cert ip 1900000000 1', 'renew_at=1761720000', 'renew_code=1', 'renew_err=Could not bind TCP port 80', 'renew_holder=nginx|812|nginx.service', 'timer=active'].join('\n'), new Date('2030-01-01'));
  assert.deepEqual(st.renew?.holder, { name: 'nginx', pid: '812', unit: 'nginx.service' });
  const p = certProblems({ id: 's', name: 'pl-1', tls_state: JSON.stringify(st) }, undefined, Date.parse('2030-01-01'));
  assert.match(p[0]!.detail, /порт 80 занят: nginx \(служба nginx\.service\) — на вкладке «Хост» включите её остановку на время продления/);
  // успешное продление — без держателя; службы, которые останавливаются на время продления, — списком
  const ok = parseCertStatus('renew_at=1761720000\nrenew_code=0\nrenew_err=\nport80_units=nginx.service,apache2.service');
  assert.equal(ok.renew?.holder, null);
  assert.deepEqual(ok.port80Units, ['nginx.service', 'apache2.service']);
});
