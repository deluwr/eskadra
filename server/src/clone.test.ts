import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify from 'fastify';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { specOf } from './protocols.js';

/** Вход ru → выходы pl, fi: h — Hysteria2 через вход (ядра на входе) с obfs и диапазоном портов, v — VLESS напрямую на pl. */
async function fixture(role = 'owner') {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-clone-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 11)));
  for (const [id, r] of [['ru', 'entry'], ['pl', 'exit'], ['fi', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.20', ?, 'k', 'x', 'restricted')`).run(id, id, r);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('h', 'hy', 'sing-box', 'hysteria2', 8444, '["hy.example"]', '["pl","fi"]', 'ru', 9444, ?)`)
    .run(JSON.stringify({ certMode: 'self', hy2Relay: 'core', autoMode: 'order', hy2Obfs: 'secret-obfs', hy2Hop: '20000-21000', ignoreGlobalRoutes: true }));
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('v', 'vl', 'xray', 'vless', 8443, '["www.apple.com"]', '["pl"]', '{"security":"reality"}')`).run();
  setSetting(db, 'cert.h', { fullchain: 'PEM', privkey: 'sealed' });
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('scoped', 'scoped', '["configs.edit"]', '{"templates":["h"]}')`).run();
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('quota', 'quota', '["configs.edit"]', '{"maxTemplates":0}')`).run();
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'a', role, totp: false, totpSecret: null }; });
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app as never, ctx);
  const clone = (id: string, name: string) => app.inject({ method: 'POST', url: `/api/v1/templates/${id}/clone`, payload: { name } });
  return { db, ctx, clone };
}

test('клон: новое имя, случайные свободные порты, новые секреты, те же серверы и настройки', async () => {
  const f = await fixture();
  const r = await f.clone('h', 'hy-two');
  assert.equal(r.statusCode, 200, r.body);
  const c = r.json() as { id: string; name: string; port: number; entry_port: number; node_ids: string[]; entry_id: string; spec: Record<string, unknown> };
  assert.equal(c.name, 'hy-two');
  assert.notEqual(c.id, 'h');
  assert.deepEqual([c.node_ids, c.entry_id], [['pl', 'fi'], 'ru']);
  for (const p of [c.port, c.entry_port]) assert.ok(![8444, 9444, 8443].includes(p) && p >= 1024, `порт ${p}`);
  assert.notEqual(c.port, c.entry_port);
  const sp = specOf(f.ctx.db.prepare('SELECT * FROM templates WHERE id = ?').get(c.id) as never);
  assert.equal(sp.hy2Relay, 'core');
  assert.equal(sp.autoMode, 'order');
  assert.equal(sp.ignoreGlobalRoutes, true, 'настройки переносятся');
  assert.match(sp.hy2Obfs, /^[0-9a-f]{32}$/);
  assert.notEqual(sp.hy2Obfs, 'secret-obfs', 'пароль obfs — новый');
  assert.match(sp.hy2Hop, /^\d+-\d+$/, 'диапазон смены портов — новый, подобранный из свободных');
  assert.notEqual(sp.hy2Hop, '20000-21000');
  assert.deepEqual(getSetting(f.db, `cert.${c.id}`, null), { fullchain: 'PEM', privkey: 'sealed' }, 'свой сертификат — тот же');
  // черновик: inbound'ов нет, на серверы попадёт при выкате
  assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM inbounds WHERE template_id = ?').get(c.id) as { n: number }).n, 0);
  // исходная не тронута
  assert.equal(specOf(f.db.prepare(`SELECT * FROM templates WHERE id = 'h'`).get() as never).hy2Obfs, 'secret-obfs');
});

test('клон: имя занято — 409; роль только со своими конфигурациями и исчерпанный лимит — 403', async () => {
  const f = await fixture();
  assert.equal((await f.clone('v', 'hy')).statusCode, 409);
  assert.equal((await f.clone('v', 'vl-copy')).statusCode, 200);
  assert.equal((await (await fixture('scoped')).clone('h', 'x1')).statusCode, 403);
  assert.equal((await (await fixture('quota')).clone('v', 'x2')).statusCode, 403);
});

test('диапазон смены портов: клон получает свободный того же размера; подбор обходит SSH, UDP-порты и чужие диапазоны', async () => {
  const f = await fixture();
  const r = await f.clone('h', 'hy-hop');
  assert.equal(r.statusCode, 200, r.body);
  const sp = specOf(f.db.prepare('SELECT * FROM templates WHERE id = ?').get((r.json() as { id: string }).id) as never);
  const m = /^(\d+)-(\d+)$/.exec(sp.hy2Hop)!;
  assert.ok(m, `диапазон «${sp.hy2Hop}»`);
  const [a, b] = [Number(m[1]), Number(m[2])];
  assert.equal(b - a, 1000, 'размер как у исходного');
  assert.ok(b < 20000 || a > 21000, 'не пересекается с исходным 20000-21000');

  // API: SSH на pl внутри почти всего высокого диапазона, UDP-inbound чужой конфигурации — результат их обходит
  f.db.prepare(`UPDATE servers SET ssh_ports = '[22, 40000]' WHERE id = 'pl'`).run();
  f.db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('x', 'v', 'pl', 'direct', 50000, 'udp', 'active')`).run();
  const { default: Fastify2 } = await import('fastify');
  const app = Fastify2();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'a', role: 'owner', totp: false, totpSecret: null }; });
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app as never, f.ctx);
  for (let i = 0; i < 20; i++) {
    const res = await app.inject({ method: 'GET', url: '/api/v1/free-hop?servers=pl,fi&size=5000&self=h' });
    assert.equal(res.statusCode, 200, res.body);
    const [x, y] = (res.json() as { range: string }).range.split('-').map(Number) as [number, number];
    assert.equal(y - x, 5000);
    for (const p of [22, 40000, 50000, 8443, 8444, 9444]) assert.ok(p < x || p > y, `${p} внутри ${x}-${y}`);
    // свой диапазон (self=h) не мешает — но остальные порты и чужие диапазоны учтены
  }
  assert.equal((await app.inject({ method: 'GET', url: '/api/v1/free-hop?servers=&size=1000' })).statusCode, 400);
});
