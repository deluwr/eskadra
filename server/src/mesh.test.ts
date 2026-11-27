import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { pruneServerRefs } from './prune.js';

/** Пункт чек-листа «Связь с другими вашими серверами есть»: только пары нынешних серверов и свежие проверки. */
test('связь с серверами: старая неудача удалённого сервера пункт не держит', async () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-mesh-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 5)));
  for (const [id, host] of [['srv-a', '198.51.100.1'], ['srv-b', '203.0.113.2']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp) VALUES (?, ?, ?, 'exit', 'k', 'x', 'restricted', 'fp')`).run(id, id, host);
  const now = new Date().toISOString();
  const put = (a: string, b: string, result: string, at = now) =>
    db.prepare('INSERT OR REPLACE INTO peer_checks (from_id, to_id, result, checked_at) VALUES (?, ?, ?, ?)').run(a, b, result, at);
  put('srv-a', 'srv-b', 'ok'); put('srv-b', 'srv-a', 'ok');
  // удалённый сервер когда-то не достучался до srv-a
  put('srv-gone', 'srv-a', 'fail');
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { serverRoutes } = await import('./routes/servers.js');
  await serverRoutes(app, ctx);
  const mesh = async () => ((await app.inject({ method: 'PUT', url: '/api/v1/servers/srv-a/checklist', payload: {} })).json().items as Array<{ id: string; done: boolean }>).find((i) => i.id === 'mesh')!.done;
  assert.equal(await mesh(), true, 'неудача удалённого сервера не считается');
  // давняя неудача пары, которую больше не проверяют, — тоже
  put('srv-a', 'srv-b', 'fail', new Date(Date.now() - 3 * 86_400_000).toISOString());
  assert.equal(await mesh(), true);
  // свежая неудача между нынешними серверами — пункт не выполнен
  put('srv-a', 'srv-b', 'fail');
  assert.equal(await mesh(), false);
  // уборка: записи удалённых серверов уходят
  pruneServerRefs(ctx);
  assert.equal((db.prepare(`SELECT COUNT(*) AS n FROM peer_checks WHERE from_id = 'srv-gone'`).get() as { n: number }).n, 0);
  await app.close();
});
