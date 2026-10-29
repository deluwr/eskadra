import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import ssh2 from 'ssh2';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { fingerprintOf, withSession, type SshTarget } from './ssh/executor.js';
import { pruneServerRefs } from './prune.js';

const { Server, utils } = ssh2;

/** SSH-сервер в процессе: exec отвечает своим именем; tcpip (ssh -J) пересылает только на разрешённый адрес. */
async function sshServer(name: string, allowForward?: string): Promise<{ port: number; fp: string; forwards: string[]; close: () => void }> {
  const key = utils.generateKeyPairSync('ed25519');
  const parsed = utils.parseKey(key.private);
  const fp = fingerprintOf((Array.isArray(parsed) ? parsed[0]! : parsed).getPublicSSH()).fp;
  const forwards: string[] = [];
  const srv = new Server({ hostKeys: [key.private] }, (client) => {
    client.on('error', () => undefined);   // клиент сам обрывает соединение (подменённый ключ сервера) — не ошибка теста
    // ключ — для SSH панели, пароль «root-pass» — для первичного доступа
    client.on('authentication', (ctx) => (ctx.method === 'publickey' || (ctx.method === 'password' && ctx.password === 'root-pass') ? ctx.accept() : ctx.reject(['publickey', 'password'])));
    client.on('ready', () => {
      client.on('session', (accept) => {
        const s = accept();
        s.on('exec', (acc, _rej, info) => { const ch = acc(); ch.write(`${name}:${info.command}`); ch.exit(0); ch.end(); });
      });
      // как permitopen у ключа панели: посредник пересылает только к SSH целевого узла
      client.on('tcpip', (accept, reject, info) => {
        const dest = `${info.destIP}:${info.destPort}`;
        forwards.push(dest);
        if (dest !== allowForward) return reject();
        const ch = accept();
        const sock = net.connect(info.destPort, info.destIP, () => { ch.pipe(sock).pipe(ch); });
        sock.on('error', () => ch.close());
      });
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  return { port: (srv.address() as net.AddressInfo).port, fp, forwards, close: () => srv.close() };
}

const clientKey = utils.generateKeyPairSync('ed25519').private;

test('через сервер: панель заходит на посредника и через него — на узел; команды выполняются на узле', async () => {
  const target = await sshServer('nl-1');
  const jump = await sshServer('ufo', `127.0.0.1:${target.port}`);
  try {
    const t: SshTarget = {
      host: '127.0.0.1', port: target.port, username: 'fleet', privateKey: clientKey, hostKeyFp: target.fp,
      jump: { host: '127.0.0.1', port: jump.port, username: 'fleet', privateKey: clientKey, hostKeyFp: jump.fp },
    };
    const r = await withSession(t, (s) => s.exec('fleet-exec ping'));
    assert.equal(r.stdout, 'nl-1:fleet-exec ping', 'команду выполнил узел, а не посредник');
    assert.deepEqual(jump.forwards, [`127.0.0.1:${target.port}`]);
    // host key узла сверяется как обычно — и через посредника
    await assert.rejects(withSession({ ...t, hostKeyFp: 'SHA256:wrong' }, (s) => s.exec('x')), /host key changed/);
    // посредник не пускает пересылку — понятная ошибка
    await assert.rejects(withSession({ ...t, port: target.port + 1 }, (s) => s.exec('x')), /не открыл соединение/);
  } finally { target.close(); jump.close(); }
});

test('через сервер: маршрут SSH и адреса панели; посредник удалён — узел возвращается на прямой канал', () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-jump-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 6)));
  setSetting(db, 'executor.ips', ['192.0.2.1']);
  for (const [id, host, mode, jumpId] of [['nl', '203.0.113.9', 'jump', 'ufo'], ['ufo', '198.51.100.3', 'direct', null]] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp, mgmt_mode, mgmt_jump) VALUES (?, ?, ?, 'exit', 'k', ?, 'restricted', 'SHA256:x', ?, ?)`)
      .run(id, id, host, ctx.seal('KEY'), mode, jumpId);
  const t = ctx.target(ctx.server('nl'));
  assert.deepEqual([t.host, t.port, t.jump?.host, t.via], ['203.0.113.9', 22, '198.51.100.3', 'сервер ufo']);
  // SSH на узел приходит с адреса посредника — он среди «адресов панели» (from=, firewall)
  assert.deepEqual(ctx.panelSources(ctx.server('nl')), ['192.0.2.1', '203.0.113.9', '198.51.100.3'], 'исполнитель и все серверы флота, включая посредника и сам узел');
  // цепочки посредников нет
  db.prepare(`UPDATE servers SET mgmt_mode = 'jump', mgmt_jump = 'nl' WHERE id = 'ufo'`).run();
  assert.throws(() => ctx.target(ctx.server('nl')), /сам управляется через посредника/);
  db.prepare(`UPDATE servers SET mgmt_mode = 'direct', mgmt_jump = NULL WHERE id = 'ufo'`).run();
  db.prepare(`DELETE FROM servers WHERE id = 'ufo'`).run();
  db.prepare(`UPDATE servers SET mgmt_jump = 'srv-gone' WHERE id = 'nl'`).run();
  assert.ok(pruneServerRefs(ctx).includes('канал управления nl'));
  assert.equal(ctx.server('nl').mgmt_mode, 'direct');
});

test('через сервер: переключение — посреднику разрешается пересылка до SSH узла, недоступному узлу — команда для консоли', async () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-jump2-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 6)));
  for (const [id, host, fail] of [['nl', '203.0.113.9', '2026-10-27T10:16:58Z'], ['ufo', '198.51.100.3', null], ['de', '198.51.100.7', '2026-10-27T10:00:00Z']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp, fail_since) VALUES (?, ?, ?, 'exit', 'k', ?, 'restricted', 'SHA256:x', ?)`).run(id, id, host, ctx.seal('KEY'), fail);
  const calls: string[] = [];
  const { kitVersion } = await import('./nodekit.js');
  (ctx as unknown as { onNode: unknown }).onNode = async (r: { name: string }, fn: (n: unknown) => Promise<unknown>) => fn({
    op: async (a: (string | number)[]) => { calls.push(`${r.name}: ${a.join(' ')}`); return { code: 0, stdout: a[0] === 'version' ? kitVersion() : '', stderr: '' }; },
    must: async () => '', stage: async () => 'sha',
  });
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { serverRoutes } = await import('./routes/servers.js');
  await serverRoutes(app, ctx);
  const patch = (payload: object) => app.inject({ method: 'PATCH', url: '/api/v1/servers/nl', payload });
  assert.match((await patch({ mgmtMode: 'jump' })).body, /выберите сервер-посредник/);
  assert.match((await patch({ mgmtMode: 'jump', mgmtJump: 'de' })).body, /панель на него сейчас не заходит/);
  const r = await patch({ mgmtMode: 'jump', mgmtJump: 'ufo' });
  assert.equal(r.statusCode, 200, r.body);
  assert.ok(calls.includes('ufo: jump-add 203.0.113.9:22'), calls.join('\n'));
  assert.equal(r.json().consoleHint, 'fleetctl allow 198.51.100.3', 'nl-1 недоступен — разрешить адрес посредника в консоли');
  assert.deepEqual([ctx.server('nl').mgmt_mode, ctx.server('nl').mgmt_jump], ['jump', 'ufo']);
  await app.close();
});

test('через сервер: первичный доступ по паролю и ключ нового сервера — тоже через посредника', async () => {
  const target = await sshServer('nl-1');
  const jump = await sshServer('ufo', `127.0.0.1:${target.port}`);
  try {
    const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-jump3-')));
    const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 6)));
    setSetting(db, 'executor.ips', ['192.0.2.1']);
    db.prepare(`INSERT INTO servers (id, name, host, ssh_port, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp, mgmt_mode) VALUES ('ufo', 'ufo', '127.0.0.1', ?, 'entry', 'k', ?, 'restricted', ?, 'direct')`).run(jump.port, ctx.seal(clientKey), jump.fp);
    db.prepare(`INSERT INTO servers (id, name, host, ssh_port, role, key_pub, key_priv_sealed, mgmt_mode, mgmt_jump) VALUES ('nl', 'nl-1', '127.0.0.1', ?, 'exit', 'ssh-ed25519 AAAA fleet-panel/nl', ?, 'jump', 'ufo')`).run(target.port, ctx.seal(clientKey));
    // ключ сервера без пароля (сниппет выполнен вручную) — через посредника
    const { fetchHostKey } = await import('./ssh/executor.js');
    const t = ctx.target(ctx.server('nl'));
    assert.equal((await fetchHostKey(t.host, t.port, 10_000, t)).fp, target.fp);
    // первичный доступ по паролю: bootstrap выполняется на nl-1, соединение пересылает ufo; в from= — адрес посредника
    const { bootstrapWithAuth } = await import('./onboard.js');
    const lines: string[] = [];
    await bootstrapWithAuth(ctx, ctx.server('nl'), { user: 'root', password: 'root-pass' }, (l) => lines.push(l));
    assert.ok(lines.some((l) => /через сервер-посредник ufo/.test(l)), lines.join('\n'));
    assert.ok(lines.some((l) => /nl-1:bash -s/.test(l)), 'bootstrap выполнил целевой сервер');
    assert.equal(ctx.server('nl').host_key_fp, target.fp);
    assert.ok(jump.forwards.length >= 2 && jump.forwards.every((f) => f === `127.0.0.1:${target.port}`));
    const { snippetOf } = await import('./onboard.js');
    assert.match(await snippetOf(ctx, ctx.server('nl')), /PANEL_IPS="192\.0\.2\.1,127\.0\.0\.1"/, 'адрес посредника — в from=');
  } finally { target.close(); jump.close(); }
});

test('через сервер при добавлении: новый сервер сразу с посредником, без адреса исполнителя; плохой посредник — отказ', async () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-jump4-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 6)));
  for (const [id, host, fail, mode] of [['ufo', '198.51.100.3', null, 'direct'], ['de', '198.51.100.7', '2026-10-27T10:00:00Z', 'direct']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp, fail_since, mgmt_mode) VALUES (?, ?, ?, 'entry', 'k', ?, 'restricted', 'SHA256:x', ?, ?)`).run(id, id, host, ctx.seal('KEY'), fail, mode);
  const { createServer, createBody } = await import('./routes/servers.js');
  const body = (o: object) => createBody.parse({ name: 'nl-2', host: '203.0.113.20', role: 'exit', ...o });
  assert.throws(() => createServer(ctx, body({ mgmtMode: 'jump' }), 'o'), /выберите сервер-посредник/);
  assert.throws(() => createServer(ctx, body({ mgmtMode: 'jump', mgmtJump: 'de' }), 'o'), /не заходит/);
  // executor.ips не задан — для «через сервер» не нужен
  const { id } = createServer(ctx, body({ mgmtMode: 'jump', mgmtJump: 'ufo' }), 'o');
  assert.deepEqual([ctx.server(id).mgmt_mode, ctx.server(id).mgmt_jump], ['jump', 'ufo']);
  // подключение: сначала посредник разрешает пересылку до SSH нового сервера
  const calls: string[] = [];
  const { kitVersion } = await import('./nodekit.js');
  (ctx as unknown as { onNode: unknown }).onNode = async (r: { name: string }, fn: (n: unknown) => Promise<unknown>) => fn({
    op: async (a: (string | number)[]) => { calls.push(`${r.name}: ${a.join(' ')}`); return { code: 0, stdout: a[0] === 'version' ? kitVersion() : '', stderr: '' }; },
    must: async () => '', stage: async () => 'sha',
  });
  const { prepareJump } = await import('./onboard.js');
  const lines: string[] = [];
  await prepareJump(ctx, ctx.server(id), (l) => lines.push(l));
  assert.ok(calls.includes('ufo: jump-add 203.0.113.20:22'), calls.join('\n'));
  assert.match(lines.join('\n'), /посредник ufo: пересылка до 203\.0\.113\.20:22 разрешена/);
});
