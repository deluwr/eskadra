import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, type UserRow } from './ctx.js';
import { Vpn } from './vpn.js';
import { kitVersion } from './nodekit.js';
import { Ops } from './ops.js';
import { singboxOutbound, specOf } from './protocols.js';
import { saveUser, userBody } from './routes/users.js';

const PIN = 'ab'.repeat(32);

/** Hysteria2 через вход: вход ru (198.51.100.10) пересылает UDP ядром ОС на выход pl (203.0.113.5). */
function fixture(settings: Record<string, unknown> = { certMode: 'self', hy2Hop: '20000-30000' }) {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-hy2r-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 9)));
  for (const [id, host, role] of [['ru', '198.51.100.10', 'entry'], ['pl', '203.0.113.5', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, ?, ?, 'k', 'x', 'restricted')`).run(id, id, host, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'hy', 'sing-box', 'hysteria2', 8444, '["hy.example"]', '["pl"]', 'ru', 9444, ?)`).run(JSON.stringify(settings));
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, tls_pin) VALUES ('ib-pl', 't', 'pl', 'direct', 8444, 'udp', 'active', ?)`).run(PIN);
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('ib-ru', 't', 'ru', 'relay', 9444, 'udp', 'active')`).run();
  const id = saveUser(ctx, null, userBody.parse({ name: 'ann' }));
  const user = () => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as UserRow;
  return { db, ctx, vpn: new Vpn(ctx), id, user };
}
const hyUsers = (cfg: any) => cfg.inbounds[0].users as Array<{ name: string; password: string }>;

test('Hysteria2 через вход: один профиль «вход → выход» без «авто», ссылка на вход, TLS и пароль — выхода', () => {
  const { vpn, ctx, id, user } = fixture();
  const ps = vpn.profiles(user());
  assert.deepEqual(ps.map((p) => p.key).sort(), ['d:t:pl', 'v:t:pl']);
  const via = ps.find((p) => p.key === 'v:t:pl')!;
  assert.equal(via.name, 'ru → pl');
  const l = vpn.link(user(), via);
  const u = new URL(l.replace('hysteria2://', 'https://'));
  assert.equal(u.hostname, '198.51.100.10', 'клиент подключается к входу');
  assert.equal(u.port, '9444');
  assert.equal(u.searchParams.get('sni'), 'hy.example');
  assert.equal(u.searchParams.get('pinSHA256'), PIN, 'отпечаток сертификата — выхода');
  assert.equal(u.searchParams.get('mport'), '20000-30000', 'диапазон смены портов — на входе');
  const secret = decodeURIComponent(u.username);
  assert.equal(secret, vpn.cred(id, 'v:t:pl'));
  // этот пароль знает inbound выхода — вход только пересылает UDP
  const users = hyUsers(vpn.renderSingbox(ctx.server('pl')));
  assert.deepEqual(users.find((x) => x.name === `${id}.v-pl`)?.password, secret);
  assert.deepEqual(users.find((x) => x.name === `${id}.d-t`)?.password, vpn.cred(id, 't:t'));
  // подписка sing-box — то же
  const sb = singboxOutbound(vpn.spec(via.template), secret, vpn.target(via)) as any;
  assert.equal(sb.server, '198.51.100.10');
  assert.equal(sb.server_port, 9444);
  assert.equal(sb.password, secret);
  assert.equal(sb.tls.server_name, 'hy.example');
  // на входе ядер нет
  assert.equal(vpn.renderSingbox(ctx.server('ru')), null);
  assert.equal(vpn.renderXray(ctx.server('ru')), null);
  assert.equal(vpn.hy2Hops(ctx.server('ru')), '-');
});

test('Hysteria2 через вход: пересылка на входе — порт и диапазон смены портов на inbound выхода', () => {
  const { vpn, ctx, db } = fixture();
  assert.equal(vpn.hy2Relays(ctx.server('ru')), '9444=203.0.113.5:8444,20000-30000=203.0.113.5:8444');
  assert.equal(vpn.hy2Relays(ctx.server('pl')), '-');
  db.prepare(`UPDATE templates SET settings = '{"certMode":"self"}'`).run();
  assert.equal(vpn.hy2Relays(ctx.server('ru')), '9444=203.0.113.5:8444');
  // выход ещё не выкачен — пересылать некуда
  db.prepare(`UPDATE inbounds SET state = 'deploying' WHERE id = 'ib-pl'`).run();
  assert.equal(vpn.hy2Relays(ctx.server('ru')), '-');
  db.prepare(`UPDATE inbounds SET state = 'active' WHERE id = 'ib-pl'`).run();
  // nft DNAT принимает только IP
  db.prepare(`UPDATE servers SET host = 'pl.example' WHERE id = 'pl'`).run();
  assert.throws(() => vpn.hy2Relays(ctx.server('ru')), /IPv4/);
});

test('Hysteria2 через вход: сертификат на IP — клиент проверяет IP выхода, а подключается ко входу', () => {
  const { vpn, user } = fixture({ certMode: 'ip' });
  const via = vpn.profiles(user()).find((p) => p.key === 'v:t:pl')!;
  const u = new URL(vpn.link(user(), via).replace('hysteria2://', 'https://'));
  assert.equal(u.hostname, '198.51.100.10');
  assert.equal(u.searchParams.get('sni'), '203.0.113.5');
  assert.equal(u.searchParams.get('insecure'), null);
  const sb = singboxOutbound(vpn.spec(via.template), 'x', vpn.target(via)) as any;
  assert.equal(sb.tls.server_name, '203.0.113.5');
  // напрямую — как раньше: имя не нужно, проверяется адрес подключения
  const direct = vpn.profiles(user()).find((p) => p.key === 'd:t:pl')!;
  assert.equal(new URL(vpn.link(user(), direct).replace('hysteria2://', 'https://')).searchParams.get('sni'), null);
});

test('Hysteria2 через вход: выключенный вариант и режимы пользователя убирают пароль с выхода; авто-выбора нет', () => {
  const { vpn, ctx, id, user } = fixture();
  saveUser(ctx, id, userBody.parse({ name: 'ann', excludedProfiles: ['v:t:pl'] }));
  assert.deepEqual(vpn.profiles(user()).map((p) => p.key), ['d:t:pl']);
  assert.deepEqual(hyUsers(vpn.renderSingbox(ctx.server('pl'))).map((x) => x.name), [`${id}.d-t`]);
  saveUser(ctx, id, userBody.parse({ name: 'ann', excludedProfiles: [], modes: ['via'] }));
  assert.deepEqual(vpn.profiles(user()).map((p) => p.key), ['v:t:pl']);
  assert.deepEqual(hyUsers(vpn.renderSingbox(ctx.server('pl'))).map((x) => x.name), [`${id}.v-pl`]);
  assert.equal(specOf({ protocol: 'hysteria2', sni: '[]', fingerprint: '', settings: '{"autoEnabled":true}' }).autoEnabled, false);
});

test('Hysteria2 через вход: выкат — на входе ни ядра, ни сертификата, только пересылка; снятие убирает её', async () => {
  const { ctx, db, vpn } = fixture({ certMode: 'ip' });
  db.prepare(`DELETE FROM inbounds WHERE id = 'ib-ru'`).run();
  const calls: string[] = [];
  let relay = '-';
  const ok = (stdout: string) => ({ code: 0, stdout, stderr: '' });
  const n = {
    op: async (a: (string | number)[]) => {
      calls.push(a.join(' '));
      if (a[0] === 'version') return ok(kitVersion());
      if (a[0] === 'hy2-relay') { if (a[1] === 'status') return ok(relay === '-' ? '' : relay.split(',').join('\n')); relay = String(a[1]); return ok(`relay ${relay}`); }
      if (a[0] === 'core-status') return ok('active=active\n:8444 ');
      return ok('');
    },
    must: async (a: (string | number)[]) => (await n.op(a)).stdout,
    stage: async () => 'sha',
  };
  (ctx as unknown as { onNode: unknown }).onNode = async (_r: unknown, fn: (s: unknown) => Promise<unknown>) => fn(n);
  db.prepare(`UPDATE servers SET cores = '{"sing-box":{"version":"1.12.0"}}' WHERE id = 'pl'`).run();
  const ops = new Ops(ctx);
  await ops.rollout(db.prepare(`SELECT * FROM templates WHERE id = 't'`).get() as never, () => undefined);
  assert.equal(relay, '9444=203.0.113.5:8444');
  assert.equal((db.prepare(`SELECT state FROM inbounds WHERE server_id = 'ru'`).get() as { state: string }).state, 'active');
  // сертификат выпускался только на выходе, ядро на вход не ставилось
  assert.deepEqual(calls.filter((c) => c.startsWith('tls-issue')), ['tls-issue ip ip 203.0.113.5']);
  assert.ok(!calls.some((c) => c.startsWith('core-install')));
  assert.equal(getSetting(db, 'hy2relay.ru', '-'), '9444=203.0.113.5:8444');
  assert.equal(vpn.hy2Relays(ctx.server('ru')), relay);
  await ops.removeTemplate(db.prepare(`SELECT * FROM templates WHERE id = 't'`).get() as never, () => undefined);
  assert.equal(relay, '-');
});

test('Hysteria2 через вход: сохранить можно только с одним выходом по IPv4, вход — не выход', async () => {
  const { ctx, db } = fixture();
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES ('fi', 'fi', 'fi.example', 'exit', 'k', 'x', 'restricted')`).run();
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app, ctx);
  const save = (over: Record<string, unknown>) => app.inject({ method: 'POST', url: '/api/v1/templates', payload: {
    name: 'hy2', protocol: 'hysteria2', port: 8445, sni: ['hy.example'], nodeIds: ['pl'], entryId: 'ru', entryPort: 9445, settings: { certMode: 'self' }, ...over } });
  const r = await save({});
  assert.equal(r.statusCode, 200, r.body);
  assert.equal(r.json().entry_id, 'ru');
  assert.match((await save({ name: 'two', nodeIds: ['pl', 'fi'] })).body, /один выход/);
  assert.match((await save({ name: 'self', nodeIds: ['pl', 'ru'] })).body, /и сам принимает напрямую/);
  assert.match((await save({ name: 'dom', nodeIds: ['fi'] })).body, /IPv4/);
  // сертификат на IP нужен только выходу: вход с доменным адресом не мешает
  db.prepare(`UPDATE servers SET host = 'ru.example' WHERE id = 'ru'`).run();
  assert.equal((await save({ name: 'ip', settings: { certMode: 'ip' } })).statusCode, 200);
  // диапазон смены портов задевает SSH входа
  db.prepare(`UPDATE servers SET ssh_ports = '[42000]' WHERE id = 'ru'`).run();
  assert.match((await save({ name: 'hop', settings: { certMode: 'self', hy2Hop: '40000-45000' } })).body, /SSH 42000 на сервере ru/);
  await app.close();
});
