import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, type TemplateRow, type UserRow } from './ctx.js';
import { Vpn } from './vpn.js';
import { kitVersion } from './nodekit.js';
import { specOf } from './protocols.js';
import { saveUser, userBody } from './routes/users.js';

/** «eskadra»: вход ru, выходы pl и fi — VLESS REALITY на входе и выходах, Hysteria2 на выходах, авто по порядку. */
async function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-bundle-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 9)));
  for (const [id, host] of [['ru', '198.51.100.10'], ['pl', '203.0.113.5'], ['fi', '203.0.113.6']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, ?, 'exit', 'k', 'x', 'restricted')`).run(id, id, host);
  const id = saveUser(ctx, null, userBody.parse({ name: 'ann' }));
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app, ctx);
  const vpn = new Vpn(ctx);
  const base = { name: 'esk', protocol: 'vless', port: 8443, sni: ['www.apple.com'], nodeIds: ['pl', 'fi'], entryId: 'ru', entryPort: 9443,
    settings: { security: 'reality', bundle: true, hy2Obfs: 'ob', hy2Hop: '20000-21000' } };
  const user = () => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as UserRow;
  const all = () => db.prepare('SELECT * FROM templates').all() as unknown as TemplateRow[];
  return { db, ctx, app, vpn, base, id, user, all };
}

test('«eskadra»: одна конфигурация создаёт служебную Hysteria2 на выходах и ссылается на неё резервом', async () => {
  const { app, vpn, base, all } = await fixture();
  const r = await app.inject({ method: 'POST', url: '/api/v1/templates', payload: base });
  assert.equal(r.statusCode, 200, r.body);
  const esk = r.json();
  assert.equal(esk.spec.bundle, true);
  assert.equal(esk.spec.autoMode, 'order', 'по умолчанию — по порядку');
  const hy = all().find((t) => specOf(t).companionOf === esk.id)!;
  assert.ok(hy, 'служебная Hysteria2 создана');
  assert.equal(hy.name, 'esk-hy2');
  assert.equal(hy.protocol, 'hysteria2');
  assert.equal(hy.port, 8443, 'тот же номер порта, но UDP');
  assert.deepEqual(JSON.parse(hy.node_ids), ['pl', 'fi'], 'только выходы');
  assert.equal(hy.entry_id, null);
  const hsp = specOf(hy);
  assert.equal(hsp.certMode, 'self');
  assert.equal(hsp.hy2Obfs, 'ob');
  assert.equal(hsp.hy2Hop, '20000-21000');
  assert.equal(specOf(vpn.template(esk.id)!).hy2Leg, hy.id);
  // в списке конфигураций — одна «eskadra»
  const list = (await app.inject({ method: 'GET', url: '/api/v1/templates' })).json();
  assert.deepEqual(list.map((t: any) => t.id), [esk.id]);
  // служебную отдельно не меняют
  assert.equal((await app.inject({ method: 'PUT', url: `/api/v1/templates/${hy.id}`, payload: { ...base, protocol: 'hysteria2', name: 'x' } })).statusCode, 409);
  assert.equal((await app.inject({ method: 'POST', url: `/api/v1/templates/${hy.id}/rollout` })).statusCode, 409);
  assert.equal((await app.inject({ method: 'DELETE', url: `/api/v1/templates/${hy.id}` })).statusCode, 409);
  await app.close();
});

test('«eskadra»: изменения переносятся в Hysteria2; убранный выход теряет её inbound', async () => {
  const { app, db, base, all } = await fixture();
  const esk = (await app.inject({ method: 'POST', url: '/api/v1/templates', payload: base })).json();
  const hy = () => all().find((t) => specOf(t).companionOf === esk.id)!;
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('h-fi', ?, 'fi', 'direct', 8443, 'udp', 'active')`).run(hy().id);
  const rev = hy().revision;
  const r = await app.inject({ method: 'PUT', url: `/api/v1/templates/${esk.id}`, payload: { ...base, name: 'esk2', nodeIds: ['pl'], settings: { ...base.settings, hy2Port: 8555, hy2Obfs: 'new' } } });
  assert.equal(r.statusCode, 200, r.body);
  assert.equal(hy().name, 'esk2-hy2');
  assert.equal(hy().port, 8555);
  assert.deepEqual(JSON.parse(hy().node_ids), ['pl']);
  assert.equal(specOf(hy()).hy2Obfs, 'new');
  assert.equal(hy().revision, rev + 1);
  assert.equal((db.prepare(`SELECT state FROM inbounds WHERE id = 'h-fi'`).get() as { state: string }).state, 'removed');
  // без изменений — ревизия не растёт
  await app.inject({ method: 'PUT', url: `/api/v1/templates/${esk.id}`, payload: { ...base, name: 'esk2', nodeIds: ['pl'], settings: { ...base.settings, hy2Port: 8555, hy2Obfs: 'new' } } });
  assert.equal(hy().revision, rev + 1);
  await app.close();
});

test('«eskadra»: пользователь видит только VLESS-профили; Hysteria2 на выходе — только плечо входа', async () => {
  const { app, db, vpn, ctx, base, user, all } = await fixture();
  const esk = (await app.inject({ method: 'POST', url: '/api/v1/templates', payload: base })).json();
  const hy = all().find((t) => specOf(t).companionOf === esk.id)!;
  const ib = (id: string, t: string, s: string, kind: string, proto: string, pub: string | null) =>
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id, tls_pin) VALUES (?, ?, ?, ?, 8443, ?, 'active', ?, 'aa', ?)`).run(id, t, s, kind, proto, pub, 'ab'.repeat(32));
  ib('v-pl', esk.id, 'pl', 'direct', 'tcp', 'PUB'); ib('v-fi', esk.id, 'fi', 'direct', 'tcp', 'PUB'); ib('v-ru', esk.id, 'ru', 'relay', 'tcp', null);
  ib('h-pl', hy.id, 'pl', 'direct', 'udp', null); ib('h-fi', hy.id, 'fi', 'direct', 'udp', null);
  const keys = vpn.profiles(user()).map((p) => p.key).sort();
  assert.deepEqual(keys, [`d:${esk.id}:fi`, `d:${esk.id}:pl`, `v:${esk.id}:auto`, `v:${esk.id}:fi`, `v:${esk.id}:pl`]);
  // на выходе — только служебные пользователи Hysteria2
  const exitHy = (vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-h-pl');
  assert.deepEqual(exitHy.users.map((u: any) => u.name).sort(), ['svc.leg-' + esk.id, 'svc.panel']);
  // вход: оба выхода — VLESS с резервом по Hysteria2, по порядку
  const x = vpn.renderXray(ctx.server('ru')) as any;
  for (const e of ['pl', 'fi']) {
    assert.equal(x.outbounds.find((o: any) => o.tag === `to-${esk.id}-${e}`).protocol, 'loopback');
    assert.equal(x.routing.balancers.find((b: any) => b.tag === `fo-${esk.id}-${e}`).fallbackTag, `hy-${esk.id}-${e}`);
  }
  assert.deepEqual(x.routing.balancers.find((b: any) => b.tag === `bal-${esk.id}`).selector, [`to-${esk.id}-pl`]);
  assert.equal(x.inbounds.find((i: any) => i.tag === 'in-v-ru').protocol, 'vless');
  const sb = vpn.renderSingbox(ctx.server('ru')) as any;
  assert.equal(sb.outbounds.find((o: any) => o.tag === `hy-${esk.id}-fi`).obfs.password, 'ob');
  // пользователь не выбирает служебную в своих конфигурациях
  assert.deepEqual(vpn.userTemplates().map((t) => t.id), [esk.id]);
  await app.close();
});

test('«eskadra»: проверка — только VLESS со входом и хотя бы одним выходом', async () => {
  const { app, base } = await fixture();
  const save = (over: Record<string, unknown>) => app.inject({ method: 'POST', url: '/api/v1/templates', payload: { ...base, ...over } });
  assert.match((await save({ name: 'a', entryId: null, entryPort: null })).body, /выберите сервер-вход/);
  assert.match((await save({ name: 'b', nodeIds: ['ru'] })).body, /хотя бы один выход/);
  assert.match((await save({ name: 'c', protocol: 'trojan', settings: { security: 'tls', certMode: 'ip', bundle: true } })).body, /строится на VLESS/);
  assert.match((await save({ name: 'd', settings: { ...base.settings, hy2UpMbps: 10 } })).body, /полоса клиента/);
  await app.close();
});

test('«eskadra»: выкат — сначала Hysteria2 на выходах, затем VLESS и вход; удаление снимает обе', async () => {
  const { app, ctx, db, base, all } = await fixture();
  const esk = (await app.inject({ method: 'POST', url: '/api/v1/templates', payload: base })).json();
  const hyId = all().find((t) => specOf(t).companionOf === esk.id)!.id;
  const calls: string[] = [];
  const ok = (stdout: string) => ({ code: 0, stdout, stderr: '' });
  const n = {
    op: async (a: (string | number)[]) => {
      calls.push(a.join(' '));
      if (a[0] === 'version') return ok(kitVersion());
      if (a[0] === 'xray-x25519') return ok('private=PRIV\npublic=PUB');
      if (a[0] === 'singbox-tls') return ok(`pin=${'ab'.repeat(32)}`);
      if (a[0] === 'core-status') return ok('active=active\n:8443 :9443 ');
      return ok('');
    },
    must: async (a: (string | number)[]) => (await n.op(a)).stdout,
    stage: async () => 'sha',
  };
  (ctx as unknown as { onNode: unknown }).onNode = async (_r: unknown, fn: (s: unknown) => Promise<unknown>) => fn(n);
  db.prepare(`UPDATE servers SET cores = '{"xray":{"version":"25.1.1"},"sing-box":{"version":"1.12.0"}}'`).run();
  // внешняя TCP-проба порта в тесте недоступна — выкат VLESS на неё и упадёт; проверяем порядок до неё
  const job = (await app.inject({ method: 'POST', url: `/api/v1/templates/${esk.id}/rollout` })).json();
  for (let i = 0; i < 100 && !['ok', 'failed'].includes((db.prepare('SELECT status FROM jobs WHERE id = ?').get(job.jobId) as { status: string }).status); i++)
    await new Promise((r) => setTimeout(r, 50));
  const ports = calls.filter((c) => c.startsWith('port-open'));
  assert.deepEqual(ports.slice(0, 2), ['port-open udp 8443', 'port-open udp 8443'], 'сначала Hysteria2 на обоих выходах');
  assert.equal(ports[2], 'port-open tcp 8443', 'затем VLESS');
  assert.equal((db.prepare(`SELECT applied_revision FROM templates WHERE id = ?`).get(hyId) as { applied_revision: number }).applied_revision, 1);
  assert.equal((await app.inject({ method: 'DELETE', url: `/api/v1/templates/${esk.id}` })).statusCode, 200);
  assert.equal(all().length, 0, 'обе конфигурации сняты');
  await app.close();
});

test('eskadra: «по нагрузке», скорость клиента и сайт маскировки — группы ведут на выходы с резервом, полоса и маскировка у Hysteria2', async () => {
  const { app, db, vpn, ctx, base, all } = await fixture();
  const settings = { ...base.settings, autoMode: 'spread', spreadGroups: 4, hy2UpMbps: 50, hy2DownMbps: 200, hy2Masquerade: 'https://www.apple.com/' };
  const r = await app.inject({ method: 'POST', url: '/api/v1/templates', payload: { ...base, settings } });
  assert.equal(r.statusCode, 200, r.body);
  const esk = r.json();
  assert.equal(esk.spec.autoMode, 'spread');
  const hy = all().find((t) => specOf(t).companionOf === esk.id)!;
  assert.equal(specOf(hy).hy2UpMbps, 50);
  assert.equal(specOf(hy).hy2Masquerade, 'https://www.apple.com/');
  const ib = (id: string, t: string, s: string, kind: string, proto: string, pub: string | null) =>
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id, tls_pin) VALUES (?, ?, ?, ?, 8443, ?, 'active', ?, 'aa', ?)`).run(id, t, s, kind, proto, pub, 'ab'.repeat(32));
  ib('v-pl', esk.id, 'pl', 'direct', 'tcp', 'PUB'); ib('v-fi', esk.id, 'fi', 'direct', 'tcp', 'PUB'); ib('v-ru', esk.id, 'ru', 'relay', 'tcp', null);
  ib('h-pl', hy.id, 'pl', 'direct', 'udp', null); ib('h-fi', hy.id, 'fi', 'direct', 'udp', null);
  const x = vpn.renderXray(ctx.server('ru')) as any;
  const groups = x.routing.balancers.filter((b: any) => b.tag.startsWith(`sg-${esk.id}-`));
  assert.ok(groups.length >= 4, 'балансировщики групп «по нагрузке»');
  // уровни групп выбирают из выходов to-…, а каждый выход — VLESS с резервом по Hysteria2
  assert.ok(groups.every((b: any) => b.selector.every((s: string) => s.startsWith(`to-${esk.id}-`))));
  assert.equal(x.outbounds.find((o: any) => o.tag === `to-${esk.id}-pl`).protocol, 'loopback');
  assert.ok(x.routing.balancers.some((b: any) => b.tag === `fo-${esk.id}-pl`));
  // полоса и маскировка: плечо входа — Brutal, inbound выхода — сайт маскировки
  assert.equal((vpn.renderSingbox(ctx.server('ru')) as any).outbounds.find((o: any) => o.tag === `hy-${esk.id}-pl`).up_mbps, 50);
  assert.equal((vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-h-pl').masquerade, 'https://www.apple.com/');
  await app.close();
});

test('eskadra со входом по Hysteria2: клиенты — Hysteria2 ко входу, плечо — Hysteria2, резерв — VLESS', async () => {
  const { app, db, vpn, ctx, base, id, user, all } = await fixture();
  const r = await app.inject({ method: 'POST', url: '/api/v1/templates', payload: { ...base, settings: { ...base.settings, entryProto: 'hysteria2' } } });
  assert.equal(r.statusCode, 200, r.body);
  const esk = r.json();
  assert.equal(esk.spec.entryProto, 'hysteria2');
  const hy = all().find((t) => specOf(t).companionOf === esk.id)!;
  const ib = (iid: string, t: string, s: string, kind: string, port: number, proto: string, pub: string | null, pin: string) =>
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id, tls_pin) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, 'aa', ?)`).run(iid, t, s, kind, port, proto, pub, pin);
  ib('v-pl', esk.id, 'pl', 'direct', 8443, 'tcp', 'PUB', 'ab'.repeat(32)); ib('v-fi', esk.id, 'fi', 'direct', 8443, 'tcp', 'PUB', 'ab'.repeat(32));
  ib('v-ru', esk.id, 'ru', 'relay', 9443, 'udp', null, 'cd'.repeat(32));
  ib('h-pl', hy.id, 'pl', 'direct', 8443, 'udp', null, 'ab'.repeat(32)); ib('h-fi', hy.id, 'fi', 'direct', 8443, 'udp', null, 'ab'.repeat(32));

  // ссылка «вход → авто» — Hysteria2 на вход: сертификат входа, obfs, смена портов
  const auto = vpn.profiles(user()).find((p) => p.key === `v:${esk.id}:auto`)!;
  const u = new URL(vpn.link(user(), auto).replace('hysteria2://', 'https://'));
  assert.equal(u.hostname, '198.51.100.10');
  assert.equal(u.port, '9443');
  assert.equal(u.searchParams.get('pinSHA256'), 'cd'.repeat(32));
  assert.equal(u.searchParams.get('sni'), 'www.apple.com');
  assert.equal(u.searchParams.get('obfs-password'), 'ob');
  assert.equal(decodeURIComponent(u.username), vpn.cred(id, `v:${esk.id}:auto`));
  // напрямую к выходу — по-прежнему VLESS
  assert.match(vpn.link(user(), vpn.profiles(user()).find((p) => p.key === `d:${esk.id}:pl`)!), /^vless:\/\//);

  // sing-box входа принимает клиентов и раздаёт их в SOCKS Xray; плечи к выходам — тоже его
  const sb = vpn.renderSingbox(ctx.server('ru')) as any;
  const entry = sb.inbounds.find((i: any) => i.tag === 'in-v-ru');
  assert.equal(entry.type, 'hysteria2');
  assert.equal(entry.listen_port, 9443);
  assert.deepEqual(entry.obfs, { type: 'salamander', password: 'ob' });
  assert.equal(entry.users.find((x: any) => x.name === `${id}.a-${esk.id}`).password, vpn.cred(id, `v:${esk.id}:auto`));
  assert.ok(sb.outbounds.some((o: any) => o.tag === 'hin-v-ru-auto'));
  assert.ok(sb.outbounds.some((o: any) => o.tag === `hy-${esk.id}-pl`));
  assert.match(vpn.hy2Hops(ctx.server('ru')), /9443:20000-21000/, 'смена портов — и на входе');

  // Xray входа: VLESS-inbound'а нет, основное плечо — Hysteria2, резерв — VLESS
  const x = vpn.renderXray(ctx.server('ru')) as any;
  assert.ok(!x.inbounds.some((i: any) => i.tag === 'in-v-ru'));
  assert.ok(x.routing.rules.some((rr: any) => rr.inboundTag?.[0] === 'hin-v-ru-auto' && rr.balancerTag === `bal-${esk.id}`));
  for (const e of ['pl', 'fi']) {
    const fo = x.routing.balancers.find((b: any) => b.tag === `fo-${esk.id}-${e}`);
    assert.deepEqual(fo.selector, [`hy-${esk.id}-${e}`]);
    assert.equal(fo.fallbackTag, `vl-${esk.id}-${e}`);
    assert.equal(x.outbounds.find((o: any) => o.tag === `vl-${esk.id}-${e}`).protocol, 'vless');
  }
  assert.ok(x.burstObservatory.subjectSelector.includes(`hy-${esk.id}-`), 'проверяется основное плечо — Hysteria2');
  assert.ok(!x.burstObservatory.subjectSelector.includes(`vl-${esk.id}-`));

  // «по нагрузке» с входом по Hysteria2 — нельзя
  assert.match((await app.inject({ method: 'POST', url: '/api/v1/templates', payload: { ...base, name: 'sp', port: 8450, entryPort: 9450, settings: { ...base.settings, entryProto: 'hysteria2', autoMode: 'spread' } } })).body, /по нагрузке/);
  await app.close();
});

test('eskadra: смена входного протокола меняет порт входа TCP ↔ UDP и закрывает прежний', async () => {
  const { app, db, ctx, base, vpn } = await fixture();
  const esk = (await app.inject({ method: 'POST', url: '/api/v1/templates', payload: base })).json();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, private_key_sealed, public_key) VALUES ('v-ru', ?, 'ru', 'relay', 9443, 'tcp', 'active', ?, 'PUB')`).run(esk.id, ctx.seal('PRIV'));
  await app.inject({ method: 'PUT', url: `/api/v1/templates/${esk.id}`, payload: { ...base, settings: { ...base.settings, entryProto: 'hysteria2' } } });
  const calls: string[] = [];
  const n = {
    op: async (a: (string | number)[]) => { calls.push(a.join(' ')); return { code: 0, stdout: a[0] === 'singbox-tls' ? `pin=${'ef'.repeat(32)}` : '', stderr: '' }; },
    must: async (a: (string | number)[]) => (await n.op(a)).stdout,
    stage: async () => 'sha',
  };
  const { Ops } = await import('./ops.js');
  const ib = await new Ops(ctx).ensureInbound(vpn.template(esk.id)!, ctx.server('ru'), 'relay', n as never);
  assert.equal(ib.proto, 'udp');
  assert.equal(ib.tls_pin, 'ef'.repeat(32), 'на входе выпущен сертификат Hysteria2');
  assert.ok(calls.includes('port-close tcp 9443'), 'прежний TCP-порт закрыт');
  assert.ok(calls.includes('singbox-tls www.apple.com'));
  await app.close();
});

test('eskadra: потолок на клиента и BBR — на Hysteria2 выходов и входа; вместе их не задать', async () => {
  const { app, db, vpn, ctx, base, all } = await fixture();
  const r = await app.inject({ method: 'POST', url: '/api/v1/templates', payload: { ...base, settings: { ...base.settings, entryProto: 'hysteria2', hy2ServerUpMbps: 300, hy2ServerDownMbps: 100 } } });
  assert.equal(r.statusCode, 200, r.body);
  const esk = r.json();
  const hy = all().find((t) => specOf(t).companionOf === esk.id)!;
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, tls_pin) VALUES ('h-pl', ?, 'pl', 'direct', 8443, 'udp', 'active', ?)`).run(hy.id, 'ab'.repeat(32));
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, tls_pin) VALUES ('v-ru', ?, 'ru', 'relay', 9443, 'udp', 'active', ?)`).run(esk.id, 'cd'.repeat(32));
  const exitIn = (vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-h-pl');
  assert.equal(exitIn.up_mbps, 300, 'выход: потолок к клиенту (ко входу)');
  assert.equal(exitIn.down_mbps, 100);
  const entryIn = (vpn.renderSingbox(ctx.server('ru')) as any).inbounds.find((i: any) => i.tag === 'in-v-ru');
  assert.equal(entryIn.up_mbps, 300, 'вход по Hysteria2: тот же потолок для пользователей');
  // BBR вместо Brutal
  const put = await app.inject({ method: 'PUT', url: `/api/v1/templates/${esk.id}`, payload: { ...base, settings: { ...base.settings, entryProto: 'hysteria2', hy2IgnoreClientBw: true } } });
  assert.equal(put.statusCode, 200, put.body);
  assert.equal((vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-h-pl').ignore_client_bandwidth, true);
  assert.equal((vpn.renderSingbox(ctx.server('ru')) as any).inbounds.find((i: any) => i.tag === 'in-v-ru').ignore_client_bandwidth, true);
  assert.match((await app.inject({ method: 'PUT', url: `/api/v1/templates/${esk.id}`, payload: { ...base, settings: { ...base.settings, hy2IgnoreClientBw: true, hy2ServerUpMbps: 300 } } })).body, /BBR/);
  await app.close();
});
