import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, type TemplateRow, type UserRow } from './ctx.js';
import { Vpn } from './vpn.js';
import { specOf } from './protocols.js';
import { saveUser, userBody } from './routes/users.js';

/**
 * XHTTP во всех цепочках: вход ru, выход pl. VLESS → VLESS, «eskadra» VLESS → VLESS/Hysteria2,
 * «eskadra» Hysteria2 → Hysteria2/VLESS; XHTTP у входа, у плеча или везде; вход за CDN.
 * XRAY_BIN — путь к xray: тогда конфиги узлов проходят и `xray run -test`.
 */
async function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-xhttp-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 7)));
  for (const [id, host] of [['ru', '198.51.100.10'], ['pl', '203.0.113.5']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, ?, 'exit', 'k', 'x', 'restricted')`).run(id, id, host);
  const uid = saveUser(ctx, null, userBody.parse({ name: 'ann', modes: ['via'] }));
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app, ctx);
  const vpn = new Vpn(ctx);
  const user = () => db.prepare('SELECT * FROM users WHERE id = ?').get(uid) as unknown as UserRow;
  const all = () => db.prepare('SELECT * FROM templates').all() as unknown as TemplateRow[];
  /** Ключи REALITY как у `xray x25519`: base64url без дополнения. */
  const x25519 = () => {
    const { privateKey, publicKey } = generateKeyPairSync('x25519');
    return { priv: privateKey.export({ format: 'jwk' }).d!, pub: publicKey.export({ format: 'jwk' }).x! };
  };
  const inbound = (id: string, t: string, s: string, kind: string, proto = 'tcp', port = 8443) => {
    const k = x25519();
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, private_key_sealed, short_id, tls_pin)
      VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, 'a1b2c3d4', ?)`).run(id, t, s, kind, port, proto, k.pub, ctx.seal(k.priv), 'ab'.repeat(32));
  };
  const create = async (payload: Record<string, unknown>) => {
    const r = await app.inject({ method: 'POST', url: '/api/v1/templates', payload });
    assert.equal(r.statusCode, 200, r.body);
    return r.json() as { id: string; spec: Record<string, unknown> };
  };
  /** Ссылки пользователя через вход по профилям. */
  const links = () => Object.fromEntries(vpn.profiles(user()).map((p) => [p.key, vpn.link(user(), p)]));
  return { db, ctx, app, vpn, all, inbound, create, links };
}

const chain = (settings: Record<string, unknown>) => ({
  name: 'x', protocol: 'vless', port: 8443, sni: ['www.apple.com'], nodeIds: ['pl'], entryId: 'ru', entryPort: 9443,
  settings: { security: 'reality', ...settings },
});
const q = (link: string) => new URL(link).searchParams;
const stream = (cfg: any, tag: string) => (cfg.inbounds.find((i: any) => i.tag === tag) ?? cfg.outbounds.find((o: any) => o.tag === tag))?.streamSettings;

/** `xray run -test` для конфига узла (если задан XRAY_BIN); пути сертификатов заменяются на временный самоподписанный. */
function xrayTest(cfg: object, cert?: { crt: string; key: string }) {
  const bin = process.env.XRAY_BIN;
  if (!bin) return;
  let text = JSON.stringify(cfg);
  if (cert) text = text.replace(/\/etc\/eskadra\/tls\/[^"]+\/fullchain\.pem/g, cert.crt.replace(/\\/g, '/')).replace(/\/etc\/eskadra\/tls\/[^"]+\/privkey\.pem/g, cert.key.replace(/\\/g, '/'));
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-xray-')), 'config.json');
  fs.writeFileSync(f, text);
  try { execFileSync(bin, ['run', '-test', '-c', f], { stdio: 'pipe' }); } catch (e) {
    const err = e as { stdout?: Buffer; stderr?: Buffer };
    assert.fail(`xray run -test: ${err.stdout?.toString() ?? ''}${err.stderr?.toString() ?? ''}`);
  }
}

test('XHTTP: путь подставляется сам, Vision у XHTTP выключен, режим auto', async () => {
  const { create, app } = await fixture();
  const t = await create(chain({ transport: 'xhttp', flow: 'xtls-rprx-vision' }));
  assert.match(String(t.spec.path), /^\/[0-9a-f]{12}$/, 'случайный путь вместо «/»');
  assert.equal(t.spec.flow, '');
  assert.equal(t.spec.xhttpMode, 'auto');
  // при сохранении без пути — прежний путь
  const r = await app.inject({ method: 'PUT', url: `/api/v1/templates/${t.id}`, payload: chain({ transport: 'xhttp', path: '/' }) });
  assert.equal(r.json().spec.path, t.spec.path);
  // свой путь не трогаем
  const own = await create({ ...chain({ transport: 'xhttp', path: '/my' }), name: 'y' });
  assert.equal(own.spec.path, '/my');
  await app.close();
});

test('XHTTP: VLESS → VLESS — везде, только для клиентов, только между серверами', async () => {
  const { create, inbound, vpn, ctx, links, app, db } = await fixture();
  for (const [name, settings, entryNet, legNet] of [
    ['all', { transport: 'xhttp' }, 'xhttp', 'xhttp'],
    ['clients', { transport: 'tcp', entryTransport: 'xhttp' }, 'xhttp', 'tcp'],
    ['leg', { transport: 'xhttp', entryTransport: 'tcp' }, 'tcp', 'xhttp'],
  ] as const) {
    db.prepare('DELETE FROM inbounds').run();
    db.prepare('DELETE FROM templates').run();
    const t = await create({ ...chain(settings), name });
    inbound(`d-${name}`, t.id, 'pl', 'direct');
    inbound(`r-${name}`, t.id, 'ru', 'relay', 'tcp', 9443);
    const entry = vpn.renderXray(ctx.server('ru')) as any;
    const exit = vpn.renderXray(ctx.server('pl')) as any;
    // вход: inbound клиентов и плечо на выход
    const ein = entry.inbounds.find((i: any) => i.tag === `in-r-${name}`);
    assert.equal(ein.streamSettings.network, entryNet, `${name}: транспорт входа`);
    assert.equal(stream(entry, `to-${t.id}-pl`).network, legNet, `${name}: транспорт плеча`);
    assert.equal(stream(exit, `in-d-${name}`).network, legNet, `${name}: транспорт выхода`);
    // Vision — только у звеньев по TCP
    const visionIn = ein.settings.clients.filter((c: any) => !c.email.startsWith('svc.')).map((c: any) => c.flow ?? '');
    assert.ok(visionIn.length && visionIn.every((f: string) => f === (entryNet === 'tcp' ? 'xtls-rprx-vision' : '')), `${name}: flow клиентов входа`);
    const legUser = entry.outbounds.find((o: any) => o.tag === `to-${t.id}-pl`).settings.vnext[0].users[0];
    assert.equal(legUser.flow ?? '', legNet === 'tcp' ? 'xtls-rprx-vision' : '', `${name}: flow плеча`);
    // у XHTTP — путь конфигурации и на входе, и на выходе
    const path = specOf(vpn.template(t.id)!).path;
    if (entryNet === 'xhttp') assert.equal(ein.streamSettings.xhttpSettings.path, path);
    if (legNet === 'xhttp') assert.equal(stream(exit, `in-d-${name}`).xhttpSettings.path, path);
    // ссылки клиентов (через вход) — транспорт входа
    for (const l of Object.values(links())) {
      assert.equal(q(l).get('type'), entryNet, `${name}: ${l}`);
      assert.equal(q(l).get('security'), 'reality');
      if (entryNet === 'xhttp') {
        assert.equal(q(l).get('path'), path);
        assert.equal(q(l).get('mode'), 'auto');
        assert.equal(q(l).get('flow'), null, 'без Vision');
      } else assert.equal(q(l).get('flow'), 'xtls-rprx-vision');
    }
    xrayTest(entry);
    xrayTest(exit);
  }
  await app.close();
});

test('XHTTP: «eskadra» VLESS → VLESS и Hysteria2 — плечо XHTTP, резерв Hysteria2 цел', async () => {
  const { create, inbound, vpn, ctx, links, all, app } = await fixture();
  const t = await create(chain({ bundle: true, transport: 'xhttp' }));
  const hy = all().find((x) => specOf(x).companionOf === t.id)!;
  inbound('v-pl', t.id, 'pl', 'direct');
  inbound('v-ru', t.id, 'ru', 'relay', 'tcp', 9443);
  inbound('h-pl', hy.id, 'pl', 'direct', 'udp');
  const entry = vpn.renderXray(ctx.server('ru')) as any;
  // основное плечо — VLESS по XHTTP, резерв — Hysteria2 через sing-box входа
  assert.equal(stream(entry, `vl-${t.id}-pl`).network, 'xhttp');
  assert.equal(entry.routing.balancers.find((b: any) => b.tag === `fo-${t.id}-pl`).selector[0], `vl-${t.id}-pl`);
  assert.equal(entry.routing.balancers.find((b: any) => b.tag === `fo-${t.id}-pl`).fallbackTag, `hy-${t.id}-pl`);
  assert.equal(entry.outbounds.find((o: any) => o.tag === `hy-${t.id}-pl`).protocol, 'socks');
  const sb = vpn.renderSingbox(ctx.server('ru')) as any;
  assert.equal(sb.outbounds.find((o: any) => o.tag === `hy-${t.id}-pl`).type, 'hysteria2');
  assert.equal((vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-h-pl').type, 'hysteria2');
  assert.equal(stream(entry, 'in-v-ru').network, 'xhttp');
  for (const l of Object.values(links())) assert.equal(q(l).get('type'), 'xhttp');
  xrayTest(entry);
  xrayTest(vpn.renderXray(ctx.server('pl'))!);
  await app.close();
});

test('XHTTP: «eskadra» Hysteria2 → Hysteria2 и VLESS — клиенты по Hysteria2, резервное плечо VLESS по XHTTP', async () => {
  const { create, inbound, vpn, ctx, links, all, app } = await fixture();
  const t = await create(chain({ bundle: true, entryProto: 'hysteria2', transport: 'xhttp' }));
  const hy = all().find((x) => specOf(x).companionOf === t.id)!;
  inbound('v-pl', t.id, 'pl', 'direct');
  inbound('v-ru', t.id, 'ru', 'relay', 'udp', 9443);
  inbound('h-pl', hy.id, 'pl', 'direct', 'udp');
  const entry = vpn.renderXray(ctx.server('ru')) as any;
  // основное плечо — Hysteria2, резерв — VLESS по XHTTP к выходу
  const fo = entry.routing.balancers.find((b: any) => b.tag === `fo-${t.id}-pl`);
  assert.deepEqual([fo.selector[0], fo.fallbackTag], [`hy-${t.id}-pl`, `vl-${t.id}-pl`]);
  assert.equal(stream(entry, `vl-${t.id}-pl`).network, 'xhttp');
  assert.equal(stream(vpn.renderXray(ctx.server('pl')), 'in-v-pl').network, 'xhttp');
  // клиенты подключаются ко входу по Hysteria2 (sing-box), Xray-inbound'а клиентов на входе нет
  assert.ok(!entry.inbounds.some((i: any) => i.tag === 'in-v-ru'));
  const sb = vpn.renderSingbox(ctx.server('ru')) as any;
  assert.equal(sb.inbounds.find((i: any) => i.tag === 'in-v-ru').type, 'hysteria2');
  assert.equal(sb.outbounds.find((o: any) => o.tag === `hy-${t.id}-pl`).type, 'hysteria2');
  for (const l of Object.values(links())) assert.match(l, /^hysteria2:\/\//);
  xrayTest(entry);
  xrayTest(vpn.renderXray(ctx.server('pl'))!);
  // свой транспорт входа и CDN для входа по Hysteria2 не принимаются
  const bad = await ctx_post(app, chain({ bundle: true, entryProto: 'hysteria2', transport: 'xhttp', cdn: 'cdn.example.com' }));
  assert.match(bad, /вход принимает Hysteria2/);
  await app.close();
});

test('XHTTP: Hysteria2 через вход (core) → Hysteria2 и VLESS по XHTTP без входа — работают рядом', async () => {
  const { create, inbound, vpn, ctx, app } = await fixture();
  // Hysteria2 → Hysteria2 (core) и VLESS XHTTP на тех же серверах: конфиги узлов собираются вместе
  const h = await create({ name: 'h', protocol: 'hysteria2', port: 8443, sni: ['www.bing.com'], nodeIds: ['pl'], entryId: 'ru', entryPort: 9443, settings: { certMode: 'self', hy2Relay: 'core' } });
  const v = await create({ ...chain({ transport: 'xhttp' }), name: 'v', port: 7443, entryPort: 7444 });
  inbound('h-pl', h.id, 'pl', 'direct', 'udp');
  inbound('h-ru', h.id, 'ru', 'relay', 'udp', 9443);
  inbound('v-pl', v.id, 'pl', 'direct', 'tcp', 7443);
  inbound('v-ru', v.id, 'ru', 'relay', 'tcp', 7444);
  const entry = vpn.renderXray(ctx.server('ru')) as any;
  assert.equal(stream(entry, 'in-v-ru').network, 'xhttp');
  assert.equal(entry.outbounds.find((o: any) => o.tag === `to-${h.id}-pl`).protocol, 'socks', 'Hysteria2 — плечо через sing-box входа');
  assert.equal((vpn.renderSingbox(ctx.server('ru')) as any).inbounds.find((i: any) => i.tag === 'in-h-ru').type, 'hysteria2');
  xrayTest(entry);
  xrayTest(vpn.renderXray(ctx.server('pl'))!);
  await app.close();
});

test('XHTTP: вход за CDN — клиенты к домену CDN по TLS, packet-up; выходы на REALITY', async () => {
  const { create, inbound, vpn, ctx, links, app, db } = await fixture();
  const t = await create({ ...chain({ cdn: 'cdn.example.com' }), entryPort: 443 });
  inbound('d-pl', t.id, 'pl', 'direct');
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, short_id) VALUES ('r-ru', ?, 'ru', 'relay', 443, 'tcp', 'active', 'a1')`).run(t.id);
  const entry = vpn.renderXray(ctx.server('ru')) as any;
  const ein = entry.inbounds.find((i: any) => i.tag === 'in-r-ru');
  assert.equal(ein.streamSettings.network, 'xhttp');
  assert.equal(ein.streamSettings.security, 'tls');
  assert.equal(ein.streamSettings.xhttpSettings.host, 'cdn.example.com');
  assert.deepEqual(ein.streamSettings.tlsSettings.certificates, [{ certificateFile: `/etc/eskadra/tls/cdn-${t.id}/fullchain.pem`, keyFile: `/etc/eskadra/tls/cdn-${t.id}/privkey.pem` }]);
  assert.ok(ein.settings.clients.every((c: any) => !c.flow));
  // плечо и выход — как были: REALITY по TCP с Vision
  assert.equal(stream(entry, `to-${t.id}-pl`).network, 'tcp');
  assert.equal(stream(entry, `to-${t.id}-pl`).security, 'reality');
  assert.equal(entry.outbounds.find((o: any) => o.tag === `to-${t.id}-pl`).settings.vnext[0].users[0].flow, 'xtls-rprx-vision');
  const ls = Object.values(links());
  assert.ok(ls.length);
  for (const l of ls) {
    const u = new URL(l);
    assert.equal(u.hostname, 'cdn.example.com');
    assert.equal(u.port, '443');
    assert.deepEqual([q(l).get('type'), q(l).get('security'), q(l).get('sni'), q(l).get('host'), q(l).get('mode')], ['xhttp', 'tls', 'cdn.example.com', 'cdn.example.com', 'packet-up']);
    assert.equal(q(l).get('path'), specOf(vpn.template(t.id)!).path);
    assert.equal(q(l).get('pbk'), null);
  }
  // подписка sing-box: XHTTP он не умеет — профиля там нет, а не сломанный
  const p = vpn.profiles(db.prepare('SELECT * FROM users').get() as unknown as UserRow)[0]!;
  const { singboxOutbound } = await import('./protocols.js');
  assert.equal(singboxOutbound(vpn.profileSpec(p), 's', vpn.target(p)), null);
  if (process.env.XRAY_BIN && process.env.XRAY_TEST_CERT) {
    const [crt, key] = process.env.XRAY_TEST_CERT.split(path.delimiter);
    xrayTest(entry, { crt: crt!, key: key! });
  }
  xrayTest(vpn.renderXray(ctx.server('pl'))!);
  // CDN — только через вход
  assert.match(await ctx_post(app, { ...chain({ cdn: 'cdn.example.com' }), name: 'z', entryId: null, entryPort: null }), /только для VLESS через вход/);
  await app.close();
});

async function ctx_post(app: { inject: (o: object) => Promise<{ body: string }> }, payload: Record<string, unknown>) {
  return (await app.inject({ method: 'POST', url: '/api/v1/templates', payload: { ...payload, name: 'bad' } })).body;
}

test('XHTTP: тонкая настройка — серверу серверное, клиенту и ссылке клиентское; через CDN — свой режим и HTTP/3', async () => {
  const { create, inbound, vpn, ctx, links, app, db } = await fixture();
  const xhttpExtra = {
    xPaddingBytes: '200-800', noGRPCHeader: true, noSSEHeader: true, scMaxEachPostBytes: '500000', scMinPostsIntervalMs: '50',
    scMaxBufferedPosts: '40', scStreamUpServerSecs: '30-60', xmux: { maxConcurrency: '8-16', hMaxRequestTimes: '500-700', hKeepAlivePeriod: '' },
  };
  const t = await create(chain({ transport: 'xhttp', xhttpExtra }));
  inbound('d-pl', t.id, 'pl', 'direct');
  inbound('r-ru', t.id, 'ru', 'relay', 'tcp', 9443);
  const entry = vpn.renderXray(ctx.server('ru')) as any;
  const exit = vpn.renderXray(ctx.server('pl')) as any;
  assert.deepEqual(stream(exit, 'in-d-pl').xhttpSettings.extra,
    { xPaddingBytes: '200-800', scMaxEachPostBytes: 500000, scMaxBufferedPosts: 40, scStreamUpServerSecs: '30-60', noSSEHeader: true });
  const client = { xPaddingBytes: '200-800', scMaxEachPostBytes: 500000, scMinPostsIntervalMs: 50, noGRPCHeader: true, xmux: { maxConcurrency: '8-16', hMaxRequestTimes: '500-700' } };
  assert.deepEqual(stream(entry, `to-${t.id}-pl`).xhttpSettings.extra, client, 'плечо — клиентская сторона');
  for (const l of Object.values(links())) assert.deepEqual(JSON.parse(q(l).get('extra')!), client);
  xrayTest(entry);
  xrayTest(exit);
  // через CDN: режим и HTTP/3 — только в ссылках, вход принимает CDN по TLS/TCP (h2, http/1.1)
  db.prepare('DELETE FROM inbounds').run();
  db.prepare('DELETE FROM templates').run();
  const c = await create({ ...chain({ cdn: 'cdn.example.com', cdnMode: 'stream-up', cdnH3: true }), name: 'c', entryPort: 443 });
  inbound('d-pl', c.id, 'pl', 'direct');
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, short_id) VALUES ('r-ru', ?, 'ru', 'relay', 443, 'tcp', 'active', 'a1')`).run(c.id);
  for (const l of Object.values(links())) assert.deepEqual([q(l).get('mode'), q(l).get('alpn')], ['stream-up', 'h3']);
  assert.deepEqual(stream(vpn.renderXray(ctx.server('ru')), 'in-r-ru').tlsSettings.alpn, ['h2', 'http/1.1']);
  // проверки значений
  const bad = (over: Record<string, unknown>) => ctx_post(app, chain({ transport: 'xhttp', xhttpExtra: over }));
  assert.match(await bad({ xmux: { maxConcurrency: '8', maxConnections: '4' } }), /вместе не задаются/);
  assert.match(await bad({ xPaddingBytes: '900-100' }), /начало больше конца/);
  assert.match(await bad({ scMinPostsIntervalMs: 'abc' }), /число или диапазон/);
  await app.close();
});
