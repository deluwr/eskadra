import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, type UserRow } from './ctx.js';
import { Vpn } from './vpn.js';
import { hinPort, legPort, specOf } from './protocols.js';
import { saveUser, userBody } from './routes/users.js';

const PIN = 'ab'.repeat(32);

/**
 * Вход ru (198.51.100.10), выходы pl (203.0.113.5) и fi (203.0.113.6).
 * h — Hysteria2 через вход с ядрами на входе (core): оба выхода, авто-выбор; hb — Hysteria2 напрямую на pl
 * (резервное плечо для v); v — VLESS REALITY через вход на оба выхода с резервом по Hysteria2 (hb).
 */
function fixture(hSettings: Record<string, unknown> = {}, vSettings: Record<string, unknown> = { hy2Leg: 'hb' }) {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-hy2c-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 9)));
  for (const [id, host, role] of [['ru', '198.51.100.10', 'entry'], ['pl', '203.0.113.5', 'exit'], ['fi', '203.0.113.6', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, ?, ?, 'k', 'x', 'restricted')`).run(id, id, host, role);
  const tpl = (id: string, core: string, protocol: string, port: number, sni: string, nodes: string[], entry: string | null, entryPort: number | null, settings: object) =>
    db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, id, core, protocol, port, sni, JSON.stringify(nodes), entry, entryPort, JSON.stringify(settings));
  const ib = (id: string, t: string, s: string, kind: string, port: number, proto: string, extra: { pin?: string; pub?: string } = {}) =>
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, tls_pin, public_key, short_id) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, 'aa')`)
      .run(id, t, s, kind, port, proto, extra.pin ?? null, extra.pub ?? null);
  tpl('h', 'sing-box', 'hysteria2', 8444, '["hy.example"]', ['pl', 'fi'], 'ru', 9444, { certMode: 'self', hy2Relay: 'core', autoMode: 'order', hy2Hop: '20000-21000', ...hSettings });
  ib('h-pl', 'h', 'pl', 'direct', 8444, 'udp', { pin: PIN });
  ib('h-fi', 'h', 'fi', 'direct', 8444, 'udp', { pin: PIN });
  ib('h-ru', 'h', 'ru', 'relay', 9444, 'udp', { pin: 'cd'.repeat(32) });
  tpl('hb', 'sing-box', 'hysteria2', 8555, '["hb.example"]', ['pl'], null, null, { certMode: 'self', hy2Obfs: 'ob' });
  ib('hb-pl', 'hb', 'pl', 'direct', 8555, 'udp', { pin: PIN });
  tpl('v', 'xray', 'vless', 8443, '["www.apple.com"]', ['pl', 'fi'], 'ru', 9443, { security: 'reality', autoMode: 'order', ...vSettings });
  ib('v-pl', 'v', 'pl', 'direct', 8443, 'tcp', { pub: 'PUB' });
  ib('v-fi', 'v', 'fi', 'direct', 8443, 'tcp', { pub: 'PUB' });
  ib('v-ru', 'v', 'ru', 'relay', 9443, 'tcp');
  const id = saveUser(ctx, null, userBody.parse({ name: 'ann' }));
  const user = () => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as UserRow;
  return { db, ctx, vpn: new Vpn(ctx), id, user };
}

const sbIn = (cfg: any, tag: string) => cfg.inbounds.find((i: any) => i.tag === tag);
const sbOut = (cfg: any, tag: string) => cfg.outbounds.find((o: any) => o.tag === tag);
const xOut = (cfg: any, tag: string) => cfg.outbounds.find((o: any) => o.tag === tag);
const xIn = (cfg: any, tag: string) => cfg.inbounds.find((i: any) => i.tag === tag);

test('telemt: конфигурация без пользователей — служебный пользователь, ядро не падает с «No users configured»', () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-mt-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 9)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES ('nl', 'nl-1', '203.0.113.9', 'exit', 'k', 'x', 'restricted')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('mt', 'mt', 'telemt', 'mtproto', 443, '[]', '["nl"]', '{}')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('mt-nl', 'mt', 'nl', 'direct', 443, 'tcp', 'deploying')`).run();
  const toml = new Vpn(ctx).renderTelemt(ctx.server('nl'))!;
  const users = toml.slice(toml.indexOf('[access.users]')).split('\n').slice(1).filter((l) => l.includes('='));
  assert.equal(users.length, 1);
  assert.match(users[0]!, /^"svc\.panel" = "[0-9a-f]{32}"$/);
  // секрет постоянный — повторный рендер не перезапускает ядро
  assert.equal(new Vpn(ctx).renderTelemt(ctx.server('nl')), toml);
});

test('Hysteria2 через вход (core): профили на каждый выход и «авто», ссылка — на вход с его сертификатом', () => {
  const { vpn, user, id } = fixture();
  const ps = vpn.profiles(user()).filter((p) => p.template.id === 'h');
  assert.deepEqual(ps.map((p) => p.key).sort(), ['d:h:fi', 'd:h:pl', 'v:h:auto', 'v:h:fi', 'v:h:pl']);
  const auto = ps.find((p) => p.key === 'v:h:auto')!;
  const u = new URL(vpn.link(user(), auto).replace('hysteria2://', 'https://'));
  assert.equal(u.hostname, '198.51.100.10');
  assert.equal(u.port, '9444');
  assert.equal(u.searchParams.get('pinSHA256'), 'cd'.repeat(32), 'сертификат — входа: клиент договаривается с sing-box входа');
  assert.equal(decodeURIComponent(u.username), vpn.cred(id, 'v:h:auto'));
});

test('Hysteria2 через вход (core): sing-box входа принимает клиентов и раздаёт их по локальным SOCKS Xray', () => {
  const { vpn, ctx, id } = fixture();
  const sb = vpn.renderSingbox(ctx.server('ru')) as any;
  const relay = sbIn(sb, 'in-h-ru');
  assert.equal(relay.type, 'hysteria2');
  assert.equal(relay.listen_port, 9444);
  assert.equal(relay.tls.certificate_path, '/etc/eskadra/sing-box/tls/hy.example.crt');
  const pw = (name: string) => relay.users.find((x: any) => x.name === name)?.password;
  assert.equal(pw(`${id}.v-pl`), vpn.cred(id, 'v:h:pl'));
  assert.equal(pw(`${id}.v-fi`), vpn.cred(id, 'v:h:fi'));
  assert.equal(pw(`${id}.a-h`), vpn.cred(id, 'v:h:auto'));
  const rules = sb.route.rules as any[];
  for (const route of ['pl', 'fi', 'auto']) {
    assert.equal(sbOut(sb, `hin-h-ru-${route}`).server_port, hinPort('h-ru', route));
    assert.ok(rules.some((r) => r.inbound?.[0] === 'in-h-ru' && r.outbound === `hin-h-ru-${route}`));
  }
  const reject = rules.findIndex((r) => r.inbound?.[0] === 'in-h-ru' && r.action === 'reject');
  assert.ok(reject > rules.findIndex((r) => r.outbound === 'hin-h-ru-auto'), 'неопознанное с входа — отклоняется после маршрутов пользователей');
  assert.ok(reject < rules.findIndex((r) => r.action === 'resolve'), 'маршруты входа — до общих правил');
  // плечи Hysteria2 к обоим выходам: пароль знает inbound выхода
  for (const x of ['pl', 'fi']) {
    assert.equal(sbIn(sb, `leg-hy-h-${x}`).listen_port, legPort('h', x));
    const leg = sbOut(sb, `hy-h-${x}`);
    assert.equal(leg.type, 'hysteria2');
    assert.equal(leg.server_port, 8444);
    const exitUsers = (vpn.renderSingbox(ctx.server(x)) as any).inbounds.find((i: any) => i.tag === `in-h-${x}`).users;
    assert.equal(exitUsers.find((u: any) => u.name === 'svc.relay-ru-h').password, leg.password);
  }
  assert.equal(sbOut(sb, 'hy-h-pl').server, '203.0.113.5');
  assert.deepEqual(sbOut(sb, 'hy-h-pl').server_ports, ['20000:21000'], 'смена портов — и на плече к выходу');
  // смена портов на входе — на inbound входа
  assert.match(vpn.hy2Hops(ctx.server('ru')), /9444:20000-21000/);
  assert.equal(vpn.hy2Relays(ctx.server('ru')), '-', 'пересылки ядром ОС нет');
});

test('Hysteria2 через вход (core): Xray входа выбирает выход — балансировщики как у VLESS, плечи через sing-box', () => {
  const { vpn, ctx } = fixture();
  const x = vpn.renderXray(ctx.server('ru')) as any;
  assert.equal(xIn(x, 'in-h-ru'), undefined, 'inbound Hysteria2 держит sing-box');
  for (const e of ['pl', 'fi']) {
    assert.deepEqual(xOut(x, `to-h-${e}`).settings.servers, [{ address: '127.0.0.1', port: legPort('h', e) }]);
    assert.equal(xIn(x, `hin-h-ru-${e}`).port, hinPort('h-ru', e));
    assert.ok(x.routing.rules.some((r: any) => r.inboundTag?.[0] === `hin-h-ru-${e}` && r.outboundTag === `to-h-${e}`));
    assert.ok(xIn(x, `probe-h-${e}`), 'пробы выходов — как у VLESS');
  }
  assert.equal(xIn(x, 'hin-h-ru-auto').settings.udp, true);
  assert.ok(x.routing.rules.some((r: any) => r.inboundTag?.[0] === 'hin-h-ru-auto' && r.balancerTag === 'bal-h'));
  // по порядку: цепочка уровней
  const bal = x.routing.balancers.find((b: any) => b.tag === 'bal-h');
  assert.deepEqual(bal.selector, ['to-h-pl']);
  assert.equal(bal.fallbackTag, 'lb-h-2');
  assert.ok(x.burstObservatory.subjectSelector.includes('to-h-'));
});

test('Hysteria2 через вход (core): «по нагрузке» не выбирается, авто выключено — без «авто» и балансировщиков', () => {
  assert.equal(specOf({ protocol: 'hysteria2', sni: '[]', fingerprint: '', settings: '{"hy2Relay":"core","autoMode":"spread"}' }).autoMode, 'order');
  assert.equal(specOf({ protocol: 'hysteria2', sni: '[]', fingerprint: '', settings: '{"hy2Relay":"core"}' }).autoEnabled, true);
  const { vpn, ctx, user } = fixture({ autoEnabled: false });
  assert.ok(!vpn.profiles(user()).some((p) => p.key === 'v:h:auto'));
  const x = vpn.renderXray(ctx.server('ru')) as any;
  assert.equal(xIn(x, 'hin-h-ru-auto'), undefined);
  assert.ok(!x.routing.balancers.some((b: any) => b.tag === 'bal-h'));
  assert.equal(sbOut(vpn.renderSingbox(ctx.server('ru')), 'hin-h-ru-auto'), undefined);
});

test('VLESS через вход с резервом Hysteria2: основное плечо не отвечает — выход идёт по Hysteria2', () => {
  const { vpn, ctx, id } = fixture();
  const x = vpn.renderXray(ctx.server('ru')) as any;
  // pl: у резервной конфигурации есть inbound — выход стал loopback в балансировщик «VLESS, иначе Hysteria2»
  assert.equal(xOut(x, 'to-v-pl').protocol, 'loopback');
  assert.equal(xOut(x, 'vl-v-pl').protocol, 'vless');
  assert.equal(xOut(x, 'vl-v-pl').streamSettings.sockopt.tcpUserTimeout, 20000);
  assert.deepEqual(xOut(x, 'hy-v-pl').settings.servers, [{ address: '127.0.0.1', port: legPort('v', 'pl') }]);
  const fo = x.routing.balancers.find((b: any) => b.tag === 'fo-v-pl');
  assert.deepEqual(fo.selector, ['vl-v-pl']);
  assert.equal(fo.fallbackTag, 'hy-v-pl');
  assert.ok(x.routing.rules.some((r: any) => r.inboundTag?.[0] === 'lg-v-pl' && r.balancerTag === 'fo-v-pl'));
  assert.ok(x.burstObservatory.subjectSelector.includes('vl-v-'), 'основное плечо проверяется');
  assert.equal(x.burstObservatory.pingConfig.interval, '5s');
  // явный «вход → pl», «авто» и пробы ведут на to-v-pl — переключение протокола для них прозрачно
  assert.ok(x.routing.rules.some((r: any) => r.user?.includes(`${id}.v-pl`) && r.outboundTag === 'to-v-pl'));
  assert.deepEqual(x.routing.balancers.find((b: any) => b.tag === 'bal-v').selector, ['to-v-pl']);
  // fi: Hysteria2-резерва там нет — как раньше, прямой VLESS-outbound
  assert.equal(xOut(x, 'to-v-fi').protocol, 'vless');
  assert.equal(xOut(x, 'vl-v-fi'), undefined);
  // клиент по-прежнему подключается ко входу по VLESS
  assert.equal(xIn(x, 'in-v-ru').protocol, 'vless');
  // sing-box входа держит плечо к inbound'у hb на pl, пароль плеча знает выход
  const sb = vpn.renderSingbox(ctx.server('ru')) as any;
  const leg = sbOut(sb, 'hy-v-pl');
  assert.equal(leg.server, '203.0.113.5');
  assert.equal(leg.server_port, 8555);
  assert.deepEqual(leg.obfs, { type: 'salamander', password: 'ob' }, 'настройки — резервной конфигурации');
  assert.equal(sbIn(sb, 'leg-hy-v-pl').listen_port, legPort('v', 'pl'));
  assert.equal(sbOut(sb, 'hy-v-fi'), undefined);
  const exit = (vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-hb-pl');
  assert.equal(exit.users.find((u: any) => u.name === 'svc.leg-v').password, leg.password);
});

test('VLESS через вход без резерва — конфиг входа прежний (без loopback и плеч)', () => {
  const { vpn, ctx } = fixture({}, {});
  const x = vpn.renderXray(ctx.server('ru')) as any;
  assert.equal(xOut(x, 'to-v-pl').protocol, 'vless');
  assert.ok(!x.outbounds.some((o: any) => /^(vl|hy)-v-/.test(o.tag)));
  assert.ok(!x.routing.balancers.some((b: any) => b.tag.startsWith('fo-v-')));
  assert.equal(sbOut(vpn.renderSingbox(ctx.server('ru')), 'hy-v-pl'), undefined);
  assert.ok(!(vpn.renderSingbox(ctx.server('pl')) as any).inbounds.find((i: any) => i.tag === 'in-hb-pl').users.some((u: any) => u.name === 'svc.leg-v'));
});

test('проверка конфигурации: Hysteria2 core — несколько выходов; резервное плечо — только к Hysteria2 на тех же выходах', async () => {
  const { ctx } = fixture();
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app, ctx);
  const save = (payload: Record<string, unknown>) => app.inject({ method: 'POST', url: '/api/v1/templates', payload });
  const hy = { protocol: 'hysteria2', port: 8446, sni: ['hy.example'], nodeIds: ['pl', 'fi'], entryId: 'ru', entryPort: 9446 };
  let r = await save({ ...hy, name: 'hc', settings: { certMode: 'self', hy2Relay: 'core' } });
  assert.equal(r.statusCode, 200, r.body);
  assert.equal(r.json().spec.autoEnabled, true);
  assert.match((await save({ ...hy, name: 'hn', settings: { certMode: 'self' } })).body, /один выход/);
  assert.match((await save({ ...hy, name: 'hs', settings: { certMode: 'self', hy2Relay: 'core', autoMode: 'spread' } })).body, /по нагрузке/);
  const vl = { protocol: 'vless', port: 8447, sni: ['www.apple.com'], nodeIds: ['pl', 'fi'], entryId: 'ru', entryPort: 9447 };
  r = await save({ ...vl, name: 'vok', settings: { security: 'reality', hy2Leg: 'hb' } });
  assert.equal(r.statusCode, 200, r.body);
  assert.equal(r.json().spec.hy2Leg, 'hb');
  assert.match((await save({ ...vl, name: 'vnone', settings: { security: 'reality', hy2Leg: 'nope' } })).body, /существующую конфигурацию Hysteria2/);
  assert.match((await save({ ...vl, name: 'vvl', settings: { security: 'reality', hy2Leg: 'v' } })).body, /существующую конфигурацию Hysteria2/);
  assert.match((await save({ ...vl, name: 'vfi', nodeIds: ['fi'], settings: { security: 'reality', hy2Leg: 'hb' } })).body, /нет ни одного из выходов/);
  assert.match((await save({ ...vl, name: 'vdir', entryId: null, entryPort: null, settings: { security: 'reality', hy2Leg: 'hb' } })).body, /только для конфигурации через вход/);
  await app.close();
});
