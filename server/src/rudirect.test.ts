import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { ruDirectOf } from './rudirect.js';

/** Вход relay → выходы pl, fi; у пользователя доступ «через вход». */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-ru-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 5)));
  for (const [id, role] of [['relay', 'entry'], ['pl', 'exit'], ['fi', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'duo', 'xray', 'vless', 8443, '[]', '["pl","fi"]', 'relay', 9443, '{"security":"reality","sniffing":false}')`).run();
  for (const s of ['pl', 'fi']) db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES (?, 't', ?, 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run(`ib-${s}`, s);
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active', 'P', 'a')`).run();
  setSetting(db, 'blocks', { bittorrent: false, smtp: false, quic: false });
  return { db, ctx, vpn: new Vpn(ctx) };
}

const ruRules = (cfg: any) => (cfg.routing.rules as any[]).filter((r) => r.outboundTag === 'direct' && (r.domain?.includes('domain:ru') || r.ip?.includes('geoip:ru')));

test('RU напрямую: по умолчанию выключено — конфиги входа и выходов те же, что без настройки', () => {
  const { db, ctx, vpn } = fixture();
  assert.deepEqual(ruDirectOf(db), { entries: [] });
  const before = ['relay', 'pl', 'fi'].map((id) => JSON.stringify(vpn.renderXray(ctx.server(id)!)));
  // включено на другом сервере — этот вход не меняется
  setSetting(db, 'ruDirect', { entries: ['fi'] });
  assert.equal(JSON.stringify(vpn.renderXray(ctx.server('relay')!)), before[0]);
  assert.equal(JSON.stringify(vpn.renderXray(ctx.server('pl')!)), before[1]);
  assert.equal(ruRules(vpn.renderXray(ctx.server('relay')!)).length, 0);
  // выход: inbound'ы direct не трогаются даже при включении на нём самом
  assert.equal(JSON.stringify(vpn.renderXray(ctx.server('fi')!)), before[2]);
});

test('RU напрямую на входе: правила на inbound входа раньше маршрутов на выходы, sniffing только для маршрутизации', () => {
  const { db, ctx, vpn } = fixture();
  setSetting(db, 'ruDirect', { entries: ['relay'] });
  const x = vpn.renderXray(ctx.server('relay')!) as any;
  const rules = x.routing.rules as any[];
  const ru = ruRules(x);
  assert.equal(ru.length, 2);
  for (const r of ru) assert.deepEqual(r.inboundTag, ['in-ib-r']);
  assert.ok(ru[0].domain.includes('geosite:category-ru') && ru[0].domain.includes('domain:xn--p1ai'));
  assert.deepEqual(ru[1].ip, ['geoip:ru']);
  // после служебных (частные адреса — в блок), раньше «всё прочее с входа — в блок» и маршрутов на выходы
  const at = rules.indexOf(ru[0]);
  assert.ok(rules.findIndex((r) => r.ip?.includes('geoip:private') || (Array.isArray(r.ip) && r.outboundTag === 'block')) < at);
  assert.ok(rules.findIndex((r) => r.inboundTag?.includes('in-ib-r') && r.outboundTag === 'block') > at);
  assert.ok(ru.every((r) => typeof r.ruleTag === 'string'), 'правила с тегом поколения — меняются на работающем Xray без перезапуска');
  const ib = x.inbounds.find((i: any) => i.tag === 'in-ib-r');
  assert.deepEqual(ib.sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true });
});

/** Вход ru: v — VLESS через вход на pl, h — Hysteria2 через вход (ядра на входе) на pl; RU напрямую на ru. */
async function entryFixture() {
  const { saveUser, userBody } = await import('./routes/users.js');
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-ru-ig-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 10)));
  for (const [id, role] of [['ru', 'entry'], ['pl', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.9', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  const tpl = (id: string, core: string, protocol: string, port: number, sni: string, entryPort: number, settings: object) =>
    db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES (?, ?, ?, ?, ?, ?, '["pl"]', 'ru', ?, ?)`)
      .run(id, id, core, protocol, port, sni, entryPort, JSON.stringify(settings));
  const ib = (id: string, t: string, s: string, kind: string, port: number, proto: string) =>
    db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, tls_pin, public_key, short_id) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, 'PUB', 'aa')`)
      .run(id, t, s, kind, port, proto, 'ab'.repeat(32));
  tpl('v', 'xray', 'vless', 8443, '["www.apple.com"]', 9443, { security: 'reality', autoEnabled: false });
  ib('v-pl', 'v', 'pl', 'direct', 8443, 'tcp'); ib('v-ru', 'v', 'ru', 'relay', 9443, 'tcp');
  tpl('h', 'sing-box', 'hysteria2', 8444, '["hy.example"]', 9444, { certMode: 'self', hy2Relay: 'core', autoEnabled: false });
  ib('h-pl', 'h', 'pl', 'direct', 8444, 'udp'); ib('h-ru', 'h', 'ru', 'relay', 9444, 'udp');
  setSetting(db, 'blocks', { bittorrent: false, smtp: false, quic: false });
  const a = saveUser(ctx, null, userBody.parse({ name: 'a', modes: ['via'] }));
  const b = saveUser(ctx, null, userBody.parse({ name: 'b', modes: ['via'] }));
  return { db, ctx, vpn: new Vpn(ctx), a, b, saveUser, userBody };
}

test('игнорировать глобальные правила: пока ни у кого не включено — конфиги входа прежние', async () => {
  const f = await entryFixture();
  const before = [JSON.stringify(f.vpn.renderXray(f.ctx.server('ru'))), JSON.stringify(f.vpn.renderSingbox(f.ctx.server('ru')))];
  // флажок у пользователя при выключенных RU-правилах ничего не меняет
  f.db.prepare('UPDATE users SET ignore_global_routes = 1 WHERE id = ?').run(f.a);
  assert.deepEqual([JSON.stringify(f.vpn.renderXray(f.ctx.server('ru'))), JSON.stringify(f.vpn.renderSingbox(f.ctx.server('ru')))], before);
  // RU-правила включены, флажков нет — правило на inbound'е целиком, как раньше
  f.db.prepare('UPDATE users SET ignore_global_routes = 0').run();
  setSetting(f.db, 'ruDirect', { entries: ['ru'] });
  const ru = ruRules(f.vpn.renderXray(f.ctx.server('ru')));
  assert.equal(ru.length, 2);
  assert.deepEqual(ru[0].inboundTag, ['in-v-ru', 'hin-h-ru-pl']);
  assert.equal(ru[0].user, undefined);
});

test('игнорировать глобальные правила: VLESS — RU-правило только для остальных, Hysteria2 — отдельный SOCKS без RU-правил', async () => {
  const f = await entryFixture();
  setSetting(f.db, 'ruDirect', { entries: ['ru'] });
  f.saveUser(f.ctx, f.a, f.userBody.parse({ name: 'a', modes: ['via'], ignoreGlobalRoutes: true }));
  assert.equal((f.db.prepare('SELECT ignore_global_routes AS g FROM users WHERE id = ?').get(f.a) as { g: number }).g, 1);
  const x = f.vpn.renderXray(f.ctx.server('ru')) as any;
  const ru = ruRules(x);
  // VLESS: пара правил с user — только b; Hysteria2: общий SOCKS выхода — целиком (там только b)
  const vless = ru.filter((r) => r.inboundTag.includes('in-v-ru'));
  assert.equal(vless.length, 2);
  for (const r of vless) assert.deepEqual(r.user, [`${f.b}.v-pl`]);
  const hy = ru.filter((r) => r.inboundTag.includes('hin-h-ru-pl'));
  assert.equal(hy.length, 2);
  assert.ok(!ru.some((r) => r.inboundTag.includes('hin-h-ru-pl-g')), 'SOCKS игнорирующих — без RU-правил');
  // оба SOCKS ведут на выход
  const rules = x.routing.rules as any[];
  assert.ok(rules.some((r) => r.inboundTag?.includes('hin-h-ru-pl') && r.inboundTag?.includes('hin-h-ru-pl-g') && r.outboundTag === 'to-h-pl'));
  assert.ok(x.inbounds.some((i: any) => i.tag === 'hin-h-ru-pl-g'));
  // sing-box: a — в SOCKS …-g, b — в общий
  const sb = f.vpn.renderSingbox(f.ctx.server('ru')) as any;
  const rr = sb.route.rules as any[];
  assert.deepEqual(rr.find((r) => r.outbound === 'hin-h-ru-pl-g')?.auth_user, [`${f.a}.v-pl`]);
  assert.deepEqual(rr.find((r) => r.outbound === 'hin-h-ru-pl')?.auth_user, [`${f.b}.v-pl`]);
  // все на входе игнорируют — RU-правил на VLESS-inbound'е нет совсем
  f.db.prepare('UPDATE users SET ignore_global_routes = 1').run();
  assert.ok(!ruRules(f.vpn.renderXray(f.ctx.server('ru'))).some((r) => r.inboundTag.includes('in-v-ru')));
  // флажок не передан (бот) — прежнее значение не сбрасывается
  f.saveUser(f.ctx, f.a, f.userBody.parse({ name: 'a', modes: ['via'] }));
  assert.equal((f.db.prepare('SELECT ignore_global_routes AS g FROM users WHERE id = ?').get(f.a) as { g: number }).g, 1);
});
