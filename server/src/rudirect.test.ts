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
