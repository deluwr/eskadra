import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { blocksOf } from './blocks.js';

/** Выход с Xray-конфигурацией (sniffing выключен) и Hysteria2. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-blk-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 4)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES ('x', 'x', '203.0.113.7', 'exit', 'k', 'x', 'restricted')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('t', 'v', 'xray', 'vless', 8443, '[]', '["x"]', '{"security":"none","sniffing":false}')`).run();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, settings) VALUES ('h', 'hy', 'sing-box', 'hysteria2', 8444, '["hy.example"]', '["x"]', '{"certMode":"self"}')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('ib-t', 't', 'x', 'direct', 8443, 'tcp', 'active')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('ib-h', 'h', 'x', 'direct', 8444, 'udp', 'active')`).run();
  return { db, ctx, vpn: new Vpn(ctx) };
}

test('блокировки: BitTorrent по умолчанию — протокол и трекеры, sniffing включается сам (только для маршрутизации)', () => {
  const { db, ctx, vpn } = fixture();
  assert.deepEqual(blocksOf(db), { bittorrent: true, smtp: false, quic: false });
  const x = vpn.renderXray(ctx.server('x')) as any;
  const rules = x.routing.rules as any[];
  assert.ok(rules.some((r) => r.protocol?.includes('bittorrent') && r.outboundTag === 'block' && !r.ruleTag));
  assert.ok(rules.some((r) => r.domain?.includes('geosite:category-public-tracker') && r.outboundTag === 'block'));
  const ib = x.inbounds.find((i: any) => i.tag === 'in-ib-t');
  assert.deepEqual(ib.sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true }, 'адрес назначения не подменяется — sniffing в конфигурации выключен');
  const sb = vpn.renderSingbox(ctx.server('x')) as any;
  assert.deepEqual(sb.route.rules[0], { action: 'sniff' });
  assert.ok(sb.route.rules.some((r: any) => r.protocol?.includes('bittorrent') && r.action === 'reject'));
});

test('блокировки: почта и QUIC по выбору; всё выключено — ни правил, ни принудительного sniffing', () => {
  const { db, ctx, vpn } = fixture();
  setSetting(db, 'blocks', { bittorrent: false, smtp: true, quic: true });
  let x = vpn.renderXray(ctx.server('x')) as any;
  assert.ok(x.routing.rules.some((r: any) => r.network === 'tcp' && r.port === '25,465,587,2525' && r.outboundTag === 'block'));
  assert.ok(x.routing.rules.some((r: any) => r.network === 'udp' && r.port === '443' && r.outboundTag === 'block'));
  assert.equal(x.inbounds.find((i: any) => i.tag === 'in-ib-t').sniffing, undefined);
  setSetting(db, 'blocks', { bittorrent: false, smtp: false, quic: false });
  x = vpn.renderXray(ctx.server('x')) as any;
  assert.ok(!x.routing.rules.some((r: any) => r.protocol || r.domain || r.port));
  const sb = vpn.renderSingbox(ctx.server('x')) as any;
  assert.equal(sb.route.rules[0].action, 'resolve');
});
