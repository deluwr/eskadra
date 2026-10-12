import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, type UserRow } from './ctx.js';
import { Vpn } from './vpn.js';
import { saveUser, userBody } from './routes/users.js';
import { maskPersonIps } from './ipmask.js';
import { roleOf } from './roles.js';

/** Вход relay, выходы pl и fi; пользователь ann с обоими режимами. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-var-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 8)));
  for (const [id, role] of [['relay', 'entry'], ['pl', 'exit'], ['fi', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'duo', 'xray', 'vless', 8443, '[]', '["pl","fi"]', 'relay', 9443, '{"security":"none","autoMode":"order","exitOrder":["pl","fi"]}')`).run();
  for (const s of ['pl', 'fi']) db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES (?, 't', ?, 'direct', 8443, 'tcp', 'active')`).run(`ib-${s}`, s);
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active')`).run();
  const id = saveUser(ctx, null, userBody.parse({ name: 'ann' }));
  const user = () => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as UserRow;
  return { db, ctx, vpn: new Vpn(ctx), id, user };
}
const emails = (cfg: any) => cfg.inbounds.flatMap((i: any) => (i.settings?.clients ?? []).map((c: any) => c.email)).filter((e: string) => e.startsWith('u-'));

test('варианты: выключенный — нет ни в подписке, ни среди клиентов узла (ссылка не работает); остальные на месте', () => {
  const { ctx, vpn, id, user } = fixture();
  assert.deepEqual(vpn.profiles(user()).map((p) => p.key).sort(), ['d:t:fi', 'd:t:pl', 'v:t:auto', 'v:t:fi', 'v:t:pl']);
  saveUser(ctx, id, userBody.parse({ name: 'ann', excludedProfiles: ['d:t:fi', 'v:t:auto'] }));
  assert.deepEqual(vpn.profiles(user()).map((p) => p.key).sort(), ['d:t:pl', 'v:t:fi', 'v:t:pl']);
  assert.deepEqual(emails(vpn.renderXray(ctx.server('fi'))), [], 'напрямую к fi — клиента нет');
  assert.deepEqual(emails(vpn.renderXray(ctx.server('pl'))), [`${id}.d-t`]);
  assert.deepEqual(emails(vpn.renderXray(ctx.server('relay'))).sort(), [`${id}.v-fi`, `${id}.v-pl`], '«авто» на входе — нет');
  // не передано — прежний выбор не меняется (бот, привязка Telegram)
  saveUser(ctx, id, userBody.parse({ name: 'ann' }));
  assert.deepEqual(JSON.parse(user().excluded_profiles!), ['d:t:fi', 'v:t:auto']);
  saveUser(ctx, id, userBody.parse({ name: 'ann', excludedProfiles: [] }));
  assert.equal(user().excluded_profiles, null);
});

test('варианты: «авто» не выдаётся, если конфигурация пользователю не выдана', () => {
  const { ctx, vpn, id } = fixture();
  ctx.db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES ('t2', 'other', 'xray', 'vless', 8444, '[]', '[]')`).run();
  saveUser(ctx, id, userBody.parse({ name: 'ann', templateIds: ['t2'] }));
  assert.deepEqual(emails(vpn.renderXray(ctx.server('relay'))), []);
});

test('варианты от роли с областью: чужие выключенные — как были, свои — как прислали', () => {
  const { ctx, db, id, user } = fixture();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES ('t2', 'other', 'xray', 'vless', 8444, '[]', '[]')`).run();
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('s', 'seller', '["users.edit"]', '{"templates":["t"]}')`).run();
  saveUser(ctx, id, userBody.parse({ name: 'ann', excludedProfiles: ['d:t2:pl', 'd:t:fi'] }));
  saveUser(ctx, id, userBody.parse({ name: 'ann', excludedProfiles: ['v:t:auto'] }), roleOf(db, 's'));
  assert.deepEqual(JSON.parse(user().excluded_profiles!).sort(), ['d:t2:pl', 'v:t:auto']);
});

test('IP без права: адреса людей заменены, адреса серверов и время — нет', () => {
  const out = maskPersonIps({
    devices: [{ ip: '94.25.170.33', first_seen: '2026-10-13T10:00:00Z' }], allowedIps: [{ cidr: '198.51.100.0/24' }],
    servers: [{ host: '185.253.45.124', admin_ips: ['1.2.3.4'], seen_from_ip: '5.6.7.8' }],
    items: [{ action: 'admin.login', detail: '{"ip":"176.97.134.21","at":"23:59:59"}' }],
  }) as any;
  assert.equal(out.devices[0].ip, 'скрыт');
  assert.equal(out.devices[0].first_seen, '2026-10-13T10:00:00Z');
  assert.equal(out.allowedIps[0].cidr, 'скрыт');
  assert.equal(out.servers[0].host, '185.253.45.124', 'адрес сервера — в ссылках подписки, не маскируется');
  assert.deepEqual(out.servers[0].admin_ips, ['скрыт']);
  assert.equal(out.servers[0].seen_from_ip, 'скрыт');
  assert.equal(out.items[0].detail, '{"ip":"скрыт","at":"23:59:59"}');
});
