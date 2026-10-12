import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { kitVersion } from './nodekit.js';
import { Ops, renderHash } from './ops.js';
import { Vpn } from './vpn.js';
import { decide, DEVICE_HOLD_MS, updateDevices, userOfEmail } from './devices.js';

/** Вход relay и выход fi; пользователи ann (лимит 1) и bob (без лимита) на одной конфигурации. */
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-dev-'));
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 5)));
  for (const [id, role] of [['relay', 'entry'], ['fi', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp, cores) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted', 'fp', '{"xray":{"version":"26.3.27"}}')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'duo', 'xray', 'vless', 8443, '[]', '["fi"]', 'relay', 9443, '{"security":"reality","autoMode":"order","exitOrder":["fi"]}')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-fi', 't', 'fi', 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active', 'P', 'a')`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, device_limit) VALUES ('u-a1', 'ann', 's1', 'k1', 1)`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token, device_limit, limit_group) VALUES ('u-b2', 'bob', 's2', 'k2', NULL, 'nolimit')`).run();
  db.prepare(`INSERT INTO limit_groups (name, devices) VALUES ('nolimit', NULL)`).run();
  // что каждый узел отдаёт как «онлайн»; какие правила на него пришли
  const online: Record<string, Record<string, string[]>> = { relay: {}, fi: {} };
  const pushed: Array<{ node: string; gen: string; rules: Array<Record<string, unknown>> }> = [];
  let current = 'relay';
  const n = {
    op: async (a: (string | number)[], o: { stdin?: string } = {}) => {
      if (a[0] === 'version') return { code: 0, stdout: kitVersion(), stderr: '' };
      if (a[0] === 'xray-online') return { code: 0, stdout: JSON.stringify(online[current]), stderr: '' };
      if (a[0] === 'xray-rules') { pushed.push({ node: current, ...JSON.parse(o.stdin!) }); return { code: 0, stdout: 'ok', stderr: '' }; }
      return { code: 0, stdout: '', stderr: '' };
    },
  };
  (ctx as unknown as { onNode: unknown }).onNode = async (r: { id: string }, fn: (s: unknown) => Promise<unknown>) => { current = r.id; return fn(n); };
  return { ctx, db, online, pushed, ops: new Ops(ctx) };
}

test('лимит устройств: первые N по времени появления, остальные — сверх лимита; без лимита — никого', () => {
  const rows = [{ ip: 'c', first_seen: '2026-01-01T00:00:03Z' }, { ip: 'a', first_seen: '2026-01-01T00:00:01Z' }, { ip: 'b', first_seen: '2026-01-01T00:00:02Z' }];
  assert.deepEqual([...decide(rows, 2)], ['c']);
  assert.deepEqual([...decide(rows, null)], []);
  assert.deepEqual([...decide(rows, 0)], [], '0 — без лимита, а не «ни одного устройства»');
  assert.equal(userOfEmail('u-a1.v-fi'), 'u-a1');
  assert.equal(userOfEmail('svc.relay-relay-t'), null);
});

test('лимит устройств: блокировка касается только своего пользователя, общий IP другого не трогает; ушедшее устройство освобождает место', () => {
  const { ctx, db } = fixture();
  const t0 = new Date('2026-10-12T10:00:00Z');
  // ann: телефон, затем ноутбук; bob — с того же адреса, что и ноутбук ann (общий NAT)
  updateDevices(ctx, new Map([['u-a1', new Set(['198.51.100.1'])]]), t0);
  const r = updateDevices(ctx, new Map([['u-a1', new Set(['198.51.100.1', '198.51.100.2'])], ['u-b2', new Set(['198.51.100.2'])]]), new Date(t0.getTime() + 30_000));
  assert.deepEqual([...r.blocked], [['u-a1', ['198.51.100.2']]]);
  assert.deepEqual(r.newlyLimited, ['u-a1']);
  const bob = db.prepare(`SELECT blocked FROM user_devices WHERE user_id = 'u-b2'`).get() as { blocked: number };
  assert.equal(bob.blocked, 0, 'bob с того же IP не заблокирован');
  // телефон ann отключился: пока не прошло HOLD — место за ним
  const t2 = new Date(t0.getTime() + 60_000);
  assert.deepEqual([...updateDevices(ctx, new Map([['u-a1', new Set(['198.51.100.2'])]]), t2).blocked], [['u-a1', ['198.51.100.2']]]);
  // после HOLD — ноутбук пропускается
  const t3 = new Date(t0.getTime() + DEVICE_HOLD_MS + 61_000);
  const r3 = updateDevices(ctx, new Map([['u-a1', new Set(['198.51.100.2'])]]), t3);
  assert.equal(r3.blocked.size, 0);
  assert.equal((db.prepare(`SELECT COUNT(*) AS c FROM user_devices WHERE user_id = 'u-a1'`).get() as { c: number }).c, 1);
});

test('конфиг Xray: учёт онлайн-IP, правило лимита сразу после служебных и раньше маршрутов входа; отпечаток не зависит от блокировок', () => {
  const { ctx } = fixture();
  const vpn = new Vpn(ctx);
  const hash = renderHash(vpn, ctx.server('relay'));
  updateDevices(ctx, new Map([['u-a1', new Set(['198.51.100.1', '198.51.100.2'])]]), new Date());
  const cfg = vpn.renderXray(ctx.server('relay')) as any;
  assert.equal(cfg.policy.levels['0'].statsUserOnline, true);
  const rules = cfg.routing.rules as any[];
  assert.deepEqual(rules.slice(0, 3).map((r) => r.ruleTag), [undefined, undefined, undefined], 'служебные правила без тега — их замена на ходу не трогает');
  assert.deepEqual(rules[3], { type: 'field', user: ['regexp:^u-a1\\.'], source: ['198.51.100.2'], outboundTag: 'block', ruleTag: 'r0-0' });
  const route = rules.findIndex((r) => r.balancerTag || String(r.outboundTag).startsWith('to-'));
  assert.ok(route > 3, 'маршруты входа — после правила лимита');
  assert.ok(rules.slice(3).every((r) => /^r0-\d+$/.test(r.ruleTag)));
  assert.equal(renderHash(vpn, ctx.server('relay')), hash, 'блокировки устройств не вызывают перезапуск Xray');
  const tail = vpn.routingTail(ctx.server('relay'), 'rk1')!;
  assert.equal(tail.length, rules.length - 3);
  assert.ok(tail.every((r: any, i) => r.ruleTag === `rk1-${i}`));
});

test('цикл лимита: онлайн со всех узлов по пользователю, правила только туда, где изменились; svc не считается', async () => {
  const f = fixture();
  f.online.relay = { 'u-a1.v-fi': ['198.51.100.1'], 'svc.mgmt': ['198.51.100.9'] };
  f.online.fi = { 'u-a1.d-t': ['198.51.100.3'], 'svc.relay-relay-t': ['203.0.113.1'] };
  let r = await f.ops.syncDevices();
  assert.deepEqual([...r.blocked], [['u-a1', ['198.51.100.3']]]);
  assert.deepEqual(f.pushed.map((p) => p.node).sort(), ['fi', 'relay']);
  const p = f.pushed[0]!;
  assert.match(p.gen, /^r[0-9a-z]+$/);
  assert.equal(p.rules[0]!.ruleTag, `${p.gen}-0`);
  assert.deepEqual(p.rules[0]!.source, ['198.51.100.3']);
  f.pushed.length = 0;
  r = await f.ops.syncDevices();
  assert.equal(f.pushed.length, 0, 'ничего не изменилось — узлы не трогаем');
  // одно и то же устройство через вход и напрямую — одно устройство
  f.db.prepare('DELETE FROM user_devices').run();
  f.online.fi = { 'u-a1.d-t': ['198.51.100.1'] };
  r = await f.ops.syncDevices();
  assert.equal(r.blocked.size, 0);
});

test('цикл лимита: ни один узел не ответил — устройства не «уходят» и блокировки не снимаются', async () => {
  const f = fixture();
  f.online.relay = { 'u-a1.v-fi': ['198.51.100.1', '198.51.100.2'] };
  await f.ops.syncDevices();
  (f.ctx as unknown as { onNode: unknown }).onNode = async () => { throw new Error('offline'); };
  const r = await f.ops.syncDevices();
  assert.deepEqual([...r.blocked], [['u-a1', ['198.51.100.2']]]);
});
