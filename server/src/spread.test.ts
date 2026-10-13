import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { kitVersion } from './nodekit.js';
import { Ops } from './ops.js';
import { probePort } from './protocols.js';
import { planSpread, spreadGroupOf, spreadHomes, type SpreadExit, type SpreadGroup } from './spread.js';

test('по нагрузке: группы делятся по ёмкости каналов, выходы чередуются; без ёмкостей — поровну', () => {
  const homes = spreadHomes(['es', 'fi', 'lv'], { es: 250, fi: 350, lv: 500 }, 6);
  const count = (x: string) => homes.filter((h) => h === x).length;
  assert.deepEqual([count('es'), count('fi'), count('lv')], [1, 2, 3]);
  assert.notEqual(homes[0], homes[1], 'группы одного выхода не подряд');
  assert.deepEqual(spreadHomes(['es', 'fi', 'lv'], {}, 6), ['es', 'fi', 'lv', 'es', 'fi', 'lv']);
  // у одного выхода ёмкость не задана — поровну
  assert.deepEqual(spreadHomes(['es', 'fi'], { es: 100 }, 4), ['es', 'fi', 'es', 'fi']);
  // каждому выходу хотя бы одна группа, даже с маленьким каналом
  assert.ok(spreadHomes(['a', 'b', 'c'], { a: 10, b: 1000, c: 1000 }, 3).includes('a'));
  assert.equal(spreadHomes(['a', 'b'], { a: 1, b: 1 }, 5).length, 5);
});

test('по нагрузке: группа пользователя стабильна и в пределах числа групп', () => {
  const g = spreadGroupOf('u-abc', 6);
  assert.equal(spreadGroupOf('u-abc', 6), g);
  for (const id of ['u-1', 'u-2', 'u-3', 'u-4']) assert.ok(spreadGroupOf(id, 6) >= 0 && spreadGroupOf(id, 6) < 6);
});

const ex = (id: string, cap: number, load: number, alive = true): SpreadExit => ({ id, cap, load, alive });
const gr = (g: number, home: string, cur: string, mbps: number): SpreadGroup => ({ g, home, cur, mbps });

test('по нагрузке: перегруженный выход отдаёт самую тяжёлую группу, которая помещается, туда, где больше запаса', () => {
  // es 250: загружен на 96%; fi 350 — запас 280·0.8−… ; lv 500 — запаса больше всех
  const exits = [ex('es', 250, 240), ex('fi', 350, 200), ex('lv', 500, 150)];
  const groups = [gr(0, 'es', 'es', 190), gr(1, 'es', 'es', 50), gr(2, 'fi', 'fi', 200), gr(3, 'lv', 'lv', 150)];
  // запас lv = 500·0.8 − 150 = 250 → группа 0 (190) помещается
  assert.deepEqual(planSpread(exits, groups, 0.8, true), { g: 0, from: 'es', to: 'lv', reason: 'overload' });
  // запаса не хватает тяжёлой — уходит следующая по тяжести
  const tight = [ex('es', 250, 240), ex('fi', 350, 260), ex('lv', 500, 330)];
  assert.deepEqual(planSpread(tight, groups, 0.8, true), { g: 1, from: 'es', to: 'lv', reason: 'overload' });
  // места нет нигде — никого не трогаем (дальше делит cake)
  assert.equal(planSpread([ex('es', 250, 240), ex('fi', 350, 300), ex('lv', 500, 420)], groups, 0.8, true), null);
  // пауза после прошлого перевода
  assert.equal(planSpread(exits, groups, 0.8, false), null);
  // мелкие группы не дёргаем: смена IP ничего не даст
  assert.equal(planSpread(exits, [gr(0, 'es', 'es', 0.5)], 0.8, true), null);
  // ёмкость не задана — выход не перегружен, а запас у него без ограничений
  assert.equal(planSpread([ex('es', 0, 900), ex('fi', 350, 10)], [gr(0, 'es', 'es', 900)], 0.8, true), null);
});

test('по нагрузке: возврат домой — с запасом (без качелей), и сразу, если выход, куда перевели, не отвечает', () => {
  // группа 0 (40 Мбит/с) переведена с es; дома 150 из 250: 150 + 40 = 190 ≤ 250·0.6 = 150? нет — остаётся
  assert.equal(planSpread([ex('es', 250, 150), ex('lv', 500, 200)], [gr(0, 'es', 'lv', 40)], 0.8, true), null);
  // дома стало 100: 140 ≤ 150 — домой
  assert.deepEqual(planSpread([ex('es', 250, 100), ex('lv', 500, 200)], [gr(0, 'es', 'lv', 40)], 0.8, true), { g: 0, from: 'lv', to: 'es', reason: 'home' });
  // lv не отвечает — домой без паузы
  assert.deepEqual(planSpread([ex('es', 250, 240), ex('lv', 500, 0, false)], [gr(0, 'es', 'lv', 40)], 0.8, false), { g: 0, from: 'lv', to: 'es', reason: 'dead' });
});

function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-spread-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 9)));
  for (const [id, role] of [['relay', 'entry'], ['es', 'exit'], ['fi', 'exit'], ['lv', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'trio', 'xray', 'vless', 8443, '[]', '["es","fi","lv"]', 'relay', 9443, ?)`)
    .run(JSON.stringify({ security: 'reality', autoMode: 'spread', exitOrder: ['es', 'fi', 'lv'], exitCapMbps: { es: 250, fi: 350, lv: 500 }, spreadGroups: 6 }));
  for (const s of ['es', 'fi', 'lv']) db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES (?, 't', ?, 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run(`ib-${s}`, s);
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active', 'P', 'a')`).run();
  for (let i = 0; i < 12; i++) db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES (?, ?, ?, ?)`).run(`u-${i}`, `user${i}`, `s${i}`, `k${i}`);
  return { db, ctx };
}

test('рендер входа «по нагрузке»: у каждой группы своя цепочка с домашнего выхода, свои outbound’ы и счётчики', async () => {
  const { ctx } = fixture();
  const { Vpn } = await import('./vpn.js');
  const x = new Vpn(ctx).renderXray(ctx.server('relay')) as any;
  const bal = (tag: string) => x.routing.balancers.find((b: any) => b.tag === tag);
  // домашние: lv, fi, es, lv, fi, lv (1/2/3 группы по ёмкости 250/350/500, чередуясь)
  const homes = spreadHomes(['es', 'fi', 'lv'], { es: 250, fi: 350, lv: 500 }, 6);
  for (let g = 0; g < 6; g++) {
    const chain = [homes[g]!, ...['es', 'fi', 'lv'].filter((e) => e !== homes[g])];
    assert.deepEqual(bal(`sg-t-${g}-0`).selector, [`sp-t-${g}-${chain[0]}`]);
    assert.equal(bal(`sg-t-${g}-0`).fallbackTag, `sgl-t-${g}-1`);
    assert.deepEqual([bal(`sg-t-${g}-2`).selector, bal(`sg-t-${g}-2`).fallbackTag], [[`sp-t-${g}-${chain[2]}`], `sp-t-${g}-${chain[0]}`], 'все лежат — через домашний');
  }
  // каждый пользователь «Авто» — ровно в одной группе
  const groupRules = x.routing.rules.filter((r: any) => r.inboundTag?.[0] === 'in-ib-r' && String(r.balancerTag ?? '').startsWith('sg-t-'));
  const emails = groupRules.flatMap((r: any) => r.user);
  assert.equal(emails.length, 12);
  assert.equal(new Set(emails).size, 12);
  for (const r of groupRules) for (const e of r.user) assert.equal(r.balancerTag, `sg-t-${spreadGroupOf(e.split('.')[0], 6)}-0`);
  assert.ok(!x.routing.rules.some((r: any) => r.balancerTag === 'bal-t'), 'общего балансировщика «Авто» нет');
  assert.equal(x.outbounds.filter((o: any) => String(o.tag).startsWith('sp-t-')).length, 18);
  assert.deepEqual(x.burstObservatory.subjectSelector, ['sp-t-']);
  assert.equal(x.policy.system.statsOutboundDownlink, true);
});

test('«по порядку» и прочие режимы: счётчики outbound’ов не включаются — их конфиги не меняются', async () => {
  const { ctx, db } = fixture();
  db.prepare(`UPDATE templates SET settings = '{"security":"reality","autoMode":"order","exitOrder":["es","fi","lv"]}' WHERE id = 't'`).run();
  const { Vpn } = await import('./vpn.js');
  const x = new Vpn(ctx).renderXray(ctx.server('relay')) as any;
  assert.deepEqual(x.policy.system, { statsInboundUplink: false });
  assert.ok(!x.outbounds.some((o: any) => String(o.tag).startsWith('sp-')));
});

test('проверка «по нагрузке»: нагрузка групп по счётчикам входа, каналы по серверам, перевод группы назначением балансировщику', async () => {
  const { ctx, db } = fixture();
  const homes = spreadHomes(['es', 'fi', 'lv'], { es: 250, fi: 350, lv: 500 }, 6);
  setSetting(db, 'spread.layout.t', { ids: ['es', 'fi', 'lv'], homes });
  setSetting(db, 'spread.statsAt.t', new Date(Date.now() - 60_000).toISOString());
  const esGroup = homes.indexOf('es');
  // группа es качает 200 Мбит/с, канал es — 240 из 250
  const bytes = (mbps: number) => Math.round((mbps * 1e6 * 60) / 8);
  const ostats = JSON.stringify({ stat: [
    { name: `outbound>>>sp-t-${esGroup}-es>>>traffic>>>downlink`, value: bytes(195) },
    { name: `outbound>>>sp-t-${esGroup}-es>>>traffic>>>uplink`, value: bytes(5) },
  ] });
  const links: Record<string, number> = { es: 240, fi: 100, lv: 100 };   // Мбит/с
  const rx: Record<string, number> = { es: 0, fi: 0, lv: 0 };
  const at: Record<string, number> = {};
  const bo: Array<[string, string]> = [];
  const node = (id: string) => ({
    op: async (a: (string | number)[]) => {
      const ok = (stdout: string) => ({ code: 0, stdout, stderr: '' });
      if (a[0] === 'version') return ok(kitVersion());
      if (a[0] === 'exit-probe') return ok('rtt_ms=40\n');
      if (a[0] === 'xray-ostats') return ok(ostats);
      if (a[0] === 'xray-bo') { bo.push([String(a[1]), String(a[2])]); return ok('ok'); }
      if (a[0] === 'xray-bi') { const last = bo.filter(([b]) => b === a[1]).pop(); return ok(`  - Selecting Override:\n    1   ${last && last[1] !== 'clear' ? last[1] : ''}\n  - Selects:\n`); }
      // счётчики интерфейса растут со скоростью канала по реальному времени между замерами
      if (a[0] === 'host-stat') {
        const now = Date.now();
        rx[id] = rx[id]! + (links[id]! * 1e6 * (now - (at[id] ?? now))) / 1000 / 8;
        at[id] = now;
        return ok(`@netdev\n  eth0: ${Math.round(rx[id]!)} 0 0 0 0 0 0 0 ${Math.round(rx[id]!)} 0 0 0 0 0 0 0\n`);
      }
      return ok('');
    },
    must: async () => 'ok',
  });
  (ctx as unknown as { onNode: unknown }).onNode = async (s: { id: string }, fn: (n: unknown) => Promise<unknown>) => fn(node(s.id));
  const ops = new Ops(ctx);
  const tpl = () => db.prepare(`SELECT * FROM templates WHERE id = 't'`).get() as never;
  // первая проверка: скорости каналов ещё не с чем сравнить — нагрузка es по счётчикам входа (200 из 250 — 80%, не выше)
  let r = await ops.checkExits(tpl(), () => undefined);
  assert.equal(r?.switched, null);
  // вторая минуту спустя: канал es 240 из 250 (96%) — группа es уходит на lv (запас 500·0.8 − 100 = 300)
  setSetting(db, 'spread.statsAt.t', new Date(Date.now() - 60_000).toISOString());
  await new Promise((res) => setTimeout(res, 300));   // каналы — по разнице с прошлым замером
  r = await ops.checkExits(tpl(), () => undefined);
  assert.equal(r?.switched?.spread?.reason, 'overload');
  assert.deepEqual([r?.switched?.from, r?.switched?.to], ['es', 'lv']);
  const chain = ['es', 'fi', 'lv'];
  assert.deepEqual(bo.at(-1), [`sg-t-${esGroup}-0`, `sgl-t-${esGroup}-${chain.indexOf('lv')}`]);
  assert.deepEqual(getSetting(db, 'spread.cur.t', {}), { [esGroup]: 'lv' });
  const st = getSetting<any>(db, 'spread.state.t', null);
  assert.equal(st.groups[esGroup].cur, 'lv');
  assert.ok(Math.abs(st.groups[esGroup].mbps - 200) <= 2, `нагрузка группы ≈ 200 Мбит/с (${st.groups[esGroup].mbps})`);
  assert.equal(st.exits.find((e: any) => e.id === 'es').measured, true);
  // сразу следующая — пауза, ничего не трогаем
  setSetting(db, 'spread.statsAt.t', new Date(Date.now() - 60_000).toISOString());
  r = await ops.checkExits(tpl(), () => undefined);
  assert.equal(r?.switched, null);
  void probePort;
});

test('ёмкость выхода: своё значение важнее замера на сервере; замер — меньшее из направлений шагом 10', async () => {
  const { parseLinkTest, measuredCap, spreadCaps } = await import('./spread.js');
  const l = parseLinkTest('dev=eth0\ndown_mbps=487\nup_mbps=512\n');
  assert.deepEqual([l?.down, l?.up], [487, 512]);
  assert.equal(measuredCap(l), 490);
  assert.equal(parseLinkTest('dev=eth0\ndown_mbps=0\nup_mbps=0\n'), null, 'Cloudflare недоступен — не замер');
  const { db } = fixture();
  setSetting(db, 'link.es', { down: 260, up: 244, at: '' });
  setSetting(db, 'link.lv', { down: 900, up: 950, at: '' });
  assert.deepEqual(spreadCaps(db, { lv: 500 }, ['es', 'fi', 'lv']), { es: 240, fi: 0, lv: 500 });
});

test('рендер «по нагрузке»: без своих значений группы делятся по замерам каналов', async () => {
  const { ctx, db } = fixture();
  db.prepare(`UPDATE templates SET settings = ? WHERE id = 't'`).run(JSON.stringify({ security: 'reality', autoMode: 'spread', exitOrder: ['es', 'fi', 'lv'], spreadGroups: 6 }));
  for (const [id, mbps] of [['es', 250], ['fi', 350], ['lv', 500]] as const) setSetting(db, `link.${id}`, { down: mbps, up: mbps, at: '' });
  const { Vpn } = await import('./vpn.js');
  const x = new Vpn(ctx).renderXray(ctx.server('relay')) as any;
  const homes = Array.from({ length: 6 }, (_, g) => x.routing.balancers.find((b: any) => b.tag === `sg-t-${g}-0`).selector[0].split('-').pop());
  assert.deepEqual(['es', 'fi', 'lv'].map((e) => homes.filter((h: string) => h === e).length), [1, 2, 3]);
});

test('новая конфигурация: случайные свободные порты — не SSH, не порты других конфигураций, в диапазоне группы', async () => {
  const { ctx, db } = fixture();
  db.prepare(`UPDATE servers SET ssh_ports = '[22]', group_name = 'g'`).run();
  db.prepare(`INSERT OR REPLACE INTO groups (name, port_range) VALUES ('g', '30000-30009')`).run();
  db.prepare(`UPDATE templates SET port = 30001, entry_port = 30002 WHERE id = 't'`).run();
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  const { templateRoutes } = await import('./routes/templates.js');
  await templateRoutes(app, ctx);
  const r = await app.inject({ method: 'GET', url: '/api/v1/free-ports?proto=tcp&count=2&servers=es,relay&avoid=30003' });
  const { ports } = r.json() as { ports: number[] };
  assert.equal(ports.length, 2);
  assert.notEqual(ports[0], ports[1]);
  for (const p of ports) assert.ok(p >= 30000 && p <= 30009 && ![30001, 30002, 30003].includes(p), `порт ${p}`);
  // в диапазоне не осталось места — понятная ошибка
  db.prepare(`UPDATE groups SET port_range = '30001' WHERE name = 'g'`).run();
  assert.equal((await app.inject({ method: 'GET', url: '/api/v1/free-ports?servers=es' })).statusCode, 409);
});
