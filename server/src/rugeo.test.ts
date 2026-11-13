import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { config } from './config.js';
import { geoEntries, pickGeo } from './geodat.js';
import { buildRuGeo, refreshRuGeo, RU_GEO_SOURCE, RU_GEOIP_SOURCE, ruGeoOf, ruGeoOnNode, ruGeoPending, syncRuGeo } from './rugeo.js';

// ── синтетические базы в формате Xray
// GeoSiteList { entry = 1 { code = 1, domain = 2 { type = 1, value = 2 } } }
const ld = (no: number, body: Buffer) => { const len: number[] = []; let n = body.length; while (n >= 0x80) { len.push((n & 0x7f) | 0x80); n >>= 7; } len.push(n); return Buffer.concat([Buffer.from([(no << 3) | 2, ...len]), body]); };
const domain = (v: string) => ld(2, Buffer.concat([Buffer.from([0x08, 0x02]), ld(2, Buffer.from(v))]));
const site = (code: string, ...ds: string[]) => ld(1, Buffer.concat([ld(1, Buffer.from(code)), ...ds.map(domain)]));
const SRC = Buffer.concat([
  site('GOOGLE', 'google.com'),
  site('RU-AVAILABLE-ONLY-INSIDE', 'gosuslugi.ru', 'nalog.gov.ru'),
  site('RU-BLOCKED-ALL', ...Array.from({ length: 300 }, (_, i) => `b${i}.example`)),
  site('CATEGORY-RU', 'ozon.ru', 'yandex.com', 'vk.com'),
]);
// GeoIPList { entry = 1 { code = 1, cidr = 2 { ip = 1, prefix = 2 } } }
const cidr = (a: number[], p: number) => ld(2, Buffer.concat([ld(1, Buffer.from(a)), Buffer.from([0x10, p])]));
const ipset = (code: string, n: number) => ld(1, Buffer.concat([ld(1, Buffer.from(code)), ...Array.from({ length: n }, (_, i) => cidr([5, i, 0, 0], 16))]));
const IPSRC = Buffer.concat([ipset('DE', 50), ipset('RU', 4), ipset('YANDEX', 2), ipset('RU-WHITELIST', 30)]);
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const CORE_D = ['geosite:category-ru', 'domain:ru', 'domain:su', 'domain:xn--p1ai'];

test('geodat: нужные категории копируются байт в байт, чужие и огромные — нет', () => {
  assert.deepEqual(geoEntries(SRC).map((e) => `${e.code}:${e.items}`), ['GOOGLE:1', 'RU-AVAILABLE-ONLY-INSIDE:2', 'RU-BLOCKED-ALL:300', 'CATEGORY-RU:3']);
  const { dat, counts } = pickGeo(SRC, ['ru-available-only-inside', 'category-ru']);
  assert.deepEqual(counts, { 'ru-available-only-inside': 2, 'category-ru': 3 });
  assert.deepEqual(geoEntries(dat).map((e) => e.code), ['RU-AVAILABLE-ONLY-INSIDE', 'CATEGORY-RU']);
  assert.ok(dat.length < SRC.length / 5);
  assert.ok(SRC.includes(geoEntries(dat)[1]!.raw), 'запись не пересобрана');
  assert.deepEqual(geoEntries(pickGeo(IPSRC, ['ru', 'yandex']).dat).map((e) => `${e.code}:${e.items}`), ['RU:4', 'YANDEX:2']);
  assert.throws(() => pickGeo(SRC, ['category-ru', 'нет-такой']), /нет категорий: нет-такой/);
  assert.throws(() => geoEntries(SRC.subarray(0, SRC.length - 3)), /geodat/);
});

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-rugeo-'));
  (config as { dataDir: string }).dataDir = dir;
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 6)));
  for (const [id, role] of [['relay', 'entry'], ['pl', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'duo', 'xray', 'vless', 8443, '[]', '["pl"]', 'relay', 9443, '{"security":"reality"}')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-pl', 't', 'pl', 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run();
  db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active', 'P', 'a')`).run();
  setSetting(db, 'ruDirect', { entries: ['relay'] });
  const hits: string[] = [];
  let src: Buffer = SRC, published = sha(SRC);
  const fetch = (async (url: string) => {
    hits.push(url);
    if (url === `${RU_GEO_SOURCE}.sha256sum`) return new Response(`${published}  geosite.dat\n`);
    if (url === RU_GEO_SOURCE) return new Response(new Uint8Array(src));
    if (url === `${RU_GEOIP_SOURCE}.sha256sum`) return new Response(`${sha(IPSRC)}  geoip.dat\n`);
    if (url === RU_GEOIP_SOURCE) return new Response(new Uint8Array(IPSRC));
    return new Response('', { status: 404 });
  }) as unknown as typeof globalThis.fetch;
  const vpn = new Vpn(ctx);
  const rules = () => ((vpn.renderXray(ctx.server('relay')!) as any).routing.rules as any[]);
  return {
    dir, db, ctx, vpn, hits, fetch, set: (b: Buffer, pub = sha(b)) => { src = b; published = pub; },
    domains: () => rules().find((r) => r.domain?.includes('domain:ru')).domain as string[],
    ips: () => rules().find((r) => r.ip?.includes('geoip:ru')).ip as string[],
  };
}

/** Узел: что лежит в каталоге баз, и что он отвечает на geo-put. */
function node(files: string[] = [], putFail: string | null = null) {
  const calls: string[][] = [];
  return {
    calls, files,
    op: async (a: (string | number)[], o?: { stdin?: string }) => {
      calls.push(a.map(String));
      if (a[0] === 'geo-list') return { code: 0, stdout: files.join('\n') + '\n', stderr: '' };
      if (a[0] === 'geo-put') {
        if (putFail) return { code: 1, stdout: '', stderr: putFail };
        assert.equal(sha(Buffer.from(o!.stdin!, 'base64')), a[2]);
        files.push(String(a[1]));
        return { code: 0, stdout: 'ok', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    },
  };
}

test('списки runetfreedom: скачать обе базы, сверить SHA-256, вырезать; те же базы — без повторного скачивания', async () => {
  const f = fixture();
  const r = await refreshRuGeo(f.ctx, { fetch: f.fetch });
  assert.equal(r.changed, true);
  const g = ruGeoOf(f.ctx)!;
  assert.equal(g.file, buildRuGeo(SRC, IPSRC).file);
  assert.match(g.file, /^eskadra-ru-[0-9a-f]{12}\.dat$/);
  assert.equal(g.ipFile, g.file.replace('eskadra-ru-', 'eskadra-ruip-'));
  assert.deepEqual(g.counts, { 'ru-available-only-inside': 2, 'category-ru': 3, 'ip:ru': 4, 'ip:yandex': 2 });
  assert.deepEqual(geoEntries(fs.readFileSync(path.join(f.dir, 'rugeo', g.ipFile))).map((e) => e.code), ['RU', 'YANDEX']);
  assert.ok(fs.existsSync(path.join(f.dir, 'rugeo', g.file)));
  assert.equal((f.ctx.server('relay') as any).config_dirty, 1, 'вход с настройкой — к переприменению');
  assert.equal((f.ctx.server('pl') as any).config_dirty, 0);
  // неделя не прошла — сеть не трогаем; принудительно и базы те же — только контрольные суммы
  f.hits.length = 0;
  await refreshRuGeo(f.ctx, { fetch: f.fetch });
  assert.deepEqual(f.hits, []);
  assert.equal((await refreshRuGeo(f.ctx, { force: true, fetch: f.fetch })).changed, false);
  assert.deepEqual(f.hits, [`${RU_GEO_SOURCE}.sha256sum`, `${RU_GEOIP_SOURCE}.sha256sum`]);
});

test('списки runetfreedom: подменённая база или нет категории — прежний набор остаётся', async () => {
  const f = fixture();
  await refreshRuGeo(f.ctx, { fetch: f.fetch });
  const before = ruGeoOf(f.ctx)!;
  f.set(Buffer.concat([SRC, site('X', 'x.com')]), 'a'.repeat(64));
  await assert.rejects(refreshRuGeo(f.ctx, { force: true, fetch: f.fetch }), /SHA-256 geosite\.dat не совпал/);
  f.set(site('GOOGLE', 'google.com'));
  await assert.rejects(refreshRuGeo(f.ctx, { force: true, fetch: f.fetch }), /нет категорий/);
  assert.deepEqual(ruGeoOf(f.ctx), before);
  assert.ok(fs.existsSync(path.join(f.dir, 'rugeo', before.file)) && fs.existsSync(path.join(f.dir, 'rugeo', before.ipFile)));
  assert.match(getSetting<{ error: string }>(f.db, 'ruGeo.check', { error: '' }).error, /нет категорий/);
});

test('вход: правила по базам ядра всегда; набор runetfreedom на узле — добавляется к ним; потерян — снова только ядро', async () => {
  const f = fixture();
  assert.deepEqual(f.domains(), CORE_D);
  assert.deepEqual(f.ips(), ['geoip:ru']);
  await refreshRuGeo(f.ctx, { fetch: f.fetch });
  const { file, ipFile } = ruGeoOf(f.ctx)!;
  assert.deepEqual(f.domains(), CORE_D, 'набор у панели есть, но на узел ещё не доставлен');
  assert.equal(ruGeoPending(f.ctx, f.ctx.server('relay')!), true);
  assert.equal(ruGeoPending(f.ctx, f.ctx.server('pl')!), false, 'настройка на выходе не включена');

  const n = node();
  await syncRuGeo(f.ctx, f.ctx.server('relay')!, n, () => undefined);
  assert.deepEqual(n.calls.filter((c) => c[0] === 'geo-put').map((c) => c[1]), [ipFile, file], 'сначала адреса, потом сайты');
  assert.equal(ruGeoOnNode(f.ctx, 'relay'), file);
  assert.deepEqual(f.domains(), [...CORE_D, `ext:${file}:ru-available-only-inside`, `ext:${file}:category-ru`]);
  assert.deepEqual(f.ips(), ['geoip:ru', `ext:${ipFile}:ru`, `ext:${ipFile}:yandex`]);
  assert.equal(ruGeoPending(f.ctx, f.ctx.server('relay')!), false);
  assert.ok(!JSON.stringify(f.vpn.renderXray(f.ctx.server('pl')!)).includes('ext:'), 'выход не затронут');

  // на узле только один файл набора (сайты без адресов) — набор не считается доставленным
  await syncRuGeo(f.ctx, f.ctx.server('relay')!, node([file], 'disk full'), () => undefined);
  assert.equal(ruGeoOnNode(f.ctx, 'relay'), null);
  assert.deepEqual(f.ips(), ['geoip:ru']);
});

test('сервер переставили, доставка не удалась — только базы ядра, и узел не дёргают ближайшие часы', async () => {
  const f = fixture();
  await refreshRuGeo(f.ctx, { fetch: f.fetch });
  await syncRuGeo(f.ctx, f.ctx.server('relay')!, node(), () => undefined);
  const log: string[] = [];
  await syncRuGeo(f.ctx, f.ctx.server('relay')!, node([], 'disk full'), (l) => log.push(l));
  assert.equal(ruGeoOnNode(f.ctx, 'relay'), null);
  assert.deepEqual(f.domains(), CORE_D);
  assert.deepEqual(f.ips(), ['geoip:ru']);
  assert.match(log.join('\n'), /не доставлены — disk full; правила — по базам ядра/);
  assert.equal(ruGeoPending(f.ctx, f.ctx.server('relay')!), false);
});

test('выключено — узел даже не спрашивают', async () => {
  const f = fixture();
  setSetting(f.db, 'ruDirect', { entries: [] });
  await refreshRuGeo(f.ctx, { force: true, fetch: f.fetch });
  const n = node();
  await syncRuGeo(f.ctx, f.ctx.server('relay')!, n, () => undefined);
  assert.deepEqual(n.calls, []);
  assert.equal((f.ctx.server('relay') as any).config_dirty, 0);
});
