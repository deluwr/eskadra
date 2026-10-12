import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { kitVersion } from './nodekit.js';
import { Ops, parseBalancerInfo } from './ops.js';
import { probePort } from './protocols.js';

test('вывод xray api bi: назначенный и реально выбранный выход', () => {
  const out = '  - Selecting Override:\n    1   to-t-b        \n  - Selects:\n    1   to-t-b        \n';
  assert.deepEqual(parseBalancerInfo(out), { override: 'to-t-b', selected: 'to-t-b' });
  assert.deepEqual(parseBalancerInfo('  - Selecting Override:\n    1                 \n  - Selects:\n    1   to-t-a\n'), { override: null, selected: 'to-t-a' });
});

/** Вход с балансировщиком: выходы «живы» или нет; xray-bo/xray-bi меняют и показывают выбор, как настоящий Xray. */
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-auto-'));
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 3)));
  for (const [id, role] of [['relay', 'entry'], ['pl', 'exit'], ['fi', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'duo', 'xray', 'vless', 8443, '[]', '["pl","fi"]', 'relay', 9443, '{"security":"reality","autoMode":"order","exitOrder":["pl","fi"]}')`).run();
  for (const s of ['pl', 'fi']) db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES (?, 't', ?, 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run(`ib-${s}`, s);
  const alive: Record<string, boolean> = { pl: true, fi: true };
  const xray = { override: null as string | null };
  const ok = (stdout: string) => ({ code: 0, stdout, stderr: '' });
  const n = {
    op: async (a: (string | number)[]) => {
      if (a[0] === 'version') return ok(kitVersion());
      if (a[0] === 'exit-probe') { const x = Object.keys(alive).find((k) => probePort('t', k) === a[1])!; return ok(alive[x] ? `rtt_ms=180\nexit_ip=198.51.100.${x === 'pl' ? 7 : 8}\nexit_loc=${x.toUpperCase()}\n${Number(a[2]) > 0 ? 'mbps=50\n' : ''}` : 'rtt_ms=fail\nmbps=fail\n'); }
      if (a[0] === 'xray-bo') { xray.override = a[2] === 'clear' ? null : String(a[2]); return ok('ok'); }
      // как настоящий Xray «по порядку»: балансировщик видит только первый выход; не отвечает — «Selects» пуст (трафик в fallback)
      // цепочка «по порядку»: bal-t видит первый выход по порядку, bal-t-2 — второй, …; жив — выбран, нет — «Selects» пуст
      if (a[0] === 'xray-bi') {
        const order = (JSON.parse((db.prepare(`SELECT settings FROM templates WHERE id = 't'`).get() as { settings: string }).settings).exitOrder ?? ['pl', 'fi']) as string[];
        const lvl = a[1] === 'bal-t' ? 0 : Number(String(a[1]).split('-')[2]) - 1;
        const x = order[lvl];
        const sel = (lvl === 0 ? xray.override : null) ?? (x && alive[x] ? `to-t-${x}` : '');
        return ok(`  - Selecting Override:\n    1   ${lvl === 0 ? xray.override ?? '' : ''}\n  - Selects:\n${sel ? `    1   ${sel}\n` : ''}`);
      }
      return ok('');
    },
    must: async () => 'ok',
  };
  (ctx as unknown as { onNode: unknown }).onNode = async (_r: unknown, fn: (s: unknown) => Promise<unknown>) => fn(n);
  return { ctx, db, alive, xray, ops: new Ops(ctx), tpl: () => db.prepare(`SELECT * FROM templates WHERE id = 't'`).get() as never };
}

test('«Авто» по порядку: порядок держит сам вход, панель не закрепляет выход и видит реальный', async () => {
  const f = fixture();
  f.xray.override = 'to-t-fi';   // закрепление от старой версии — снимается
  let r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.xray.override, null);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-pl');

  f.alive.pl = false;   // остановили ядро на pl — вход сам ушёл на fi
  r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-fi');
  assert.deepEqual(r?.switched, { from: 'pl', to: 'fi' });
  assert.equal(r?.results.find((x) => x.exitId === 'pl')?.ok, false, 'неактивный выход не «отвечает»');

  f.alive.pl = true;    // запустили снова — вход вернулся сам
  r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-pl');
  assert.deepEqual(r?.switched, { from: 'fi', to: 'pl' });
});

test('«Авто» по качеству: выбор назначается входу и восстанавливается, если вход его «забыл»', async () => {
  const f = fixture();
  f.db.prepare(`UPDATE templates SET settings = '{"security":"reality","autoMode":"smart","maxRttMs":500,"minMbps":0.5}' WHERE id = 't'`).run();
  await f.ops.checkExits(f.tpl(), () => undefined);
  assert.ok(f.xray.override, 'выход назначен');
  const chosen = f.xray.override;
  f.xray.override = null;   // вход перезапустился
  await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.xray.override, chosen);
});

test('рендер входа «по порядку»: цепочка уровней через loopback — каждый видит свой выход, последний — к первому', async () => {
  const f = fixture();
  f.db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES ('es', 'es', '203.0.113.1', 'exit', 'k', 'x', 'restricted')`).run();
  f.db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-es', 't', 'es', 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run();
  f.db.prepare(`UPDATE templates SET settings = '{"security":"reality","autoMode":"order","exitOrder":["pl","fi","es"]}' WHERE id = 't'`).run();
  f.db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active', 'P', 'a')`).run();
  const { Vpn } = await import('./vpn.js');
  const x = new Vpn(f.ctx).renderXray(f.ctx.server('relay')) as any;
  const bal = (tag: string) => x.routing.balancers.find((b: any) => b.tag === tag);
  assert.deepEqual([bal('bal-t').selector, bal('bal-t').fallbackTag], [['to-t-pl'], 'lb-t-2']);
  assert.deepEqual([bal('bal-t-2').selector, bal('bal-t-2').fallbackTag], [['to-t-fi'], 'lb-t-3']);
  assert.deepEqual([bal('bal-t-3').selector, bal('bal-t-3').fallbackTag], [['to-t-es'], 'to-t-pl'], 'все лежат — через первый');
  assert.deepEqual(x.outbounds.filter((o: any) => o.protocol === 'loopback').map((o: any) => [o.tag, o.settings.inboundTag]), [['lb-t-2', 'lvl-t-2'], ['lb-t-3', 'lvl-t-3']]);
  const rule = (inb: string) => x.routing.rules.find((r: any) => r.inboundTag?.[0] === inb);
  assert.equal(rule('lvl-t-2').balancerTag, 'bal-t-2');
  assert.equal(rule('lvl-t-3').balancerTag, 'bal-t-3');
  assert.equal(bal('bal-t').strategy.settings.costs, undefined, 'веса leastLoad множат разброс задержки — порядок по ним скачет');
  assert.equal(x.burstObservatory.pingConfig.interval, '5s');
});

test('«Авто» по порядку: не отвечают первые два — вход сам ведёт через третий, панель ничего не закрепляет и видит его', async () => {
  const f = fixture();
  f.db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES ('es', 'es', '203.0.113.1', 'exit', 'k', 'x', 'restricted')`).run();
  f.db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-es', 't', 'es', 'direct', 8443, 'tcp', 'active', 'P', 'a')`).run();
  f.db.prepare(`UPDATE templates SET settings = '{"security":"reality","autoMode":"order","exitOrder":["pl","fi","es"]}' WHERE id = 't'`).run();
  f.alive.es = true;
  f.alive.pl = false; f.alive.fi = false;
  let r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.xray.override, null, 'цепочка переключает сама');
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-es');
  f.alive.pl = true;
  r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.xray.override, null);
  assert.deepEqual(r?.switched, { from: 'es', to: 'pl' });
  f.alive.pl = false; f.alive.es = false;   // не отвечает никто — через первый
  await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-pl');
});

test('проверка выходов: адрес и страна выхода в интернет сохраняются и не стираются, когда выход не ответил', async () => {
  const f = fixture();
  let r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.deepEqual(r?.results.map((x) => [x.exitId, x.exitIp, x.exitLoc]), [['pl', '198.51.100.7', 'PL'], ['fi', '198.51.100.8', 'FI']]);
  f.alive.fi = false;
  r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(r?.results.find((x) => x.exitId === 'fi')?.exitIp, null);
  const row = f.db.prepare(`SELECT exit_ip, exit_loc FROM exit_health WHERE template_id = 't' AND exit_id = 'fi'`).get() as { exit_ip: string; exit_loc: string };
  assert.deepEqual({ ...row }, { exit_ip: '198.51.100.8', exit_loc: 'FI' });
});
