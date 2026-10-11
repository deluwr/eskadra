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
      if (a[0] === 'exit-probe') { const x = Object.keys(alive).find((k) => probePort('t', k) === a[1])!; return ok(alive[x] ? `rtt_ms=180\n${Number(a[2]) > 0 ? 'mbps=50\n' : ''}` : 'rtt_ms=fail\nmbps=fail\n'); }
      if (a[0] === 'xray-bo') { xray.override = a[2] === 'clear' ? null : String(a[2]); return ok('ok'); }
      if (a[0] === 'xray-bi') { const sel = xray.override ?? (alive.pl ? 'to-t-pl' : 'to-t-fi'); return ok(`  - Selecting Override:\n    1   ${xray.override ?? ''}\n  - Selects:\n    1   ${sel}\n`); }
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

test('рендер входа «по порядку»: веса по порядку выходов и частое наблюдение', async () => {
  const f = fixture();
  f.db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state, public_key, short_id) VALUES ('ib-r', 't', 'relay', 'relay', 9443, 'tcp', 'active', 'P', 'a')`).run();
  const { Vpn } = await import('./vpn.js');
  const x = new Vpn(f.ctx).renderXray(f.ctx.server('relay')) as any;
  const bal = x.routing.balancers.find((b: any) => b.tag === 'bal-t');
  assert.deepEqual(bal.strategy.settings.costs.map((c: any) => [c.match, c.value]), [['to-t-pl', 1], ['to-t-fi', 100]]);
  assert.equal(x.burstObservatory.pingConfig.interval, '5s');
});
