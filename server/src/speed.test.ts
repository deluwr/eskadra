import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { kitVersion } from './nodekit.js';
import { Ops, skipLevels, slowExits } from './ops.js';
import { probePort } from './protocols.js';
import { updateDevices } from './devices.js';

test('порог скорости «по порядку»: ниже порога — медленный, обратно — от порога +10%; не мерили — как было', () => {
  const r = (exitId: string, mbps: number | null, ok = true) => ({ exitId, ok, mbps });
  assert.deepEqual(slowExits([r('es', 30), r('pl', 80)], [], 50, true), ['es']);
  assert.deepEqual(slowExits([r('es', 52), r('pl', 80)], ['es'], 50, true), ['es'], '52 < 55 — ещё медленный');
  assert.deepEqual(slowExits([r('es', 56), r('pl', 80)], ['es'], 50, true), []);
  assert.deepEqual(slowExits([r('es', null), r('pl', 80)], [], 50, true), ['es'], 'отвечает, но не скачал — медленный');
  assert.deepEqual(slowExits([r('es', 10)], ['es'], 50, false), ['es'], 'между замерами — прежнее решение');
  assert.deepEqual(slowExits([r('es', 10)], ['es'], 0, true), [], 'порог 0 — не мерить');
  // пропускаем медленный, если дальше есть отвечающий быстрый
  const ok = (exitId: string, alive = true) => ({ exitId, ok: alive });
  assert.deepEqual(skipLevels([ok('es'), ok('pl'), ok('fi')], ['es']), [true, false, false]);
  assert.deepEqual(skipLevels([ok('es'), ok('pl'), ok('fi')], ['es', 'pl']), [true, true, false], 'медленный и следующий — сразу на третий');
  assert.deepEqual(skipLevels([ok('es'), ok('pl'), ok('fi')], ['es', 'pl', 'fi']), [false, false, false], 'медленные все — обычный порядок');
  assert.deepEqual(skipLevels([ok('es'), ok('pl', false)], ['es']), [false, false], 'следующий лежит — медленный лучше никакого');
});

/** Вход и три выхода «по порядку» (es → pl → fi) с порогом 50 Мбит/с; скорость и доступность выходов задаёт тест. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-spd-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 6)));
  for (const [id, role] of [['relay', 'entry'], ['es', 'exit'], ['pl', 'exit'], ['fi', 'exit']] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted')`).run(id, id, role);
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'trio', 'xray', 'vless', 8443, '[]', '["es","pl","fi"]', 'relay', 9443, '{"security":"none","autoMode":"order","exitOrder":["es","pl","fi"],"orderMinMbps":50,"checkMin":15,"testMB":5}')`).run();
  for (const s of ['es', 'pl', 'fi']) db.prepare(`INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, state) VALUES (?, 't', ?, 'direct', 8443, 'tcp', 'active')`).run(`ib-${s}`, s);
  const speed: Record<string, number> = { es: 30, pl: 80, fi: 90 };
  const alive: Record<string, boolean> = { es: true, pl: true, fi: true };
  const bo: Record<string, string | null> = {};
  const probes: Array<[string, number]> = [];
  const ok = (stdout: string) => ({ code: 0, stdout, stderr: '' });
  const n = {
    op: async (a: (string | number)[]) => {
      if (a[0] === 'version') return ok(kitVersion());
      if (a[0] === 'exit-probe') {
        const x = Object.keys(alive).find((k) => probePort('t', k) === a[1])!;
        probes.push([x, Number(a[2])]);
        return ok(alive[x] ? `rtt_ms=100\n${Number(a[2]) > 0 ? `mbps=${speed[x]}\n` : ''}` : 'rtt_ms=fail\n');
      }
      if (a[0] === 'xray-bo') { bo[String(a[1])] = a[2] === 'clear' ? null : String(a[2]); return ok('ok'); }
      if (a[0] === 'xray-bi') {
        const lvl = a[1] === 'bal-t' ? 0 : Number(String(a[1]).split('-')[2]) - 1;
        const x = ['es', 'pl', 'fi'][lvl]!;
        const ov = bo[String(a[1])] ?? '';
        return ok(`  - Selecting Override:\n    1   ${ov}\n  - Selects:\n${alive[x] ? `    1   to-t-${x}\n` : ''}`);
      }
      return ok('');
    },
  };
  (ctx as unknown as { onNode: unknown }).onNode = async (_r: unknown, fn: (s: unknown) => Promise<unknown>) => fn(n);
  return { ctx, db, speed, alive, bo, probes, ops: new Ops(ctx), tpl: () => db.prepare(`SELECT * FROM templates WHERE id = 't'`).get() as never };
}

test('«по порядку» с порогом: замер каждую минуту, решение раз в 15 минут по медиане — одна плохая минута не перекидывает', async () => {
  const f = fixture();
  // время идёт: сдвигаем отметки «когда мерили» и «когда решали» в прошлое
  const ago = (key: string, min: number) => setSetting(f.db, key, new Date(Date.now() - min * 60_000).toISOString());
  const minute = () => ago('auto.speedAt.t', 1.1);
  const samples = (exit: string) => (f.db.prepare(`SELECT COUNT(*) AS n FROM exit_speed WHERE exit_id = ?`).get(exit) as { n: number }).n;
  // первая проверка — замер и решение: es 30 < 50 — пропускаем, трафик через pl
  f.speed.es = 30;
  let r = await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.bo['bal-t'], 'lb-t-2');
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-pl');
  assert.deepEqual(r?.switched, { from: 'es', to: 'pl', slow: true }, 'бот: переключён с es на pl — es медленнее порога');
  // через минуту es разогнался — замер есть, но до решения пропуск держится
  f.speed.es = 100; minute(); f.probes.length = 0;
  await f.ops.checkExits(f.tpl(), () => undefined);
  assert.ok(f.probes.some(([, bytes]) => bytes > 0), 'замер скорости — каждую минуту');
  assert.equal(samples('es'), 2);
  assert.equal(f.bo['bal-t'], 'lb-t-2', 'решение — только раз в 15 минут');
  // в ту же минуту повторный замер не делается
  f.probes.length = 0;
  await f.ops.checkExits(f.tpl(), () => undefined);
  assert.ok(f.probes.every(([, bytes]) => bytes === 0));
  // ещё три быстрые минуты, время решения: медиана es [30, 100, 100, 100, 100] = 100 — снова через es
  for (let i = 0; i < 3; i++) { minute(); await f.ops.checkExits(f.tpl(), () => undefined); }
  ago('auto.decideAt.t', 16);
  minute(); await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.bo['bal-t'], null);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-es');
  // одна плохая минута es (10) среди быстрых — медиана выше порога, трафик остаётся на es
  f.db.prepare('DELETE FROM exit_speed').run();
  for (const v of [100, 10, 100]) { f.speed.es = v; minute(); await f.ops.checkExits(f.tpl(), () => undefined); }
  ago('auto.decideAt.t', 16); f.speed.es = 100;
  minute(); await f.ops.checkExits(f.tpl(), () => undefined);
  assert.equal(f.bo['bal-t'], null, 'одна просадка не перекидывает');
  // устойчиво медленно и es, и pl — по кнопке «Проверить сейчас» сразу на fi
  f.speed.es = 30; f.speed.pl = 20;
  r = await f.ops.checkExits(f.tpl(), () => undefined, { force: true });
  assert.deepEqual([f.bo['bal-t'], f.bo['bal-t-2']], ['lb-t-2', 'lb-t-3']);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-fi');
});

test('«по порядку» без порога — ничего не мерим и не пропускаем', async () => {
  const f = fixture();
  f.db.prepare(`UPDATE templates SET settings = '{"security":"none","autoMode":"order","exitOrder":["es","pl","fi"]}' WHERE id = 't'`).run();
  await f.ops.checkExits(f.tpl(), () => undefined, { force: true });
  assert.ok(f.probes.every(([, bytes]) => bytes === 0));
  assert.equal(f.bo['bal-t'], null);
  assert.equal(getSetting(f.db, 'auto.actual.t', null), 'to-t-es');
});

test('онлайн: подключения видели за минуту — в сети; потом — «был в сети» с временем', async () => {
  const { db, ctx } = fixture();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u-a1', 'ann', 's', 'k')`).run();
  updateDevices(ctx, new Map([['u-a1', new Set(['198.51.100.1'])]]), new Date());
  const { default: Fastify } = await import('fastify');
  const app = Fastify();
  app.addHook('preHandler', async (req) => { (req as { admin?: unknown }).admin = { id: 1, username: 'o', role: 'owner', totp: false, totpSecret: null }; });
  const { userRoutes } = await import('./routes/users.js');
  await userRoutes(app, ctx);
  let u = (await app.inject({ method: 'GET', url: '/api/v1/users' })).json()[0];
  assert.equal(u.online, true);
  // ушёл 3 минуты назад: строк устройств уже нет, остаётся «был в сети»
  updateDevices(ctx, new Map(), new Date(Date.now() + 3 * 60_000));
  u = (await app.inject({ method: 'GET', url: '/api/v1/users' })).json()[0];
  assert.equal(u.online, false);
  assert.ok(u.lastSeen);
  await app.close();
});
