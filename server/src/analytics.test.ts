import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { kitVersion } from './nodekit.js';
import { audit } from './lib/audit.js';
import { analyticsSummary, buildDiagnostics, collectMetrics, diagFileName } from './analytics.js';

function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-an-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 4)));
  for (const [id, role, fp] of [['relay', 'entry', 'fp'], ['es', 'exit', 'fp'], ['new', 'exit', null]] as const)
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp) VALUES (?, ?, '203.0.113.1', ?, 'k', 'x', 'restricted', ?)`).run(id, `${id}-1`, role, fp);
  const calls: string[] = [];
  let rx = 0;
  (ctx as unknown as { onNode: unknown }).onNode = async (s: { id: string }, fn: (n: unknown) => Promise<unknown>) => fn({
    op: async (a: (string | number)[]) => {
      calls.push(`${s.id}:${a.join(' ')}`);
      const ok = (stdout: string) => ({ code: 0, stdout, stderr: '' });
      if (a[0] === 'version') return ok(kitVersion());
      if (a[0] === 'host-stat') { rx += 125_000_000; return ok(`@stat\ncpu 100 0 100 800 0 0 0 0\n@meminfo\nMemTotal: 2000000 kB\nMemAvailable: 500000 kB\n@netdev\n  eth0: ${rx} 0 0 0 0 0 0 0 ${rx} 0 0 0 0 0 0 0\n@loadavg\n0.50 0.4 0.3 1/100 1\n@df\n/dev/vda1 1000 250 750 25% /\n`); }
      if (a[0] === 'diag') return ok(`@host\nuptime: up 1 day\n@services\neskadra-xray: active\n@log служба eskadra-xray\nстрок: 3, разных: 1\n3× 10-19T01:00…10-19T02:00 | from 176.97.x.x:1 rejected`);
      return ok('');
    },
    must: async () => 'ok',
  });
  return { db, ctx, calls };
}

test('аналитика: срез раз в 5 минут — только подключённые серверы, старше 48 часов удаляется', async () => {
  const { db, ctx, calls } = fixture();
  db.prepare(`INSERT INTO host_metrics (server_id, at, cpu) VALUES ('es', ?, 5)`).run(new Date(Date.now() - 49 * 3600_000).toISOString());
  assert.equal(await collectMetrics(ctx), 2);
  assert.ok(!calls.some((c) => c.startsWith('new:')), 'не подключённый до конца сервер не опрашивается');
  assert.equal((db.prepare(`SELECT COUNT(*) n FROM host_metrics WHERE at < ?`).get(new Date(Date.now() - 48 * 3600_000).toISOString()) as { n: number }).n, 0);
  await new Promise((r) => setTimeout(r, 20));
  await collectMetrics(ctx);
  const s = analyticsSummary(ctx).servers.find((x) => x.id === 'es')!;
  assert.equal(s.points, 2);
  assert.equal(s.mem?.max, 75, 'память: занято 1500 из 2000 МБ');
  assert.equal(s.disk?.max, 25);
  assert.ok((s.series.at(-1)!.net ?? 0) > 0, 'сеть — по разнице со прошлым срезом');
  // потери связи — из аудита
  audit(db, 'system', 'server.recovered', 'es', { downMin: 6 });
  audit(db, 'system', 'server.recovered', 'es', { downMin: 2 });
  assert.deepEqual(analyticsSummary(ctx).servers.find((x) => x.id === 'es')!.outages, { count: 2, worstMin: 6 });
});

test('выгрузка: серверы, конфигурации, события без пользователей и с замаскированными адресами, журналы с серверов', async () => {
  const { db, ctx, calls } = fixture();
  db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids, entry_id, entry_port, settings) VALUES ('t', 'trio', 'xray', 'vless', 8443, '[]', '["es"]', 'relay', 9443, '{"security":"reality","autoMode":"spread","spreadGroups":6}')`).run();
  audit(db, 'fleet', 'admin.login', undefined, { ip: '176.97.134.103' });
  audit(db, 'fleet', 'user.create', 'u-1', { name: 'Иван Петров' });
  audit(db, 'system', 'server.recovered', 'es', { downMin: 3 });
  await collectMetrics(ctx);
  const md = await buildDiagnostics(ctx, 48);
  assert.match(md, /^# Эскадра — диагностика за 48 ч/);
  assert.match(md, /\| trio \| vless \| reality\/tcp .*\| relay-1:9443 \| es-1 \| по нагрузке \(групп 6/);
  assert.match(md, /admin\.login .*176\.97\.x\.x/, 'адрес админа замаскирован');
  assert.ok(!md.includes('176.97.134.103'));
  assert.ok(!md.includes('Иван Петров'), 'данные пользователей не выгружаются');
  assert.match(md, /user\.create ×1/);
  assert.match(md, /server\.recovered es-1/);
  assert.match(md, /### es-1 \(exit, 203\.0\.113\.1\)\n\n```text\n#### Хост/);
  assert.match(md, /#### служба eskadra-xray\n.*\n3× /);
  assert.ok(calls.filter((c) => c.endsWith('diag 48')).length === 2, 'журналы — с каждого подключённого сервера');
  assert.match(diagFileName(48, new Date('2026-10-19T01:02:00Z')), /^eskadra-diag-2026-10-19-01-02-48h\.md$/);
});
