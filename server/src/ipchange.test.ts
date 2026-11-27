import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getSetting, openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { attentionOf } from './attention.js';
import { applyPanelIp, checkPanelIp, isPublicV4, knownPanelIp, type IpProbe } from './ipchange.js';

const OLD = '198.51.100.1';
const NEW = '203.0.113.50';

/** Главный сервер-узел main (local, relay) на OLD, выход pl по прямому SSH; подписки на IP панели. */
function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-ipch-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 7)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, mgmt_mode, host_key_fp) VALUES ('main', 'relay', '${OLD}', 'entry', 'k', 'x', 'restricted', 'local', 'SHA256:m')`).run();
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, host_key_fp) VALUES ('pl', 'pl', '203.0.113.9', 'exit', 'k', 'x', 'restricted', 'SHA256:pl')`).run();
  setSetting(db, 'executor.ips', [OLD, '192.0.2.7']);
  setSetting(db, 'sub.host', OLD);
  return { db, ctx };
}

/** Проба: адреса интерфейсов, маршрут и внешний адрес — заданные. */
const probe = (o: { ifaces?: string[]; route?: string | null; egress?: string | null }): IpProbe => ({
  ifaces: () => o.ifaces ?? [],
  route: async () => o.route ?? null,
  egress: async () => o.egress ?? null,
});

test('публичные адреса', () => {
  for (const ip of ['10.0.0.1', '172.20.1.1', '192.168.1.1', '100.64.0.1', '127.0.0.1', '169.254.1.1', '::1']) assert.equal(isPublicV4(ip), false, ip);
  for (const ip of ['8.8.8.8', NEW, '172.32.0.1']) assert.equal(isPublicV4(ip), true, ip);
});

test('нынешний IP: главный сервер-узел, иначе адрес панели, иначе первый адрес исполнителя', () => {
  const { ctx } = fixture();
  assert.equal(knownPanelIp(ctx, 'pnl.example'), OLD);
  ctx.updateServer('main', { mgmt_mode: 'direct' });
  assert.equal(knownPanelIp(ctx, '198.51.100.77'), '198.51.100.77');
  assert.equal(knownPanelIp(ctx, 'pnl.example'), OLD);
});

test('адрес на интерфейсе — смены нет; пропал, а маршрут с нового — смена со второй проверки', async () => {
  const { ctx } = fixture();
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [OLD], route: OLD }), ''), null);
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [NEW], route: NEW }), ''), null, 'первая проверка — только кандидат');
  assert.deepEqual(await checkPanelIp(ctx, probe({ ifaces: [NEW], route: NEW }), ''), { from: OLD, to: NEW });
});

test('мигание адреса не считается сменой', async () => {
  const { ctx } = fixture();
  await checkPanelIp(ctx, probe({ ifaces: [OLD], route: OLD }), '');
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [NEW], route: NEW }), ''), null);
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [OLD], route: OLD }), ''), null);
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [NEW], route: NEW }), ''), null, 'после возврата — снова с первой');
});

test('за NAT: внешний адрес; если он никогда не совпадал с известным — ничего само не меняется', async () => {
  const { ctx } = fixture();
  // выход в интернет с другого адреса с самого начала — это не смена
  const other = probe({ ifaces: ['10.0.0.5'], route: '10.0.0.5', egress: NEW });
  assert.equal(await checkPanelIp(ctx, other, ''), null);
  assert.equal(await checkPanelIp(ctx, other, ''), null);
  assert.equal(await checkPanelIp(ctx, other, ''), null);
  // раньше внешний адрес совпадал — смена засчитывается
  const { ctx: c2 } = fixture();
  await checkPanelIp(c2, probe({ ifaces: ['10.0.0.5'], route: '10.0.0.5', egress: OLD }), '');
  await checkPanelIp(c2, other, '');
  assert.deepEqual(await checkPanelIp(c2, other, ''), { from: OLD, to: NEW });
});

test('адрес панели уже новый, а главный сервер-узел — на прежнем: смена сразу, без базового адреса', async () => {
  const { ctx } = fixture();
  // панель не видела прежний адрес (смена была до обновления), eskadra уже записала новый в адрес панели
  assert.deepEqual(await checkPanelIp(ctx, probe({ ifaces: [NEW], route: NEW }), NEW), { from: OLD, to: NEW });
  // за NAT — подтверждение внешним адресом
  assert.deepEqual(await checkPanelIp(ctx, probe({ ifaces: ['10.0.0.5'], route: '10.0.0.5', egress: NEW }), NEW), { from: OLD, to: NEW });
  // адрес панели не подтверждается — ничего
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: ['10.0.0.5'], route: '10.0.0.5', egress: '203.0.113.77' }), NEW), null);
  // прежний адрес ещё на интерфейсе — смены нет
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [OLD, NEW], route: OLD }), NEW), null);
});

test('нет сети — ничего не решаем', async () => {
  const { ctx } = fixture();
  await checkPanelIp(ctx, probe({ ifaces: [OLD] }), '');
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [] }), ''), null);
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [] }), ''), null);
});

test('смена: адрес главного сервера, исполнителя и подписок — новый; «Требует внимания» — что осталось', async () => {
  const { db, ctx } = fixture();
  const c = await applyPanelIp(ctx, OLD, NEW, 'test', OLD);
  assert.equal(ctx.server('main').host, NEW);
  assert.equal(ctx.server('main').mgmt_mode, 'local');
  assert.deepEqual(ctx.executorIps(), [NEW, '192.0.2.7'], 'новый — первым, прежний убран');
  assert.equal(getSetting(db, 'sub.host', ''), NEW);
  assert.equal(c.panelHost, 'manual', 'адрес панели — прежний IP: его меняет помощник');
  // пока узлы обрабатываются — сообщение о ходе
  assert.ok(attentionOf(ctx, new Vpn(ctx)).some((a) => a.title === `IP главного сервера сменился: ${OLD} → ${NEW}` && a.level === 'info'));
  // узел не пустил панель — команда для консоли
  setSetting(db, 'panel.ipchange', { ...c, running: false, cut: ['pl'] });
  ctx.updateServer('pl', { fail_since: new Date().toISOString() });
  const prev = process.env.FLEET_PUBLIC_HOST;
  process.env.FLEET_PUBLIC_HOST = OLD;
  try {
    const a = attentionOf(ctx, new Vpn(ctx)).find((x) => x.title.startsWith('IP главного сервера сменился'))!;
    assert.equal(a.level, 'warn');
    assert.match(a.detail, /eskadra public-ip/);
    assert.match(a.detail, /pl\. Разрешите им новый адрес — в консоли хостера: fleetctl allow 203\.0\.113\.50/);
  } finally { if (prev === undefined) delete process.env.FLEET_PUBLIC_HOST; else process.env.FLEET_PUBLIC_HOST = prev; }
  // после смены базовый адрес — новый: следующая проверка с него
  assert.equal(await checkPanelIp(ctx, probe({ ifaces: [NEW], route: NEW }), ''), null);
});

test('подписки на домене и адрес панели — домен: остаются', async () => {
  const { db, ctx } = fixture();
  setSetting(db, 'sub.host', 'sub.invalid');
  const c = await applyPanelIp(ctx, OLD, NEW, 'test', 'pnl.invalid');
  assert.equal(getSetting(db, 'sub.host', ''), 'sub.invalid');
  assert.equal(c.panelHost, null);
});
