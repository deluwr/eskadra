import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Vpn } from './vpn.js';
import { renderPlan, stalePanelPorts } from './firewall.js';
import { attentionOf } from './attention.js';

test('главный сервер под защитой: порт панели или подписок сменили после применения — напоминание', () => {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-fwp-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 3)));
  db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed, sudo_mode, mgmt_mode, host_key_fp, ssh_ports) VALUES ('main', 'gw', '198.51.100.1', 'entry', 'k', 'x', 'restricted', 'local', 'SHA256:m', '[22]')`).run();
  setSetting(db, 'sub.port', 59705);
  const prev = process.env.FLEET_PORT;
  process.env.FLEET_PORT = '42174';
  try {
    const plan = renderPlan(ctx, ctx.server('main'), 'P3').text;
    ctx.updateServer('main', { fw_mode: 'enforced', fw_plan: plan });
    assert.deepEqual(stalePanelPorts(ctx, ctx.server('main')), []);
    assert.ok(!attentionOf(ctx, new Vpn(ctx)).some((a) => a.title.includes('защита не знает порт')));
    process.env.FLEET_PORT = '43000';
    setSetting(db, 'sub.port', 50000);
    assert.deepEqual(stalePanelPorts(ctx, ctx.server('main')), [43000, 50000]);
    assert.ok(attentionOf(ctx, new Vpn(ctx)).some((a) => a.title === 'gw: защита не знает порт 43000, 50000'));
    // защита не применена — напоминать не о чем
    ctx.updateServer('main', { fw_mode: 'observe' });
    assert.deepEqual(stalePanelPorts(ctx, ctx.server('main')), []);
  } finally { if (prev === undefined) delete process.env.FLEET_PORT; else process.env.FLEET_PORT = prev; }
});
