import { test } from 'node:test';
import assert from 'node:assert/strict';
import { billingAlerts, billingDue, billingText, paidDaysLeft } from './billing.js';
import { parseLinkTest } from './spread.js';
import type { ServerRow } from './ctx.js';

const now = new Date('2026-10-13T15:00:00Z');
const srv = (id: string, paid_until: string | null, paid_warn_days = 5) => ({ id, name: id, paid_until, paid_warn_days }) as ServerRow;

test('оплата: дни до конца — дата последнего оплаченного дня, сегодня — 0, после — отрицательные', () => {
  assert.equal(paidDaysLeft('2026-10-16', now), 3);
  assert.equal(paidDaysLeft('2026-10-13', now), 0);
  assert.equal(paidDaysLeft('2026-10-11', now), -2);
  assert.equal(paidDaysLeft(null, now), null);
  assert.equal(paidDaysLeft('15.10.2026', now), null);
});

test('оплата: баннер — только серверы в окне напоминания, ближайшие сверху', () => {
  const a = billingAlerts([srv('es-1', '2026-10-16'), srv('pl-1', '2026-12-01'), srv('fi-1', '2026-10-14'), srv('nl-1', null), srv('lv', '2026-10-25', 14)], now);
  assert.deepEqual(a.map((x) => [x.name, x.daysLeft, x.level]), [['fi-1', 1, 'fail'], ['es-1', 3, 'warn'], ['lv', 12, 'warn']]);
});

test('оплата: напоминание раз в день, после окончания — ещё три дня; новая дата — снова отслеживается', () => {
  const notified: Record<string, string> = {};
  const servers = [srv('es-1', '2026-10-16')];
  const ctx = { servers: () => servers };
  assert.equal(billingDue(ctx, notified, now).length, 1);
  assert.equal(billingDue(ctx, notified, new Date('2026-10-13T20:00:00Z')).length, 0, 'тот же день — повторно не шлём');
  assert.equal(billingDue(ctx, notified, new Date('2026-10-14T09:00:00Z')).length, 1, 'на следующий день — снова');
  assert.equal(billingDue(ctx, notified, new Date('2026-10-19T09:00:00Z')).length, 1, '3 дня после окончания');
  assert.equal(billingDue(ctx, notified, new Date('2026-10-20T09:00:00Z')).length, 0, 'дальше молчим');
  servers[0] = srv('es-1', '2026-11-16');
  assert.equal(billingDue(ctx, notified, new Date('2026-11-12T09:00:00Z')).length, 1);
});

test('оплата: текст напоминания', () => {
  const [a] = billingAlerts([srv('es-1', '2026-10-15')], now);
  assert.match(billingText(a!), /через 2 дня \(оплачен до 15\.10\.2026\)/);
  assert.match(billingText({ ...a!, daysLeft: 0 }), /сегодня последний/);
  assert.match(billingText({ ...a!, daysLeft: -1 }), /истёк 15\.10\.2026/);
  assert.match(billingText({ ...a!, daysLeft: 5 }), /через 5 дней/);
  assert.match(billingText({ ...a!, daysLeft: 1 }), /через 1 день/);
});

test('замер канала: результат Ookla и запасной — по зеркалам', () => {
  assert.deepEqual({ ...parseLinkTest('dev=eth0\ndown_mbps=247\nup_mbps=245\nserver=CITIC Telecom CPC Estonia OÜ\nsource=ookla\n'), at: '' },
    { down: 247, up: 245, at: '', source: 'ookla', server: 'CITIC Telecom CPC Estonia OÜ' });
  assert.equal(parseLinkTest('dev=eth0\ndown_mbps=240\nup_mbps=230\nsource=mirrors\n')?.source, 'mirrors');
});

test('замер канала: speedtest не поставился — причина сохраняется вместе с замером по зеркалам', () => {
  const l = parseLinkTest('dev=eth0\nnote=speedtest от Ookla установить не удалось — замер по тестовым файлам\ndown_mbps=231\nup_mbps=240\nsource=mirrors\n');
  assert.equal(l?.source, 'mirrors');
  assert.match(l?.note ?? '', /установить не удалось/);
});
