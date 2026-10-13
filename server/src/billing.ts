/**
 * Срок оплаты серверов: до какой даты оплачен сервер (вводит админ в карточке сервера). За paid_warn_days дней
 * до конца — напоминание в Telegram раз в день и баннер в панели; после окончания — ещё три дня напоминаний.
 */
import type { Ctx, ServerRow } from './ctx.js';

const DAY = 86_400_000;

/** Сколько дней осталось до конца оплаченного срока (дата — последний оплаченный день): 0 — сегодня последний, <0 — истёк. */
export function paidDaysLeft(paidUntil: string | null, now = new Date()): number | null {
  if (!paidUntil || !/^\d{4}-\d{2}-\d{2}$/.test(paidUntil)) return null;
  const today = Date.parse(now.toISOString().slice(0, 10));
  return Math.round((Date.parse(paidUntil) - today) / DAY);
}

export interface BillingAlert { id: string; name: string; paidUntil: string; daysLeft: number; level: 'warn' | 'fail' }

/** Серверы, у которых срок оплаты подходит к концу или истёк: для баннера в панели и уведомлений. */
export function billingAlerts(servers: ServerRow[], now = new Date()): BillingAlert[] {
  const out: BillingAlert[] = [];
  for (const s of servers) {
    const left = paidDaysLeft(s.paid_until, now);
    if (left === null || left > (s.paid_warn_days || 5)) continue;
    out.push({ id: s.id, name: s.name, paidUntil: s.paid_until!, daysLeft: left, level: left <= 1 ? 'fail' : 'warn' });
  }
  return out.sort((a, b) => a.daysLeft - b.daysLeft);
}

/** «15.10.2026» */
export const ruDate = (iso: string) => iso.split('-').reverse().join('.');

const days = (n: number) => {
  const m10 = n % 10, m100 = n % 100;
  return `${n} ${m10 === 1 && m100 !== 11 ? 'день' : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? 'дня' : 'дней'}`;
};

/** Текст напоминания для бота. */
export function billingText(a: BillingAlert): string {
  if (a.daysLeft > 0) return `💳 ${a.name}: оплата заканчивается через ${days(a.daysLeft)} (оплачен до ${ruDate(a.paidUntil)}). Продлите у хостера и обновите дату в карточке сервера.`;
  if (a.daysLeft === 0) return `💳 ${a.name}: сегодня последний оплаченный день (${ruDate(a.paidUntil)}). Продлите у хостера и обновите дату в карточке сервера.`;
  return `⛔ ${a.name}: срок оплаты истёк ${ruDate(a.paidUntil)} — хостер может отключить сервер. Продлите и обновите дату в карточке сервера.`;
}

/**
 * Какие напоминания отправить сейчас: по одному на сервер в день (ключ — дата оплаты и число оставшихся дней),
 * после окончания срока — ещё три дня. Отмеченные отправленными запоминаются в notified.
 */
export function billingDue(ctx: Pick<Ctx, 'servers'>, notified: Record<string, string>, now = new Date()): BillingAlert[] {
  const due: BillingAlert[] = [];
  for (const a of billingAlerts(ctx.servers(), now)) {
    if (a.daysLeft < -3) continue;
    const key = `${a.paidUntil}:${a.daysLeft}`;
    if (notified[a.id] === key) continue;
    notified[a.id] = key;
    due.push(a);
  }
  return due;
}
