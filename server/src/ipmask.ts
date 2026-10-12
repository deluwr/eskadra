/**
 * Видимость IP-адресов людей (право «ips.view», у owner — всегда). Без права адреса пользователей (устройства,
 * белый список) и администраторов (сессии, входы в журнале, домашние адреса на серверах, адрес панели) не
 * уходят из API вовсе — заменяются на «скрыт» перед отправкой ответа, а не прячутся в интерфейсе.
 *
 * Адреса серверов не маскируются: они есть в каждой ссылке подписки, которую роль выдаёт пользователям;
 * интерфейс без права их не показывает.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Ctx } from './ctx.js';
import { can, roleOf } from './roles.js';

export const HIDDEN = 'скрыт';

/** Поля ответов с адресами людей. */
const PERSON_IP_KEYS = new Set(['ip', 'cidr', 'seen_from_ip', 'seenFromIp', 'admin_ips', 'executorIps', 'detected']);
// IPv6 — с «::» или из 5+ групп: время вида 23:59:59 и прочие «a:b:c» не трогаем
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b|\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}(?:\/\d{1,3})?\b|(?:\b[0-9a-f]{1,4})?(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?(?:\/\d{1,3})?/gi;

export const maskIpsInText = (s: string) => s.replace(IP_RE, HIDDEN);

/** Заменить адреса людей в ответе (глубоко); в журнале — и внутри текста detail. */
export function maskPersonIps(v: unknown, key = ''): unknown {
  if (PERSON_IP_KEYS.has(key)) {
    if (Array.isArray(v)) return v.map(() => HIDDEN);
    return typeof v === 'string' && v ? HIDDEN : v;
  }
  if (key === 'detail' && typeof v === 'string') return maskIpsInText(v);
  if (Array.isArray(v)) return v.map((x) => maskPersonIps(x));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, maskPersonIps(x, k)]));
  return v;
}

export const canSeeIps = (ctx: Ctx, req: FastifyRequest) => !!req.admin && can(roleOf(ctx.db, req.admin.role), 'ips.view');

/** Хук ответов защищённой части API. Свои сессии (/api/v1/me) — без маскировки: это адреса самого админа. */
export function registerIpMask(app: FastifyInstance, ctx: Ctx) {
  app.addHook('preSerialization', async (req, _reply, payload) => {
    if (!req.admin || canSeeIps(ctx, req) || (req.routeOptions.url ?? '').includes('/api/v1/me')) return payload;
    return maskPersonIps(payload);
  });
}
