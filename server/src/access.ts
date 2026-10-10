import { isIP } from 'node:net';
import type { Ctx, UserRow } from './ctx.js';
import { Vpn } from './vpn.js';

/**
 * Адрес → элемент белого списка по режиму пользователя (§13.4, решение §24.1):
 * exact — сам адрес (/32, для IPv6 — /64); prefix — /24 (IPv6 — /48); asn — /16 (IPv6 — /32).
 * Режим asn приближён префиксом: точная база ASN не входит в поставку.
 */
export function normalizeCidr(ip: string, mode: UserRow['wl_mode']): string {
  const fam = isIP(ip);
  if (fam === 4) {
    const bits = mode === 'exact' ? 32 : mode === 'prefix' ? 24 : 16;
    const n = ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
    const masked = bits === 32 ? n : (n & (~0 << (32 - bits))) >>> 0;
    return `${[24, 16, 8, 0].map((s) => (masked >>> s) & 255).join('.')}/${bits}`;
  }
  if (fam === 6) {
    const bits = mode === 'exact' ? 64 : mode === 'prefix' ? 48 : 32;
    const full = expand6(ip);
    const groups = full.split(':').slice(0, bits / 16);
    return `${groups.join(':')}::/${bits}`;
  }
  throw new Error('bad ip');
}

function expand6(ip: string): string {
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const mid = Array(8 - h.length - t.length).fill('0');
  return [...h, ...(ip.includes('::') ? mid : []), ...t].map((g) => g.padStart(4, '0')).join(':');
}

const ttlArg = (sec: number) => (sec % 3600 === 0 && sec / 3600 <= 9999 ? `${sec / 3600}h` : `${Math.min(9999, Math.ceil(sec / 60))}m`);

/** Узлы пользователя, где firewall держит белый список. */
function enforcedNodesFor(ctx: Ctx, u: UserRow) {
  const vpn = new Vpn(ctx);
  return ctx.servers().filter((s) => s.sudo_mode === 'restricted' && ['enforced', 'pending', 'shadow'].includes(s.fw_mode) && vpn.userAllows(u, s.id));
}

export async function pushAllowedIp(ctx: Ctx, u: UserRow, cidrOrIp: string, source: string, ttlSec: number) {
  const cidr = cidrOrIp.includes('/') ? cidrOrIp : normalizeCidr(cidrOrIp, u.wl_mode);
  const expires = new Date(Date.now() + ttlSec * 1000).toISOString();
  ctx.db.prepare(`INSERT INTO allowed_ips (user_id, cidr, source, expires_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, cidr) DO UPDATE SET expires_at = excluded.expires_at, source = excluded.source`).run(u.id, cidr, source, expires);
  const results: Array<{ server: string; ok: boolean }> = [];
  for (const s of enforcedNodesFor(ctx, u)) {
    try {
      await ctx.onNode(s, (n) => n.must(['user-add', cidr, ttlArg(ttlSec)]));
      results.push({ server: s.name, ok: true });
    } catch { results.push({ server: s.name, ok: false }); }
  }
  return { cidr, expires, results };
}

export async function revokeAllowedIp(ctx: Ctx, u: UserRow, id: number) {
  const row = ctx.db.prepare('SELECT cidr FROM allowed_ips WHERE id = ? AND user_id = ?').get(id, u.id) as { cidr: string } | undefined;
  if (!row) return;
  ctx.db.prepare('DELETE FROM allowed_ips WHERE id = ?').run(id);
  for (const s of enforcedNodesFor(ctx, u)) await ctx.onNode(s, (n) => n.op(['user-del', row.cidr])).catch(() => undefined);
}
