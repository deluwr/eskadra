/**
 * Подбор сайтов маскировки REALITY (§10.6): кандидаты проверяются с самого узла — оттуда, откуда Xray
 * будет ходить к сайту. Требования к сайту: TLS 1.3, X25519, HTTP/2, сертификат на это имя; лучше без
 * редиректа на другой сайт и с малой задержкой от узла (сосед по дата-центру — лучший вариант).
 */
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { Ctx, ServerRow } from './ctx.js';
import { HttpError } from './ctx.js';
import { Ops } from './ops.js';

/** Известные кандидаты: крупные сайты с TLS 1.3 и HTTP/2 по всему миру. Что подходит именно узлу — покажет проверка. */
export const SNI_CANDIDATES = [
  'www.apple.com', 'dl.google.com', 'www.cloudflare.com', 'www.samsung.com', 'www.amazon.com', 'aws.amazon.com',
  'www.nvidia.com', 'www.amd.com', 'www.intel.com', 'www.dell.com', 'www.hp.com', 'www.asus.com', 'www.logitech.com',
  'www.mozilla.org', 'addons.mozilla.org', 'github.com', 'www.speedtest.net', 'cdn.jsdelivr.net', 'www.yahoo.com',
  'www.oracle.com', 'www.sony.com', 'www.tesla.com', 'gateway.icloud.com', 'swdist.apple.com', 'www.cisco.com',
  'www.ikea.com', 'www.lovelive-anime.jp', 'www.microsoft.com',
];

/** Проходят проверку, но с REALITY не работают (проверено на Xray 26.3). */
export const SNI_KNOWN_BAD: Record<string, string> = {
  'www.microsoft.com': 'с REALITY рукопожатие не проходит',
};

export interface SniResult {
  domain: string; source: 'list' | 'neighbor'; ok: boolean; ip: string | null; tcp_ms: number | null; tls_ms: number | null;
  tls13: boolean; h2: boolean; x25519: boolean; redirect: string | null; error: string | null; neighbor_ip?: string;
}

const DOMAIN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** Порядок: подходящие, затем соседи по подсети (тот же дата-центр), затем по задержке от узла. */
export function rankSni(rs: SniResult[]): SniResult[] {
  return [...rs].sort((a, b) => Number(b.ok) - Number(a.ok) || Number(!!a.redirect) - Number(!!b.redirect)
    || Number(b.source === 'neighbor') - Number(a.source === 'neighbor') || (a.tcp_ms ?? 1e9) - (b.tcp_ms ?? 1e9));
}

export async function scanSni(ctx: Ctx, s: ServerRow, opts: { neighbors: boolean; domains?: string[] }): Promise<{ results: SniResult[]; host: string | null }> {
  if (s.sudo_mode !== 'restricted') throw new HttpError(409, `${s.name}: сначала установите nodekit`);
  const domains = [...new Set((opts.domains?.length ? opts.domains : SNI_CANDIDATES).map((d) => d.trim().toLowerCase()).filter((d) => DOMAIN.test(d)))].slice(0, 60);
  // соседи ищутся в /24 адреса узла: IPv4 — как есть, имя — резолвим
  let host: string | null = isIP(s.host) === 4 ? s.host : null;
  if (opts.neighbors && !host) host = await lookup(s.host, { family: 4 }).then((r) => r.address).catch(() => null);
  const ops = new Ops(ctx);
  const out = await ctx.onNode(s, async (n) => {
    await ops.ensureKit(s, n, () => undefined);   // fleet-sni появился в nodekit вместе с этой функцией
    return n.must(['sni-scan'], { stdin: JSON.stringify({ domains, neighbors: opts.neighbors && !!host, host }), timeoutMs: 150_000 });
  });
  let parsed: { results: SniResult[] };
  try { parsed = JSON.parse(out) as { results: SniResult[] }; } catch { throw new HttpError(502, `узел вернул не JSON: ${out.slice(0, 200)}`); }
  const results = parsed.results.map((r) => (SNI_KNOWN_BAD[r.domain] && r.ok ? { ...r, ok: false, error: SNI_KNOWN_BAD[r.domain]! } : r));
  return { results: rankSni(results), host };
}
