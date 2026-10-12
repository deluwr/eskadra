/**
 * Проверка порта служебного туннеля сразу после bootstrap, пока открыт первичный доступ (onboard.ts, шаг 1).
 *
 * Раньше недоступный порт туннеля обнаруживался только на шаге 2 («Timed out while waiting for handshake»),
 * когда root-доступа уже нет и причину не выяснить. Теперь: панель тем же путём, каким пойдёт туннель
 * (напрямую или через прокси), делает TLS-рукопожатие с портом туннеля. REALITY чужому клиенту отвечает
 * сайтом маскировки — рукопожатие проходит, значит порт открыт. Не проходит — по root-сессии смотрим,
 * слушает ли служба порт и не режет ли его firewall системы (iptables/nftables с запретом по умолчанию:
 * bootstrap открывает порт только в ufw и firewalld); режет — открываем и проверяем снова. Локально всё
 * открыто, а снаружи нет — это firewall хостера, о нём и пишем.
 */
import tls from 'node:tls';

/** TLS-рукопожатие с портом туннеля: true — порт отвечает как сайт маскировки. */
export function tlsReachable(host: string, port: number, servername: string, timeoutMs = 10_000): Promise<boolean> {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port, servername, rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] });
    const done = (ok: boolean) => { clearTimeout(t); s.destroy(); resolve(ok); };
    const t = setTimeout(() => done(false), timeoutMs);
    s.once('secureConnect', () => done(true));
    s.once('error', () => done(false));
  });
}

/** Состояние порта на узле: слушает ли служба, что в firewall системы. Вывод разбирает parseTunnelDiag. */
export const diagScript = (port: number) => `P=${port}
echo "@active"; systemctl is-active fleet-mgmt 2>/dev/null || true
echo "@listen"; ss -Hltn "sport = :$P" 2>/dev/null | head -3
echo "@ipt"; iptables -S INPUT 2>/dev/null | head -60
echo "@nft"; nft -a list ruleset 2>/dev/null | grep -E '^table |hook input|dport|policy' | head -80
journalctl -u fleet-mgmt -n 5 --no-pager -o cat 2>/dev/null | sed 's/^/@log /'
`;

export interface TunnelDiag { active: boolean; listening: boolean; iptablesBlocks: boolean; nftChains: string[]; log: string[] }

/** Разбор вывода diagScript: блокирует ли iptables/nftables входящие на порт по умолчанию. */
export function parseTunnelDiag(out: string, port: number): TunnelDiag {
  const sec = (name: string) => {
    const m = out.split(/^@/m).find((x) => x.startsWith(`${name}\n`) || x === name);
    return (m ?? '').split('\n').slice(1).filter(Boolean);
  };
  const ipt = sec('ipt');
  const portOk = (l: string) => new RegExp(`--dport ${port}\\b.*-j ACCEPT`).test(l);
  // запрет по умолчанию: политика DROP или итоговое правило DROP/REJECT без условий порта
  const iptDefaultDeny = ipt.some((l) => /^-P INPUT (DROP|REJECT)/.test(l)) || ipt.some((l) => /^-A INPUT( -j| .*-j) (DROP|REJECT)/.test(l) && !/--dport|-s |-i lo/.test(l));
  const iptablesBlocks = iptDefaultDeny && !ipt.some(portOk);
  // цепочки nftables с hook input и policy drop (кроме таблицы панели inet fleet — на шаге 1 её ещё нет)
  const nftChains: string[] = [];
  let table = '';
  for (const l of sec('nft')) {
    const t = l.match(/^table (\S+ \S+)/);
    if (t) { table = t[1]!; continue; }
    const c = l.match(/chain (\S+)/);
    if (/hook input/.test(l) && /policy drop/.test(l) && table !== 'inet fleet') nftChains.push(`${table} ${c?.[1] ?? 'input'}`);
  }
  return {
    active: sec('active')[0]?.trim() === 'active',
    listening: sec('listen').length > 0,
    iptablesBlocks,
    nftChains,
    log: out.split('\n').filter((l) => l.startsWith('@log ')).map((l) => l.slice(5)),
  };
}

/** Открыть порт туннеля в firewall системы (iptables и/или цепочки nftables с запретом по умолчанию). */
export function openScript(port: number, d: TunnelDiag): string {
  const lines = ['set -e'];
  if (d.iptablesBlocks) {
    lines.push(`iptables -C INPUT -p tcp --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport ${port} -j ACCEPT`);
    // сохранить, если правила загружаются при старте (iptables-persistent / netfilter-persistent)
    lines.push('if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; elif [ -d /etc/iptables ]; then iptables-save > /etc/iptables/rules.v4 || true; fi');
  }
  for (const ch of d.nftChains) {
    const [family, table, chain] = ch.split(' ');
    if (!/^[a-z0-9_-]+$/i.test(`${family}${table}${chain}`)) continue;
    lines.push(`nft insert rule ${family} ${table} ${chain} tcp dport ${port} accept`);
  }
  if (d.nftChains.length) lines.push('if [ -f /etc/nftables.conf ] && systemctl is-enabled nftables >/dev/null 2>&1; then nft list ruleset > /etc/nftables.conf; fi');
  lines.push('echo opened');
  return lines.join('\n') + '\n';
}

/** Человеческое объяснение, почему порт туннеля недоступен. */
export function explainTunnel(d: TunnelDiag, host: string, port: number, viaLabel: string | null): string {
  const path = viaLabel ? `через прокси ${viaLabel}` : 'с главного сервера';
  if (!d.active) return `служба туннеля fleet-mgmt на ${host} не работает${d.log.length ? `: ${d.log.join(' ')}` : ''}`;
  if (!d.listening) return `служба туннеля fleet-mgmt работает, но порт ${port}/tcp не слушается${d.log.length ? `: ${d.log.join(' ')}` : ''}`;
  return `порт туннеля ${port}/tcp на ${host} закрыт снаружи (${path}): служба слушает, firewall системы порт пропускает — откройте ${port}/tcp во входящих в firewall хостера (панель провайдера) и нажмите «Повторить»`;
}
