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
import net from 'node:net';
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

/**
 * Состояние порта на узле: слушает ли служба, что в firewall системы, открывается ли с узла сайт маскировки
 * (REALITY чужому клиенту отвечает им: не открывается — рукопожатие не проходит, хотя порт открыт). Вывод разбирает parseTunnelDiag.
 */
export const diagScript = (port: number, sni: string) => `P=${port}
echo "@active"; systemctl is-active fleet-mgmt 2>/dev/null || true
echo "@listen"; ss -Hltn "sport = :$P" 2>/dev/null | head -3
echo "@ipt"; iptables -S INPUT 2>/dev/null | head -60
echo "@nft"; nft -a list ruleset 2>/dev/null | grep -E '^table |hook input|dport|policy' | head -80
echo "@dest"; curl -sS -o /dev/null --max-time 8 -w '%{http_code}\\n' 'https://${sni}/' 2>&1 | tail -1
journalctl -u fleet-mgmt -n 5 --no-pager -o cat 2>/dev/null | sed 's/^/@log /'
`;

export interface TunnelDiag { active: boolean; listening: boolean; iptablesBlocks: boolean; nftChains: string[]; destOk: boolean; destErr: string; log: string[] }

/** Какие сайты маскировки открываются с узла: строки «sni=ok» / «sni=<ошибка curl>». */
export const destScript = (snis: string[]) => snis.map((s) =>
  `c="$(curl -sS -o /dev/null --max-time 8 -w '%{http_code}' 'https://${s}/' 2>&1 | tail -1)"; case "$c" in [1-5][0-9][0-9]) echo "${s}=ok" ;; *) echo "${s}=$c" ;; esac`).join('\n') + '\n';

export const parseDest = (out: string): Map<string, string> =>
  new Map(out.split('\n').map((l) => l.match(/^([a-z0-9.-]+)=(.*)$/i)).filter((m): m is RegExpMatchArray => !!m).map((m) => [m[1]!, m[2]!.trim()]));

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
  const dest = (sec('dest')[0] ?? '').trim();
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
    // нет секции (старый вывод) — не считаем сайт недоступным
    destOk: !out.includes('@dest') || /^[1-5]\d\d$/.test(dest),
    destErr: dest,
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

// ───── подбор порта туннеля, который пропускает firewall хостера ─────

/**
 * Кандидаты: популярные порты, которые хостеры обычно не закрывают (HTTPS-альтернативы Cloudflare, веб).
 * 443 и 80 — в конце: они нужнее пользовательским конфигурациям (порт туннеля зарезервирован на узле).
 */
export const TUNNEL_PORT_CANDIDATES = [2083, 2087, 8880, 2052, 2082, 2086, 2095, 8080, 8443, 2053, 2096, 443, 80];

/** Маячки на узле: слушают свободные из ports ~90 с, на подключение отвечают «fleet-probe <порт>». Печатает занятые ими порты. */
export const beaconScript = (ports: number[]) => `python3 - ${ports.join(' ')} <<'PY'
import os, select, socket, sys, time
socks = {}
for p in map(int, sys.argv[1:]):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(("::", p))
    except OSError:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", p))
        except OSError:
            continue   # порт занят — не трогаем
    s.listen(8)
    socks[s] = p
print("bound=" + ",".join(str(p) for p in socks.values()), flush=True)
if os.fork():
    os._exit(0)
os.setsid()
with open("/run/fleet-beacon.pid", "w") as f:
    f.write(str(os.getpid()))
null = os.open(os.devnull, os.O_RDWR)
for fd in (0, 1, 2):
    os.dup2(null, fd)
end = time.time() + 90
while time.time() < end:
    ready, _, _ = select.select(list(socks), [], [], 1)
    for s in ready:
        try:
            c, _ = s.accept()
            c.sendall(("fleet-probe %d\\n" % socks[s]).encode())
            c.close()
        except OSError:
            pass
PY
`;

/** Погасить маячки и дождаться, пока их порты освободятся: иначе Xray туннеля на выбранном порту не встанет. */
export const beaconStopScript = (ports: number[], bound: number[]) => `pid="$(cat /run/fleet-beacon.pid 2>/dev/null || true)"
[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
pkill -f '^python3 - ${ports.join(' ')}$' 2>/dev/null || true
rm -f /run/fleet-beacon.pid
for i in $(seq 1 25); do
  ss -Hltn 2>/dev/null | grep -Eq ':(${bound.join('|') || '0'})\\s' || exit 0
  [ "$i" = 10 ] && { [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; pkill -9 -f '^python3 - ${ports.join(' ')}$' 2>/dev/null; } || true
  sleep 0.2
done
echo "порты маячков не освободились" >&2
`;

/** Из вывода сниппета — строки, по которым видно, почему не встала служба (ошибка Xray, а не общий «Failed»). */
export function snippetFailure(out: string): string {
  const lines = out.trim().split('\n').map((l) => l.trim()).filter(Boolean);
  const why = lines.filter((l) => /address already in use|bind:|listen tcp|permission denied|failed to|\[Error\]|Failed to start|конфиг туннеля/i.test(l) && !/Failed with result/.test(l));
  return [...new Set([...why.slice(-2), ...lines.slice(-1)])].join(' ');
}

/** Ответил ли маячок на порту: читаем «fleet-probe <порт>» (через прокси TCP «соединяется» всегда, доказывает только ответ узла). */
export function beaconAnswers(host: string, port: number, expectPort: number, timeoutMs = 8000): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    let buf = '';
    const done = (ok: boolean) => { clearTimeout(t); s.destroy(); resolve(ok); };
    const t = setTimeout(() => done(false), timeoutMs);
    s.on('data', (d) => { buf += d.toString('utf8'); if (buf.includes(`fleet-probe ${expectPort}`)) done(true); });
    s.once('error', () => done(false));
    s.once('close', () => done(buf.includes(`fleet-probe ${expectPort}`)));
  });
}
