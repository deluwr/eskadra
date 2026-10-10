import { isIP } from 'node:net';
import { expectedPanelIps, type Ctx, type ServerRow } from './ctx.js';
import { json, Vpn } from './vpn.js';

export interface PlanResult {
  text: string;
  shadow: string;
  lint: string[];       // блокирующие ошибки
  warnings: string[];
  summary: { level: string; stealth: string; sshPorts: number[]; svcTcp: number[]; svcUdp: number[]; panel: string[]; admin: string[]; peers: string[]; users: number };
}

const v4 = (ips: string[]) => ips.filter((i) => isIP(i) === 4);
const v6 = (ips: string[]) => ips.filter((i) => isIP(i) === 6);
const els = (xs: (string | number)[]) => (xs.length ? ` elements = { ${xs.join(', ')} }` : '');

/**
 * План nft для узла (§13.3, §7.11). Структура — фиксированная, данные — в наборах.
 * Уровни: P1 — плана нет; P2 — default-drop, порты роли открыты всем; P3 — SSH только с доверенных адресов,
 * сервисные порты — по уровню скрытности группы.
 */
export function renderPlan(ctx: Ctx, s: ServerRow, level: 'P2' | 'P3'): PlanResult {
  const vpn = new Vpn(ctx);
  const lint: string[] = [];
  const warnings: string[] = [];
  const group = ctx.db.prepare('SELECT * FROM groups WHERE name = ?').get(s.group_name) as
    | { stealth: string; peer_scope: string } | undefined;
  const stealth = level === 'P2' ? 'S0' : group?.stealth ?? 'S0';

  const sshPorts = json<number[]>(s.ssh_ports, []);
  if (!sshPorts.length) lint.push('неизвестны SSH-порты узла — запустите preflight');
  const panel = ctx.executorIps();
  const tunnel = s.mgmt_mode === 'tunnel';
  // через туннель SSH панели приходит через lo: пустой executor.ips панель не отрежет (§5.8)
  if (!panel.length && !tunnel) lint.push('пустой executor.ips — панель отрежет сама себя');
  if (tunnel && !s.mgmt_port) lint.push('у узла нет порта служебного туннеля — переключите канал заново');
  if (s.seen_from_ip && !expectedPanelIps(s, panel).includes(s.seen_from_ip))
    lint.push(`узел видит панель с ${s.seen_from_ip}, этого адреса нет в executor.ips`);
  const admin = json<string[]>(s.admin_ips, []);

  const peers = ctx.servers()
    .filter((x) => x.id !== s.id && isIP(x.host))
    .filter(() => (group?.peer_scope ?? 'services') !== 'none')
    .map((x) => x.host);

  const ibs = vpn.inbounds(`server_id = ? AND state IN ('active','deploying')`, s.id);
  const svcTcp = [...new Set(ibs.filter((i) => i.proto === 'tcp').map((i) => i.port))];
  const svcUdp = [...new Set(ibs.filter((i) => i.proto === 'udp').map((i) => i.port))];
  for (const p of [...svcTcp, ...svcUdp]) if (sshPorts.includes(p)) lint.push(`сервисный порт ${p} совпадает с SSH`);
  if (s.mgmt_port && svcTcp.includes(s.mgmt_port)) lint.push(`сервисный порт ${s.mgmt_port} совпадает с портом служебного туннеля`);

  // Пользовательские IP с оставшимся TTL — только если уровень требует whitelist
  const useUsers = level === 'P3' && (stealth === 'S3' || stealth === 'S4');
  const now = Date.now();
  const userRows = useUsers
    ? (ctx.db.prepare(`SELECT a.cidr, a.expires_at, a.user_id FROM allowed_ips a JOIN users u ON u.id = a.user_id WHERE u.status = 'active'`).all() as Array<{ cidr: string; expires_at: string; user_id: string }>)
    : [];
  const u4: string[] = [];
  const u6: string[] = [];
  for (const r of userRows) {
    const left = Math.floor((Date.parse(r.expires_at) - now) / 1000);
    if (left < 60) continue;
    const el = `${r.cidr} timeout ${left}s`;
    (r.cidr.includes(':') ? u6 : u4).push(el);
  }
  const exitHidden = s.role === 'exit' && !s.direct_access;

  const sshList = sshPorts.length ? `{ ${sshPorts.join(', ')} }` : '22';
  const lines: string[] = [];
  lines.push(
    'add table inet fleet',
    'flush table inet fleet',
    'table inet fleet {',
    `  set users4  { type ipv4_addr; flags interval, timeout;${els(u4)} }`,
    `  set users6  { type ipv6_addr; flags interval, timeout;${els(u6)} }`,
    `  set fleet4  { type ipv4_addr;${els(v4(peers))} }`,
    `  set fleet6  { type ipv6_addr;${els(v6(peers))} }`,
    `  set panel4  { type ipv4_addr;${els(v4(panel))} }`,
    `  set panel6  { type ipv6_addr;${els(v6(panel))} }`,
    `  set admin4  { type ipv4_addr;${els(v4(admin))} }`,
    `  set admin6  { type ipv6_addr;${els(v6(admin))} }`,
    `  set svc_tcp { type inet_service;${els(svcTcp)} }`,
    `  set svc_udp { type inet_service;${els(svcUdp)} }`,
    '',
    '  chain input {',
    '    type filter hook input priority 0; policy __POLICY__;',
    '    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept',
    '    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept',
    '    ct state established,related accept',
    '    ct state invalid drop',
    '    iif "lo" accept',
  );
  // служебный туннель открыт всем (protected set, §7.3): без ключа REALITY он отвечает как обычный сайт
  if (tunnel && s.mgmt_port) lines.push(`    tcp dport ${s.mgmt_port} accept`);
  if (level === 'P2') {
    lines.push(`    tcp dport ${sshList} accept`);
  } else {
    lines.push(
      `    ip  saddr @panel4 tcp dport ${sshList} accept`,
      `    ip6 saddr @panel6 tcp dport ${sshList} accept`,
      `    ip  saddr @admin4 tcp dport ${sshList} accept`,
      `    ip6 saddr @admin6 tcp dport ${sshList} accept`,
    );
  }
  lines.push(
    '    ip  saddr @fleet4 tcp dport @svc_tcp accept',
    '    ip  saddr @fleet4 udp dport @svc_udp accept',
    '    ip6 saddr @fleet6 tcp dport @svc_tcp accept',
    '    ip6 saddr @fleet6 udp dport @svc_udp accept',
    '    ip  saddr @fleet4 icmp type echo-request accept',
  );
  if (!exitHidden) {
    if (useUsers) {
      lines.push(
        '    ip  saddr @users4 tcp dport @svc_tcp accept',
        '    ip  saddr @users4 udp dport @svc_udp accept',
        '    ip6 saddr @users6 tcp dport @svc_tcp accept',
        '    ip6 saddr @users6 udp dport @svc_udp accept',
      );
    } else {
      lines.push('    tcp dport @svc_tcp accept', '    udp dport @svc_udp accept');
    }
  }
  lines.push('__TAIL__', '  }', '}');

  if (!svcTcp.length && !svcUdp.length) warnings.push('на узле нет сервисных портов: открыты будут только SSH и связь с нодами');
  if (useUsers && !u4.length && !u6.length) warnings.push('белый список пользователей пуст: до knock никто из пользователей не подключится');
  if (s.ufw_active) lint.push('на узле активен firewall хоста (ufw/firewalld) — выключите его перед применением (он перебивает разрешения nftables)');

  const body = lines.join('\n') + '\n';
  const text = body.replace('__POLICY__', 'drop').replace('__TAIL__\n', '');
  const shadow = body
    .replace('__POLICY__', 'accept')
    .replace('__TAIL__', '    counter log prefix "FLEET-WOULD-DROP " level info limit rate 10/second');

  return {
    text, shadow, lint, warnings,
    summary: { level, stealth, sshPorts, svcTcp, svcUdp, panel, admin, peers, users: u4.length + u6.length },
  };
}

export interface ChecklistItem { id: string; title: string; auto: boolean }

export const CHECKLIST: ChecklistItem[] = [
  { id: 'panel_ssh', title: 'SSH панели в новой сессии', auto: true },
  { id: 'admin_key', title: 'Вход своим ключом с вашего устройства (независимый путь)', auto: false },
  { id: 'console', title: 'Консоль хостера открывается, вход работает', auto: false },
  { id: 'breakglass', title: 'Break-glass: вход в консоль под fleetadmin, sudo fleetctl status отвечает', auto: false },
  { id: 'panel_web', title: 'Панель открывается с вашего устройства', auto: false },
  { id: 'inbounds', title: 'Каждый inbound подключается реальным клиентом из домашней и мобильной сети', auto: false },
  { id: 'subs', title: 'Подписка импортируется в клиенты', auto: false },
  { id: 'mesh', title: 'Связь с соседними нодами проходит', auto: true },
  { id: 'executor', title: 'Узел видит панель с адреса из executor.ips', auto: true },
  { id: 'snapshot', title: 'Снапшот VM у провайдера сделан', auto: false },
  { id: 'open_list', title: 'Просмотрен список того, что останется открытым', auto: false },
  { id: 'key_two_paths', title: 'Для P3: вход по ключу проверен двумя путями (панель и ваш ключ)', auto: false },
];
