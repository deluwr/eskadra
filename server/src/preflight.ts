export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info';

export interface Check {
  id: string;
  title: string;
  status: CheckStatus;
  detail: string;
}

export interface PreflightSummary {
  checks: Check[];
  sshPorts: number[];
  clientIp: string | null;
  os: { id: string; version: string; pretty: string } | null;
  ufwActive: boolean;
  blocking: boolean;
  externalCores: Array<{ name: string; active: string; version: string }>;
}

export function coresFrom(s: Map<string, string>) {
  return (s.get('cores') ?? '').split('\n').map((l) => {
    const m = l.match(/^name=(\S+) active=(\S*) version=(.*)$/);
    return m ? { name: m[1]!, active: m[2]!, version: m[3]!.trim() } : null;
  }).filter((x): x is { name: string; active: string; version: string } => !!x && !x.name.startsWith('eskadra-'));
}

export function parseSections(raw: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /^### (\S+)\s*$/gm;
  const marks: Array<{ name: string; start: number; end: number }> = [];
  for (let m = re.exec(raw); m; m = re.exec(raw)) marks.push({ name: m[1]!, start: m.index, end: re.lastIndex });
  marks.forEach((mk, i) => {
    const next = marks[i + 1]?.start ?? raw.length;
    out.set(mk.name, raw.slice(mk.end, next).replace(/^\n/, '').trimEnd());
  });
  return out;
}

const kv = (text: string): Record<string, string> =>
  Object.fromEntries(
    text
      .split('\n')
      .map((l) => l.match(/^([A-Za-z_]+)=(.*)$/))
      .filter((m): m is RegExpMatchArray => !!m)
      .map((m) => [m[1]!, m[2]!.replace(/^"|"$/g, '')]),
  );

/** Порты SSH — объединение sshd -T, ssh.socket и фактических листенеров (§7.3). */
export function sshPortsFrom(s: Map<string, string>): number[] {
  const ports = new Set<number>();
  for (const l of (s.get('sshd_t') ?? '').split('\n')) {
    const m = l.match(/^port (\d+)/i);
    if (m) ports.add(Number(m[1]));
  }
  for (const m of (s.get('ssh_socket') ?? '').matchAll(/:(\d+) \(Stream\)/g)) ports.add(Number(m[1]));
  for (const l of (s.get('listen') ?? '').split('\n')) {
    if (!/users:\(\("sshd"/.test(l)) continue;
    const m = l.match(/\s(?:\S*):(\d+)\s/);
    if (m) ports.add(Number(m[1]));
  }
  return [...ports].sort((a, b) => a - b);
}

export function summarize(raw: string, executorIps: string[]): PreflightSummary {
  const s = parseSections(raw);
  const checks: Check[] = [];
  const add = (id: string, title: string, status: CheckStatus, detail: string) => checks.push({ id, title, status, detail });

  const osr = kv(s.get('os') ?? '');
  const os = osr.ID ? { id: osr.ID, version: osr.VERSION_ID ?? '', pretty: osr.PRETTY_NAME ?? osr.ID } : null;
  const init = (s.get('init') ?? 'systemd').trim();
  // секций pkgmgr/init нет в выводе старого nodekit — тогда это «неизвестно», а не ошибка
  const pmSection = s.get('pkgmgr');
  const pm = (pmSection ?? '').trim();
  const pmLabel = pm ? ` · ${pm}` : '';
  const family = `${osr.ID ?? ''} ${osr.ID_LIKE ?? ''}`;
  if (!os) add('os', 'ОС', 'fail', 'не удалось прочитать /etc/os-release');
  else if (init !== 'systemd') add('os', 'ОС', 'fail', `${os.pretty}: нужен systemd (таймеры отката firewall и ядра работают через него)`);
  else if (pmSection !== undefined && !pm) add('os', 'ОС', 'fail', `${os.pretty}: не найден пакетный менеджер (apt, dnf, yum, zypper, pacman)`);
  else if ((os.id === 'ubuntu' && Number(os.version) >= 20.04) || (os.id === 'debian' && Number(os.version) >= 11))
    add('os', 'ОС', 'ok', `${os.pretty}${pmLabel}`);
  else if (/rhel|fedora|centos|rocky|almalinux|suse|arch|debian|ubuntu/.test(family))
    add('os', 'ОС', 'info', `${os.pretty}${pmLabel}: поддерживается, но не входит в тест-матрицу (Ubuntu 20.04+, Debian 11+)`);
  else add('os', 'ОС', 'warn', `${os.pretty}${pmLabel}: неизвестный дистрибутив — должно работать на любом Linux с systemd, но не проверялось`);
  const selinux = (s.get('selinux') ?? 'none').trim();
  if (selinux === 'Enforcing') add('selinux', 'SELinux', 'info', 'Enforcing: Эскадра работает в его рамках; при проблемах см. журнал audit');

  const whoami = s.get('whoami') ?? '';
  add('sudo', 'Привилегии', /uid=0\(/.test(whoami) ? 'ok' : 'fail', /uid=0\(/.test(whoami) ? 'sudo работает' : `sudo не дал root: ${whoami}`);

  const sshPorts = sshPortsFrom(s);
  const sshd = Object.fromEntries(
    (s.get('sshd_t') ?? '').split('\n').map((l) => l.trim().split(/\s+/, 2) as [string, string]).filter((p) => p[0]),
  );
  add('ssh', 'SSH', sshPorts.length ? 'ok' : 'warn',
    `порты: ${sshPorts.join(', ') || '?'}; PasswordAuthentication=${sshd.passwordauthentication ?? '?'}; PermitRootLogin=${sshd.permitrootlogin ?? '?'}`);
  const socket = s.get('ssh_socket') ?? '';
  if (/ActiveState=active/.test(socket)) add('ssh_socket', 'ssh.socket', 'info', 'socket activation включён: смена порта только по §7.6');

  const clientIp = (s.get('ssh_connection') ?? '').trim().split(/\s+/)[0] || null;
  if (clientIp) {
    const known = executorIps.includes(clientIp);
    add('egress', 'Адрес исполнителя', known ? 'ok' : 'warn',
      known ? `сервер видит панель с ${clientIp}` : `сервер видит панель с ${clientIp}, его нет в executor.ips`);
  }

  // ufw (Debian/Ubuntu) и firewalld (RHEL/Fedora/openSUSE) одинаково перебивают разрешения нашей таблицы nftables
  const ufw = s.get('ufw') ?? '';
  const fwd = (s.get('firewalld') ?? '').trim();
  const active = [/^Status: active/m.test(ufw) && 'ufw', fwd === 'running' && 'firewalld'].filter(Boolean) as string[];
  const ufwActive = active.length > 0;
  add('ufw', 'Firewall хоста', ufwActive ? 'warn' : 'ok',
    ufwActive ? `${active.join(' и ')} активен: перед P2/P3 его нужно выключить по подтверждению (§5.5)` : 'ufw и firewalld неактивны');

  const nft = s.get('nft') ?? '';
  const nftTables = [...nft.matchAll(/^table (\S+ \S+)/gm)].map((m) => m[1]);
  const ipt = (s.get('iptables') ?? '').split('\n').filter((l) => l.startsWith('-A ')).length;
  add('firewall', 'Firewall', 'info',
    `nft: ${nftTables.length ? nftTables.join(', ') : 'пусто'}; правил iptables: ${ipt}. Режим панели: observe — ничего не блокируется`);

  const listen = (s.get('listen') ?? '').split('\n').filter(Boolean);
  const busy = (port: number) => listen.filter((l) => new RegExp(`:${port}\\s`).test(l));
  const p443 = busy(443);
  const p80 = busy(80);
  add('ports', 'Порты 80/443', p443.length || p80.length ? 'warn' : 'ok',
    p443.length || p80.length ? `уже заняты: ${[...p80, ...p443].map((l) => l.replace(/\s+/g, ' ')).join(' | ')}` : 'свободны');

  if ((s.get('docker') ?? '').includes('present')) add('docker', 'Docker', 'warn', 'опубликованные порты обходят input — см. §13.3');

  const audit = (s.get('dpkg_audit') ?? '').trim();
  const lock = (s.get('dpkg_lock') ?? '').trim();
  add('apt', 'Пакеты', audit || lock === 'busy' ? 'warn' : 'ok',
    [audit && 'dpkg --audit сообщает о проблемах', lock === 'busy' && 'менеджер пакетов занят'].filter(Boolean).join('; ') || `${pm || '?'}: в порядке`);

  const disk = (s.get('disk') ?? '').trim().split(/\s+/);
  const usePct = Number((disk[4] ?? '').replace('%', ''));
  const [memTotal, memAvail] = (s.get('mem') ?? '').trim().split(/\s+/).map(Number);
  add('resources', 'Диск/RAM', usePct > 90 || (memTotal ?? 0) < 450 ? 'warn' : 'ok',
    `диск занят ${disk[4] ?? '?'}; RAM ${memTotal ?? '?'} МБ (доступно ${memAvail ?? '?'})`);

  const t = kv(s.get('time') ?? '');
  add('time', 'Время', t.NTPSynchronized === 'yes' ? 'ok' : 'warn',
    t.NTPSynchronized === 'yes' ? `синхронизировано (${t.Timezone ?? ''})` : 'NTP не синхронизирован — поставим chrony');

  const v6 = (s.get('ipv6') ?? '').split('\n').filter((l) => /inet6/.test(l));
  add('ipv6', 'IPv6', 'info', v6.length ? `есть глобальный IPv6 (${v6.length}) — фильтруем оба стека` : 'глобального IPv6 нет');

  const py = (s.get('python3') ?? '').trim();
  add('python3', 'python3', py === 'missing' ? 'warn' : 'ok', py === 'missing' ? 'нет — установится вместе с nodekit' : py);

  add('provider_fw', 'Файрвол провайдера', 'info', 'с хоста не виден: проверьте вручную или подключите API провайдера (§7.12.3)');

  const externalCores = coresFrom(s);
  const xui = externalCores.find((c) => c.name === '3x-ui');
  if (xui) add('cores', 'Ядра', 'info', xui.active === 'active'
    ? `найден 3x-ui ${xui.version}: Эскадра будет добавлять свои inbounds в его Xray, второй Xray не запускается`
    : `найдены остатки 3x-ui (служба ${xui.active || 'не запущена'}): 3x-ui не работает — Эскадра поставит свой Xray`);
  else if (externalCores.length) add('cores', 'Ядра', 'warn', `уже работают: ${externalCores.map((c) => `${c.name} (${c.active})`).join(', ')} — Эскадра не запустит второе ядро того же типа`);
  else add('cores', 'Ядра', 'ok', 'сторонних VPN-ядер нет');

  const blocking = checks.some((c) => c.status === 'fail');
  return { checks, sshPorts, clientIp, os, ufwActive, blocking, externalCores };
}
