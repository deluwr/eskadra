import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';
import { sha256hex } from './lib/crypto.js';

interface KitFile {
  src: string | null;
  dest: string;
  mode: string;
  content?: string;
}

/** sudoers: одна обёртка; SSH_CONNECTION пробрасывается, чтобы preflight видел адрес панели. */
export const SUDOERS_90 =
  'Defaults:fleet env_keep += "SSH_CONNECTION"\nfleet ALL=(root) NOPASSWD: /usr/local/sbin/fleet-exec\n';

const FILES: KitFile[] = [
  { src: 'sbin/fleet-exec', dest: '/usr/local/sbin/fleet-exec', mode: '0755' },
  { src: 'sbin/fleetctl', dest: '/usr/local/sbin/fleetctl', mode: '0755' },
  { src: 'sbin/fleet-preflight', dest: '/usr/local/sbin/fleet-preflight', mode: '0755' },
  { src: 'sbin/fleet-baseline', dest: '/usr/local/sbin/fleet-baseline', mode: '0755' },
  { src: 'sbin/fleet-fw-apply', dest: '/usr/local/sbin/fleet-fw-apply', mode: '0755' },
  { src: 'sbin/fleet-fw-rollback', dest: '/usr/local/sbin/fleet-fw-rollback', mode: '0755' },
  { src: 'sbin/fleet-fw-confirm', dest: '/usr/local/sbin/fleet-fw-confirm', mode: '0755' },
  { src: 'sbin/fleet-core', dest: '/usr/local/sbin/fleet-core', mode: '0755' },
  { src: 'sbin/fleet-gate', dest: '/usr/local/sbin/fleet-gate', mode: '0755' },
  { src: 'sbin/fleet-kit-install', dest: '/usr/local/sbin/fleet-kit-install', mode: '0755' },
  { src: 'sbin/fleet-sshd-harden', dest: '/usr/local/sbin/fleet-sshd-harden', mode: '0755' },
  { src: 'sbin/fleet-xui', dest: '/usr/local/sbin/fleet-xui', mode: '0755' },
  { src: 'systemd/fleet-fw.service', dest: '/etc/systemd/system/fleet-fw.service', mode: '0644' },
  { src: null, dest: '/etc/sudoers.d/90-fleet', mode: '0440', content: SUDOERS_90 },
];

/** Скрипты читаются с диска и нормализуются к LF (репозиторий может лежать на Windows). */
export function readKitFile(rel: string): string {
  return fs.readFileSync(path.join(config.nodekitDir, rel), 'utf8').replace(/\r\n/g, '\n');
}

const contentOf = (f: KitFile) => f.content ?? readKitFile(f.src!);

export function kitVersion(): string {
  return sha256hex(FILES.map((f) => f.dest + '\n' + contentOf(f)).join('\n\0')).slice(0, 12);
}

/** Первичная установка через широкий bootstrap-sudo (шаг 3): файлы в base64 через stdin, атомарно. */
export function buildInstallScript(): string {
  const version = kitVersion();
  const parts = [
    'set -euo pipefail',
    'install -d -m 755 /usr/local/lib/fleet /etc/fleet /etc/fleet/state',
    'install -d -m 700 /var/lib/fleet /var/lib/fleet/staging /var/lib/fleet/fw',
    'export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a',
    // любой Linux с systemd: пакеты — менеджером системы (apt/dnf/yum/zypper/pacman)
    'need=""; for p in python3:python3:python nft:nftables:nftables curl:curl:curl openssl:openssl:openssl; do',
    '  IFS=: read -r c gen arch <<< "$p"; command -v "$c" >/dev/null && continue',
    '  if command -v pacman >/dev/null; then need="$need $arch"; else need="$need $gen"; fi',
    'done',
    'if [ -n "$need" ]; then',
    '  if command -v apt-get >/dev/null; then apt-get -o DPkg::Lock::Timeout=600 update -qq && apt-get -o DPkg::Lock::Timeout=600 install -y -qq $need >/dev/null',
    '  elif command -v dnf >/dev/null; then dnf install -y -q $need >/dev/null',
    '  elif command -v yum >/dev/null; then yum install -y -q $need >/dev/null',
    '  elif command -v zypper >/dev/null; then zypper --non-interactive --quiet install $need >/dev/null',
    '  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed $need >/dev/null',
    '  else echo "нет пакетного менеджера, установите вручную:$need" >&2; exit 1; fi',
    'fi',
  ];
  for (const f of FILES) {
    if (f.dest.startsWith('/etc/sudoers.d/')) continue; // sudoers сужается отдельным шагом с проверкой
    const b64 = Buffer.from(contentOf(f), 'utf8').toString('base64').replace(/(.{76})/g, '$1\n');
    parts.push(
      `base64 -d > '${f.dest}.new' <<'FLEET_B64'\n${b64}\nFLEET_B64`,
      `chmod ${f.mode} '${f.dest}.new' && chown root:root '${f.dest}.new' && mv '${f.dest}.new' '${f.dest}'`,
    );
  }
  parts.push(
    `[ -s /etc/fleet/reserved-ports ] || echo '10085' > /etc/fleet/reserved-ports`,
    `echo '${version}' > /usr/local/lib/fleet/VERSION`,
    'systemctl daemon-reload',
    `echo "nodekit ${version} installed"`,
  );
  return parts.join('\n') + '\n';
}

/** Обновление уже суженного узла: JSON-пакет для fleet-exec kit-install (пути проверяет сам узел). */
export function buildKitBundle(): string {
  return JSON.stringify({
    version: kitVersion(),
    files: FILES.map((f) => ({ dest: f.dest, mode: f.mode, b64: Buffer.from(contentOf(f), 'utf8').toString('base64') })),
  });
}

/** Сужение sudo до одной обёртки (шаг 3.3): сначала новый файл, проверка — и только потом удаление широкого. */
export const SUDO_NARROW_WRITE = [
  'set -euo pipefail',
  `cat > /etc/sudoers.d/90-fleet.new <<'EOF'\n${SUDOERS_90}EOF`,
  'chmod 440 /etc/sudoers.d/90-fleet.new',
  'visudo -cf /etc/sudoers.d/90-fleet.new',
  'mv /etc/sudoers.d/90-fleet.new /etc/sudoers.d/90-fleet',
  'echo written',
].join('\n') + '\n';

export const SUDO_DROP_BOOTSTRAP = 'rm -f /etc/sudoers.d/90-fleet-bootstrap && echo dropped\n';
