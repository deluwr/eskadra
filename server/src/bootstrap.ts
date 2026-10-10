/**
 * Bootstrap-сниппет (§6, шаг 1). ТОЛЬКО ДОБАВЛЯЕТ доступ: не трогает существующие ключи, пароли, порты и firewall.
 * Запускается администратором на сервере под root (консоль провайдера или существующий SSH).
 * Работает на любом Linux с systemd: Debian/Ubuntu, RHEL/Rocky/Alma/Fedora, openSUSE, Arch.
 *
 * В режиме служебного туннеля (§5.8) сниппет ещё ставит на узле отдельный Xray (fleet-mgmt), через который
 * панель приходит к SSH узла. Всё делается локально: панель до узла, возможно, не дотягивается.
 */
import { nodeConfig, type TunnelCreds, type XrayPin } from './mgmt.js';

export interface SnippetMgmt { creds: TunnelCreds; sshPort: number; xray: XrayPin }

export function bootstrapSnippet(opts: { panelIps: string[]; pubkey: string; mgmt?: SnippetMgmt }): string {
  // через туннель SSH панели приходит на узел с 127.0.0.1 (freedom → 127.0.0.1:ssh), поэтому он — в from=
  const ips = (opts.mgmt ? ['127.0.0.1', ...opts.panelIps] : opts.panelIps).join(',');
  return `#!/usr/bin/env bash
# Fleet-UI bootstrap: ТОЛЬКО ДОБАВЛЯЕТ доступ.
set -euo pipefail

PANEL_IPS="${ips}"
PUBKEY='${opts.pubkey}'
LINE="from=\\"\${PANEL_IPS}\\",restrict,port-forwarding,permitopen=\\"127.0.0.1:10085\\" \${PUBKEY}"

pkg_get() {  # установить пакеты менеджером системы
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
    apt-get -qq update && apt-get -y -qq install "$@" >/dev/null
  elif command -v dnf >/dev/null; then dnf -y -q install "$@"
  elif command -v yum >/dev/null; then yum -y -q install "$@"
  elif command -v zypper >/dev/null; then zypper --non-interactive -q install "$@"
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed "$@" >/dev/null
  else echo "установите $* и повторите" >&2; exit 1; fi
}

# sudo есть не во всех минимальных образах
if ! command -v sudo >/dev/null || ! command -v visudo >/dev/null; then pkg_get sudo; fi

install -d -m 755 /etc/fleet
tr ',' '\\n' <<< "$PANEL_IPS" > /etc/fleet/panel-ips

id fleet &>/dev/null || useradd --create-home --shell /bin/bash fleet
usermod -p '*' fleet
install -d -m 700 -o fleet -g fleet /home/fleet/.ssh
touch /home/fleet/.ssh/authorized_keys
grep -qxF "$LINE" /home/fleet/.ssh/authorized_keys || echo "$LINE" >> /home/fleet/.ssh/authorized_keys
chown fleet:fleet /home/fleet/.ssh/authorized_keys
chmod 600 /home/fleet/.ssh/authorized_keys
command -v restorecon >/dev/null && restorecon -R /home/fleet/.ssh || true   # SELinux (RHEL/Fedora)

# каталог /etc/sudoers.d подключён не везде (например, в Arch по умолчанию закомментирован)
install -d -m 750 /etc/sudoers.d
if ! grep -Eq '^(#|@)includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers; then
  cp -a /etc/sudoers /etc/sudoers.fleet-bak
  echo '#includedir /etc/sudoers.d' >> /etc/sudoers
  visudo -c >/dev/null || { mv /etc/sudoers.fleet-bak /etc/sudoers; echo "не удалось подключить /etc/sudoers.d" >&2; exit 1; }
fi

echo 'fleet ALL=(root) NOPASSWD:ALL' > /etc/sudoers.d/90-fleet-bootstrap
chmod 440 /etc/sudoers.d/90-fleet-bootstrap
visudo -cf /etc/sudoers.d/90-fleet-bootstrap || { rm -f /etc/sudoers.d/90-fleet-bootstrap; echo "sudoers invalid, removed" >&2; exit 1; }
${opts.mgmt ? tunnelPart(opts.mgmt) : ''}
echo "Fleet bootstrap OK. Host key fingerprint (сверьте с панелью):"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
`;
}

/** Служебный Xray на узле: свой бинарник (проверка SHA-256 из панели), конфиг, юнит, порт в зарезервированных. */
function tunnelPart(m: SnippetMgmt): string {
  const cfg = JSON.stringify(nodeConfig(m.creds, m.sshPort), null, 2);
  return `
# ── служебный туннель управления (VLESS-REALITY, §5.8) ──
MGMT_PORT=${m.creds.port}
XRAY_VER=${m.xray.version}
case "$(uname -m)" in
  x86_64) XRAY_ZIP=Xray-linux-64.zip; XRAY_SHA=${m.xray.sha.amd64} ;;
  aarch64|arm64) XRAY_ZIP=Xray-linux-arm64-v8a.zip; XRAY_SHA=${m.xray.sha.arm64} ;;
  *) echo "архитектура $(uname -m) не поддерживается" >&2; exit 1 ;;
esac
for c in curl unzip sha256sum; do command -v "$c" >/dev/null || pkg_get "$c"; done

id fleet-mgmt &>/dev/null || useradd --system --no-create-home --shell "$(command -v nologin || echo /bin/false)" fleet-mgmt
install -d -m 755 /usr/local/lib/fleet-mgmt
install -d -m 750 -o root -g fleet-mgmt /etc/fleet/mgmt
if ! /usr/local/lib/fleet-mgmt/xray version 2>/dev/null | grep -q "^Xray $XRAY_VER "; then
  tmp="$(mktemp -d)"
  curl -fsSL --retry 3 --max-time 300 -o "$tmp/x.zip" "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/$XRAY_ZIP"
  echo "$XRAY_SHA  $tmp/x.zip" | sha256sum -c --quiet - || { rm -rf "$tmp"; echo "SHA-256 архива Xray не совпал" >&2; exit 1; }
  unzip -o -q "$tmp/x.zip" xray -d "$tmp"
  install -m 755 "$tmp/xray" /usr/local/lib/fleet-mgmt/xray.new
  mv /usr/local/lib/fleet-mgmt/xray.new /usr/local/lib/fleet-mgmt/xray
  rm -rf "$tmp"
fi

cat > /etc/fleet/mgmt/config.json.new <<'MGMT_EOF'
${cfg}
MGMT_EOF
chown root:fleet-mgmt /etc/fleet/mgmt/config.json.new
chmod 640 /etc/fleet/mgmt/config.json.new
/usr/local/lib/fleet-mgmt/xray run -test -c /etc/fleet/mgmt/config.json.new >/dev/null || { echo "конфиг туннеля не прошёл проверку Xray" >&2; exit 1; }
mv /etc/fleet/mgmt/config.json.new /etc/fleet/mgmt/config.json

cat > /etc/systemd/system/fleet-mgmt.service <<'UNIT_EOF'
[Unit]
Description=Fleet management tunnel (Eskadra)
After=network-online.target
Wants=network-online.target

[Service]
User=fleet-mgmt
Group=fleet-mgmt
ExecStart=/usr/local/lib/fleet-mgmt/xray run -c /etc/fleet/mgmt/config.json
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
systemctl enable fleet-mgmt >/dev/null 2>&1
systemctl restart fleet-mgmt

# порт туннеля — в зарезервированные: на него не встанет пользовательский inbound
touch /etc/fleet/reserved-ports
grep -qx 10085 /etc/fleet/reserved-ports || echo 10085 >> /etc/fleet/reserved-ports
grep -qx "$MGMT_PORT" /etc/fleet/reserved-ports || echo "$MGMT_PORT" >> /etc/fleet/reserved-ports

# firewall хоста, если он включён: только добавляем разрешение для порта туннеля
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "$MGMT_PORT/tcp" comment 'fleet mgmt tunnel' >/dev/null
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port="$MGMT_PORT/tcp" && firewall-cmd -q --reload
fi

sleep 1
systemctl is-active --quiet fleet-mgmt || { journalctl -u fleet-mgmt -n 20 --no-pager; echo "служба туннеля fleet-mgmt не запустилась" >&2; exit 1; }
echo "Туннель управления слушает порт $MGMT_PORT/tcp. Если у хостера есть свой firewall — откройте в нём этот порт."
`;
}
