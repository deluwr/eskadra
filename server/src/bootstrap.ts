/**
 * Bootstrap-сниппет (§6, шаг 1). ТОЛЬКО ДОБАВЛЯЕТ доступ: не трогает существующие ключи, пароли, порты и firewall.
 * Запускается администратором на сервере под root (консоль провайдера или существующий SSH).
 * Работает на любом Linux с systemd: Debian/Ubuntu, RHEL/Rocky/Alma/Fedora, openSUSE, Arch.
 */
export function bootstrapSnippet(opts: { panelIps: string[]; pubkey: string }): string {
  const ips = opts.panelIps.join(',');
  return `#!/usr/bin/env bash
# Fleet-UI bootstrap: ТОЛЬКО ДОБАВЛЯЕТ доступ.
set -euo pipefail

PANEL_IPS="${ips}"
PUBKEY='${opts.pubkey}'
LINE="from=\\"\${PANEL_IPS}\\",restrict,port-forwarding,permitopen=\\"127.0.0.1:10085\\" \${PUBKEY}"

# sudo есть не во всех минимальных образах
if ! command -v sudo >/dev/null || ! command -v visudo >/dev/null; then
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -y -qq install sudo
  elif command -v dnf >/dev/null; then dnf -y -q install sudo
  elif command -v yum >/dev/null; then yum -y -q install sudo
  elif command -v zypper >/dev/null; then zypper --non-interactive -q install sudo
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed sudo
  else echo "установите sudo и повторите" >&2; exit 1; fi
fi

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

echo "Fleet bootstrap OK. Host key fingerprint (сверьте с панелью):"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
`;
}
