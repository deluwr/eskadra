/**
 * Bootstrap-сниппет (§6, шаг 1). ТОЛЬКО ДОБАВЛЯЕТ доступ: не трогает существующие ключи, пароли, порты и firewall.
 * Запускается администратором на сервере под root (консоль провайдера или существующий SSH).
 */
export function bootstrapSnippet(opts: { panelIps: string[]; pubkey: string }): string {
  const ips = opts.panelIps.join(',');
  return `#!/usr/bin/env bash
# Fleet-UI bootstrap: ТОЛЬКО ДОБАВЛЯЕТ доступ.
set -euo pipefail

PANEL_IPS="${ips}"
PUBKEY='${opts.pubkey}'
LINE="from=\\"\${PANEL_IPS}\\",restrict,port-forwarding,permitopen=\\"127.0.0.1:10085\\" \${PUBKEY}"
install -d -m 755 /etc/fleet
tr ',' '\\n' <<< "$PANEL_IPS" > /etc/fleet/panel-ips

id fleet &>/dev/null || useradd --create-home --shell /bin/bash fleet
usermod -p '*' fleet
install -d -m 700 -o fleet -g fleet /home/fleet/.ssh
touch /home/fleet/.ssh/authorized_keys
grep -qxF "$LINE" /home/fleet/.ssh/authorized_keys || echo "$LINE" >> /home/fleet/.ssh/authorized_keys
chown fleet:fleet /home/fleet/.ssh/authorized_keys
chmod 600 /home/fleet/.ssh/authorized_keys

echo 'fleet ALL=(root) NOPASSWD:ALL' > /etc/sudoers.d/90-fleet-bootstrap
chmod 440 /etc/sudoers.d/90-fleet-bootstrap
visudo -cf /etc/sudoers.d/90-fleet-bootstrap || { rm -f /etc/sudoers.d/90-fleet-bootstrap; echo "sudoers invalid, removed" >&2; exit 1; }

echo "Fleet bootstrap OK. Host key fingerprint (сверьте с панелью):"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
`;
}
