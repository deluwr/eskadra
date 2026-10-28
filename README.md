# Eskadra

**English** · [Русский](README.ru.md)

A control panel for a personal fleet of VPN servers. One main server manages nodes in different countries over SSH, rolls out Xray / sing-box configurations, keeps users and subscriptions, and maintains allowlists and host protection — so that no block can cut you off from your own servers.

> Status: early version (beta). Read "Current limitations" before using it in production.

## Installing the main server

On any Linux with systemd, as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/deluwr/eskadra/main/scripts/install.sh)
```

The installer:

- installs Node.js from the official builds and the Eskadra release from GitHub (both downloads are verified by SHA-256);
- runs the panel as a dedicated `eskadra` user under systemd;
- picks a **random port** and a **random secret path** for the panel;
- issues a **Let's Encrypt** certificate before the panel's first start: for the server's IP (no domain needed, 6-day certificate, renews itself) or for a domain. There are no self-signed certificates: if issuance fails, the installation stops with the reason, and re-running it resumes from that point;
- installs Python ≥ 3.9 with venv (if missing or too old) and certbot;
- if **3x-ui** is already on the server, asks whether to extend it (Eskadra puts its inbounds into 3x-ui's Xray) or remove it (with a database backup); standalone xray / sing-box can be kept or stopped;
- picks a random port for the subscription service;
- if ufw is enabled, opens only these two ports in it;
- prints a one-time link for creating the owner account.

Running the same command again updates the panel and keeps your data (`/var/lib/eskadra`) and settings (`/etc/eskadra`). If an installation was interrupted (for example, SSH dropped), re-running continues the initial setup from where it stopped; all output is written to `/var/log/eskadra-install.log`.

Unattended: `ESKADRA_TLS=ip|domain`, `ESKADRA_DOMAIN=…`, `ESKADRA_XUI=keep|remove` (choosing Let's Encrypt means you accept its terms).

**Let's Encrypt.** certbot ≥ 5.4 is installed into its own environment (`/opt/eskadra/certbot`) and keeps the certificate in its own directory `/etc/eskadra/letsencrypt` — the system certbot and other sites' certificates on the server are not touched. Issuance uses HTTP-01: port 80 is opened in ufw only while issuing and renewing; if another service occupies it, the installer asks whether it may stop that service for ~30 s. Renewal runs from the `eskadra-certbot.timer` twice a day, and the panel picks up the new certificate without a restart. With a Let's Encrypt certificate, subscriptions are also served over HTTPS.

## Supported systems

Main server and nodes — any Linux with **systemd** and **glibc ≥ 2.28**, on amd64 or arm64:

| Family | Package manager | Status |
|---|---|---|
| Ubuntu 20.04+, Debian 11+ | apt | tested (Ubuntu 22.04 / 24.04) |
| RHEL 8+, Rocky, AlmaLinux, CentOS Stream, Fedora | dnf / yum | supported |
| openSUSE Leap / Tumbleweed | zypper | supported |
| Arch Linux | pacman | supported |
| Alpine (musl, OpenRC) | — | not supported: no systemd, Node.js is built for glibc |

What is taken into account: package names across distributions, the host firewall (ufw or firewalld), the SSH service name (`ssh` or `sshd`), enabling `sshd_config.d` and `sudoers.d` where they are disabled, the admin group (`sudo` or `wheel`), SELinux, Python 3.6 on RHEL 8 (Python ≥ 3.9 is installed for certbot).

## Terminal management

```bash
eskadra
```

An interactive numbered menu: **fleet** — overview, servers, users, configurations, cores, backups, audit (with drill-down: server → check, preflight, nodekit, temporarily open SSH, update core…; user → subscription, links, limits, disable…), and **panel** — address, certificate, ports, path, passwords, 3x-ui, update. The fleet sections work through the panel's API under a console session: the permissions and audit are the same as in the web interface. Commands without the menu:

| Command | What it does |
|---|---|
| `eskadra fleet [section]` | interactive fleet management (servers, users, configs, cores…) |
| `eskadra url` | panel address (or the one-time owner-creation link) |
| `eskadra status` | state, ports, number of servers and users |
| `eskadra port [N\|random]` | change the panel port (ufw is updated) |
| `eskadra path [name]` | change the panel's secret path |
| `eskadra sub-port [N\|random]` | change the subscription port |
| `eskadra reset-password [login]` | new administrator password |
| `eskadra disable-2fa <login>` | disable 2FA if the authenticator is lost |
| `eskadra backup` | make a backup now |
| `eskadra cert letsencrypt [ip / domain <domain>]` | issue a Let's Encrypt certificate |
| `eskadra conflicts` | 3x-ui / xray / sing-box on this server: extend or remove |
| `eskadra update [version]` | update |
| `eskadra uninstall [--purge]` | remove the program (data is kept) or everything — database, keys, certificate and firewall ports |

## Connecting nodes

**Servers → Add server**: address, role (entry or exit), login (usually root), and a password or your SSH key. The panel does the rest: it connects, adds its key, pins the server's host key, checks the system and installs the helper scripts (sudo is narrowed to a single wrapper). The password is used once and is never stored. If the main server has no direct SSH access, the same setup can be run as a command on the server itself — it is shown in the server card.

The **management channel** is chosen when adding a node:

- **direct over SSH** — the main server is outside Russia;
- **through a tunnel** — the main server is in Russia: the panel's SSH runs inside VLESS-REALITY (ordinary HTTPS to the DPI), and a separate Xray `fleet-mgmt` is installed on the node on a random TCP port; if your hosting provider has its own firewall, open this port. The node lets the panel in by the tunnel key, not by IP.

**Initial access through a proxy.** To set up the tunnel, the panel has to reach the server once. If SSH from Russia to the server is blocked, choose "Initial access" in the connect form: through a fleet configuration (for example, an exit abroad — the panel goes in via the service client `svc.mgmt`) or through your own `vless://` / `trojan://` / `vmess://` / `ss://` link or JSON outbound. The panel starts a separate Xray process that forwards `127.0.0.1 → proxy → server:SSH` only for the duration of the connection; the link is not stored. The same is available in the bot (`/addserver`).

**Main server as an entry.** The button on the "Servers" page turns the server running the panel into an entry for users (for example, entry in Russia → exits abroad). The panel and subscription ports stay open.

Roles and the order of actions are described in the "Help" section of the panel itself.

## Configurations

**Configurations → New configuration**: protocol, port, security, servers and (optionally) an entry.

| Protocol | Core | Security | Transports |
|---|---|---|---|
| VLESS | Xray | REALITY · TLS · none | TCP, WebSocket, gRPC, XHTTP, HTTPUpgrade |
| VMess | Xray | TLS · none | TCP, WebSocket, gRPC, HTTPUpgrade |
| Trojan | Xray | TLS · REALITY | TCP, WebSocket, gRPC, HTTPUpgrade |
| Shadowsocks-2022 | Xray | — | TCP |
| Hysteria2 | sing-box | TLS (QUIC) | — |
| MTProto (Telegram) | telemt | fake-TLS | — |

**TLS certificate:** Let's Encrypt for the server's IP (the default; issued and renewed on the server itself — a timer twice a day; port 80 is needed while issuing and renewing; the panel checks expiry dates and the renewal result every 3 hours, warns in "Needs attention" and in the bot on failure, and there is a "Renew now" button on the "Host" tab), your own domain on each server, or an uploaded certificate — for example, a wildcard for a shared domain. Transport, path, ALPN, fingerprint and the rest are under "Advanced". MTProto is issued as a separate `tg://` link (it is not included in the VPN subscription).

**Entry and "Auto".** If a configuration has an entry, the subscription gets an "entry → auto" profile. How it picks the exit is set per configuration:

- **by quality** — an exit that passes the latency and speed thresholds (100 ms and 10 Mbit/s by default); it is kept while it passes, otherwise the fastest suitable one is chosen;
- **in order** — a list of exits that you set: traffic goes through the first one that passes the thresholds, and returns to it when it recovers;
- **random** — any exit for each connection.

The entry checks latency itself once a minute, and the panel measures speed on a schedule; switching does not drop connections, and the bot notifies admins about every switch.

## Telegram bot

The bot answers only linked people and only in private chats; to a stranger on `/start` it shows only their own Telegram ID — no panel name, no logins, no servers. Linking is done with the "Link" button in "Access and roles" and in the user card: the panel issues a one-time bot link (valid for 15 minutes), and the person presses "Start". All management is done with buttons under the message:

- owner, admin and operator: users — add by Telegram ID (`/adduser name 123456789`), subscription and individual links, which configurations go into the subscription, enable/disable; deleting is for admin and owner;
- servers: state, protection level, enable/disable cores; connect a new one by login and password or key (`/addserver`, admin and owner) — the bot deletes the message with the password right after reading it;
- "Needs attention", "Auto" exits with a check, backup (owner and admin);
- notifications: each admin chooses their own (`/notify` or "Access and roles" → "My notifications"); VPN users do not receive such messages;
- user: `/sub` — subscription, `/links` — profile links, traffic for the month, opening access from a new address (if the allowlist is on);
- `/help` — commands for your role.

**Subscription page.** A subscription link opened in a browser shows a page: a QR code and buttons for apps, expiry, traffic and limits, available nodes, individual links with QR codes. Apps get the subscription from the same link as before.

**Updating and restoring from the panel.** The "Update" button at the bottom of the menu (owner) runs `eskadra update` through a root helper and shows the log; the helper is installed by an update from the console, so the first time after v0.15 update with the `eskadra update` command. "Backups" has a restore: the backup file and the backup password → check and summary → data swap and panel restart (the previous files stay on the server). "Settings" → "Move the panel to another server" moves the panel with all data to a new host over SSH (same version, port and URL path).

**Already installed cores.** Preflight finds 3x-ui, xray, sing-box, etc.:

- if a node has **3x-ui**, Eskadra does not start a second Xray but adds its own inbounds (marked `eskadra-…`) to 3x-ui's Xray through its API. The 3x-ui login and password are entered once on the "Host" tab and stored encrypted; 3x-ui's own inbounds are left alone;
- if another core of the same kind is running, Eskadra does not install its own and explains why.

## Updating cores

**Configurations → Cores**: Xray and sing-box versions on each node, the latest releases from GitHub, pinning a version for new nodes.

- Updating on a node is safe: the new version is installed next to the old one, the current config is checked with the new binary, then it switches over and restarts. If the core does not start or the inbound ports stop listening, the node returns to the previous version by itself. The current and previous versions are kept, and there is a manual rollback.
- "Update all nodes" works in waves: canary first, then the rest one by one; the first error stops the rollout.
- Every 6 hours the panel checks for new releases and notifies the Telegram bot once per version.
- A node's Xray with 3x-ui belongs to 3x-ui and is updated there; Eskadra shows its version.

## Security (in brief)

- A key per server, manual host-key verification (no trust on first use), `from=` and a strict mode for the panel's key.
- Firewall blocks are applied only after a manual checklist — first in shadow mode, then under a rollback timer that runs on the node itself.
- Emergency access: "temporarily open SSH", emergency lifting of blocks, a short command for the hosting provider's KVM console (`sudo fleetctl allow 1 2 3 4`).
- Secrets in the database are encrypted with a master key; backups are encrypted with a backup password and sent by the bot to the Telegram IDs from the settings.
- Roles owner / admin / operator, TOTP 2FA, an audit log with a hash chain.

Detailed architecture (in Russian) — [`eskadra-architecture.md`](eskadra-architecture.md).

## Current limitations

- The management channel is fixed per node: there is no automatic switching between the tunnel and direct SSH yet (see the architecture, §4.3).
- No integration with hosting providers' firewall APIs; no interactive terminal (only individual commands under audit).
- The device limit is displayed but is not enforced on 3x-ui nodes; sing-box traffic statistics are not collected.
- The "universal entry" (relay) is not available on nodes in 3x-ui mode.

## Development

Requires Node.js 24.

```bash
npm install
npm run build -w web
npm run dev          # panel at http://127.0.0.1:7070
npm test
```

Layout: `server/` — API, SSH executor, workers (TypeScript, Fastify, built-in SQLite); `web/` — the interface (React + Vite); `nodekit/` — scripts installed on nodes; `scripts/` — the installer, the `eskadra` menu, release build.

## Making a release

A release is built by GitHub Actions on a tag:

```bash
git tag v0.4.0
git push origin v0.4.0
```

The workflow `.github/workflows/release.yml` runs the tests, builds `eskadra.tar.gz` with a checksum and publishes them to Releases — that is where the installer fetches them from.

## License

[GNU GPL v3](LICENSE).
