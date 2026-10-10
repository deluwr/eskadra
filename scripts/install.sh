#!/usr/bin/env bash
# Эскадра — установка главного сервера одной командой:
#   bash <(curl -fsSL https://raw.githubusercontent.com/deluwr/eskadra/main/scripts/install.sh)
# Повторный запуск обновляет панель, сохраняя данные и настройки.
#
# Переменные (необязательно):
#   ESKADRA_REPO=deluwr/eskadra  откуда брать релизы
#   ESKADRA_VERSION=v0.4.0       конкретная версия (по умолчанию — последняя)
#   ESKADRA_PORT=…               порт панели (по умолчанию — случайный)
#   ESKADRA_NODE_MAJOR=24        мажорная версия Node.js
#   ESKADRA_TLS=ip|domain        сертификат Let's Encrypt без вопроса (это согласие с условиями Let's Encrypt)
#   ESKADRA_DOMAIN=panel.example  домен для ESKADRA_TLS=domain
#   ESKADRA_XUI=keep|remove      что делать с найденным 3x-ui без вопроса
set -Eeuo pipefail

REPO="${ESKADRA_REPO:-deluwr/eskadra}"
ESK_VERSION="${ESKADRA_VERSION:-latest}"
NODE_MAJOR="${ESKADRA_NODE_MAJOR:-24}"
PREFIX=/opt/eskadra
DATA=/var/lib/eskadra
ETC=/etc/eskadra
ENVF="$ETC/eskadra.env"

c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
say()  { printf '%s\n' "${c_b}==>${c_0} $*"; }
warn() { printf '%s\n' "${c_warn}!${c_0} $*" >&2; }
die()  { printf '%s\n' "${c_err}✗ $*${c_0}" >&2; exit 1; }

trap 'die "ошибка в строке $LINENO: $BASH_COMMAND"' ERR   # без этого set -e обрывает установку молча

[ "$(id -u)" -eq 0 ] || die "запустите под root (sudo -i)"
# весь вывод дублируется в лог: если SSH оборвётся, видно, где остановилась установка
LOG=/var/log/eskadra-install.log
exec > >(tee -a "$LOG") 2>&1
printf '\n── %s ──\n' "$(date '+%F %T')" >> "$LOG"
# данные ОС читаем в подоболочке: os-release определяет свои VERSION, NAME, ID и затёр бы переменные установщика
OS_ID="$( [ -r /etc/os-release ] && . /etc/os-release; echo "${ID:-}" )"
OS_NAME="$( [ -r /etc/os-release ] && . /etc/os-release; echo "${PRETTY_NAME:-неизвестная ОС}" )"
case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) die "архитектура $(uname -m) не поддерживается" ;; esac
[[ "$REPO" == */* && "$REPO" != *__* ]] || die "задайте репозиторий: ESKADRA_REPO=owner/eskadra"

# ── Совместимость: любой Linux с systemd и glibc ≥ 2.28 ──────────────────────
# Проверено на Ubuntu 22.04/24.04 и Debian 12; работает на Debian/Ubuntu, RHEL/Rocky/Alma/Fedora,
# openSUSE и Arch. Alpine (musl, OpenRC) не поддерживается: официальные сборки Node.js — под glibc.
[ -d /run/systemd/system ] || die "нужен systemd (у вас $OS_NAME без systemd)"
GLIBC="$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+$' || true)"
if [ -z "$GLIBC" ]; then die "не найдена glibc (musl/Alpine не поддерживается: Node.js собирается под glibc)"; fi
awk -v v="$GLIBC" 'BEGIN { split(v, a, "."); exit !(a[1] > 2 || (a[1] == 2 && a[2] >= 28)) }' \
  || die "glibc $GLIBC слишком старая для Node.js $NODE_MAJOR (нужна ≥ 2.28; это Ubuntu 20.04+, Debian 10+, RHEL 8+)"

if   command -v apt-get >/dev/null; then PM=apt
elif command -v dnf     >/dev/null; then PM=dnf
elif command -v yum     >/dev/null; then PM=yum
elif command -v zypper  >/dev/null; then PM=zypper
elif command -v pacman  >/dev/null; then PM=pacman
else die "не найден поддерживаемый менеджер пакетов (apt, dnf, yum, zypper, pacman)"; fi
case "$OS_ID" in ubuntu|debian) ;; *) warn "$OS_NAME: не входит в тест-матрицу (Ubuntu/Debian), ставлю через $PM" ;; esac

apt_wait() {  # на свежем VPS apt часто занят автообновлением: ждём с сообщением, а не молча
  local n=0
  command -v fuser >/dev/null || return 0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
    [ "$n" = 0 ] && echo "  apt занят (обычно автообновление системы после запуска VPS) — жду, до 10 минут…"
    n=$((n + 1)); [ "$n" -ge 120 ] && break; sleep 5
  done
}

# pkg_install <команда:пакет-apt:пакет-rpm:пакет-pacman> … — ставит только то, чего нет
pkg_install() {
  local need=() spec cmd deb rpm arch
  for spec in "$@"; do
    IFS=: read -r cmd deb rpm arch <<< "$spec"
    command -v "$cmd" >/dev/null && continue
    case "$PM" in apt) need+=("$deb") ;; dnf|yum|zypper) need+=("$rpm") ;; pacman) need+=("${arch:-$rpm}") ;; esac
  done
  [ ${#need[@]} -gt 0 ] || return 0
  case "$PM" in
    apt)    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1; apt_wait
            apt-get -o DPkg::Lock::Timeout=600 update -qq && apt-get -o DPkg::Lock::Timeout=600 install -y -qq "${need[@]}" >/dev/null ;;
    dnf)    dnf install -y -q "${need[@]}" >/dev/null ;;
    yum)    yum install -y -q "${need[@]}" >/dev/null ;;
    zypper) zypper --non-interactive --quiet install "${need[@]}" >/dev/null ;;
    pacman) pacman -Sy --noconfirm --needed "${need[@]}" >/dev/null ;;
  esac
}

say "Пакеты ($PM)"
pkg_install curl:curl:curl openssl:openssl:openssl xz:xz-utils:xz tar:tar:tar ss:iproute2:iproute:iproute2 \
  python3:python3:python3:python sha256sum:coreutils:coreutils useradd:passwd:shadow-utils:shadow

fetch() { curl -fsSL --retry 3 --max-time 600 "$@"; }

# ── Node.js из официальных сборок, с проверкой SHA256 ───────────────────────
install_node() {
  local shas file sum tmp
  shas="$(fetch "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/SHASUMS256.txt")" || die "не удалось получить список Node.js"
  file="$(printf '%s\n' "$shas" | awk -v a="linux-$ARCH.tar.xz" '$2 ~ a"$" {print $2; exit}')"
  sum="$(printf '%s\n' "$shas" | awk -v f="$file" '$2==f {print $1}')"
  [ -n "$file" ] && [ -n "$sum" ] || die "нет сборки Node.js для linux-$ARCH"
  if [ -x "$PREFIX/node/bin/node" ] && [ "$(cat "$PREFIX/node/.release" 2>/dev/null)" = "$file" ]; then return; fi
  say "Node.js ${file%%-linux*}"
  tmp="$(mktemp -d)"
  fetch -o "$tmp/$file" "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/$file"
  echo "$sum  $tmp/$file" | sha256sum -c --quiet - || die "SHA256 Node.js не совпал"
  rm -rf "$PREFIX/node.new"; mkdir -p "$PREFIX/node.new"
  tar -xJf "$tmp/$file" -C "$PREFIX/node.new" --strip-components=1
  echo "$file" > "$PREFIX/node.new/.release"
  rm -rf "$PREFIX/node"; mv "$PREFIX/node.new" "$PREFIX/node"; rm -rf "$tmp"
}

# ── Релиз Эскадры с GitHub, с проверкой SHA256 ──────────────────────────────
install_app() {
  local base tmp
  if [ "$ESK_VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
  else base="https://github.com/$REPO/releases/download/$ESK_VERSION"; fi
  say "Эскадра ($ESK_VERSION) из $REPO"
  tmp="$(mktemp -d)"
  fetch -o "$tmp/eskadra.tar.gz" "$base/eskadra.tar.gz" || die "не удалось скачать релиз"
  fetch -o "$tmp/eskadra.tar.gz.sha256" "$base/eskadra.tar.gz.sha256" || die "нет файла контрольной суммы релиза"
  (cd "$tmp" && sha256sum -c --quiet eskadra.tar.gz.sha256) || die "SHA256 релиза не совпал"
  rm -rf "$PREFIX/app.new"; mkdir -p "$PREFIX/app.new"
  tar -xzf "$tmp/eskadra.tar.gz" -C "$PREFIX/app.new"
  [ -f "$PREFIX/app.new/server/dist/main.js" ] || die "архив релиза повреждён"
  rm -rf "$PREFIX/app.prev"; [ -d "$PREFIX/app" ] && mv "$PREFIX/app" "$PREFIX/app.prev"
  mv "$PREFIX/app.new" "$PREFIX/app"; rm -rf "$tmp"
  install -m 755 "$PREFIX/app/scripts/eskadra" /usr/local/bin/eskadra
}

public_ip() {
  local ip
  ip="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  [[ "$ip" =~ ^[0-9.]+$ ]] || ip="$(ip -4 -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
  echo "$ip"
}

free_port() {  # случайный свободный порт, не известный по умолчанию
  local p
  for _ in $(seq 1 50); do
    p=$(( (RANDOM << 15 | RANDOM) % 50000 + 10000 ))
    case "$p" in 10085|51820|2053|2096|54321) continue ;; esac
    ss -ltnH "sport = :$p" 2>/dev/null | grep -q . || { echo "$p"; return; }
  done
  die "не нашёл свободный порт"
}

# не «tr < /dev/urandom | head»: head закрывает канал, tr получает SIGPIPE, и pipefail молча роняет установку
rand_path() { local s=""; while [ ${#s} -lt 12 ]; do s+="$(head -c 256 /dev/urandom | tr -dc 'a-z0-9')"; done; echo "${s:0:12}"; }

FRESH=0
[ -f "$ENVF" ] || FRESH=1
SETUP_MARK="$ETC/.setup-done"   # появляется, когда первичная настройка прошла до конца (иначе повторный запуск её продолжит)

install_node
install_app

NOLOGIN="$(command -v nologin || echo /bin/false)"   # /usr/sbin/nologin в Debian, /sbin/nologin в RHEL
id eskadra >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell "$NOLOGIN" eskadra
install -d -m 700 -o eskadra -g eskadra "$DATA" "$DATA/tls"
install -d -m 755 "$ETC"

IP="$(public_ip)"
if [ "$FRESH" = 1 ]; then
  say "Первичная настройка"
  PORT="${ESKADRA_PORT:-$(free_port)}"
  BASE="/$(rand_path)/"
  cat > "$ENVF" <<EOF
# Эскадра — настройки панели (меняйте через команду eskadra)
FLEET_HOST=0.0.0.0
FLEET_PORT=$PORT
FLEET_BASE_PATH=$BASE
FLEET_DATA=$DATA
FLEET_TLS_CERT=$DATA/tls/cert.pem
FLEET_TLS_KEY=$DATA/tls/key.pem
FLEET_SECURE_COOKIES=1
FLEET_SUB_BIND=0.0.0.0
FLEET_NODEKIT=$PREFIX/app/nodekit
FLEET_WEB_DIST=$PREFIX/app/web/dist
FLEET_PUBLIC_HOST=$IP
FLEET_SUB_TLS=0
EOF
  chmod 640 "$ENVF"; chgrp eskadra "$ENVF"
fi

cat > /etc/systemd/system/eskadra.service <<EOF
[Unit]
Description=Eskadra panel
After=network-online.target
Wants=network-online.target

[Service]
User=eskadra
Group=eskadra
EnvironmentFile=$ENVF
WorkingDirectory=$PREFIX/app
ExecStart=$PREFIX/node/bin/node $PREFIX/app/server/dist/main.js
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DATA
CapabilityBoundingSet=
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
# Помощник «главный сервер как узел»: панель (без root) кладёт запрос, root-юнит добавляет её ключ на этом хосте
install -d -m 700 -o eskadra -g eskadra "$DATA/selfnode"
cat > /etc/systemd/system/eskadra-selfnode.service <<EOF
[Unit]
Description=Eskadra: panel access to this host (self node)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/eskadra self-node-apply
EOF
cat > /etc/systemd/system/eskadra-selfnode.path <<EOF
[Unit]
Description=Eskadra: watch self-node requests
[Path]
PathChanged=$DATA/selfnode/request.json
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now eskadra-selfnode.path >/dev/null 2>&1 || warn "не удалось включить eskadra-selfnode.path"

cli() { runuser -u eskadra -- env $(grep -v '^#' "$ENVF" | xargs) "$PREFIX/node/bin/node" "$PREFIX/app/server/dist/cli.js" "$@"; }
envget() { grep -E "^$1=" "$ENVF" | tail -1 | cut -d= -f2- || true; }
# установки до появления отметки: если владелец уже создан, настройка давно пройдена
if [ "$FRESH" = 0 ] && [ ! -f "$SETUP_MARK" ] && [[ "$(cli status 2>/dev/null || true)" =~ \"admins\":[1-9] ]]; then
  date -u +%FT%TZ > "$SETUP_MARK"
fi
if [ ! -f "$SETUP_MARK" ]; then
  [ -n "$IP" ] && cli executor "$IP" >/dev/null
fi
PORT="$(envget FLEET_PORT)"
SUBPORT="$(cli sub-port "" "$( [ -f "$SETUP_MARK" ] || echo "$IP")")"   # существующий порт подписок сохраняется
# Порты панели и подписок — в том firewall хоста, который включён (ufw в Debian/Ubuntu, firewalld в RHEL/Fedora/openSUSE).
# Проверяется при каждом запуске: если прошлая установка оборвалась, порты всё равно откроются.
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "$PORT/tcp" comment 'eskadra panel' >/dev/null
  ufw allow "$SUBPORT/tcp" comment 'eskadra subscriptions' >/dev/null
  say "ufw: открыты порты $PORT и $SUBPORT"
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port="$PORT/tcp" --add-port="$SUBPORT/tcp" && firewall-cmd -q --reload
  say "firewalld: открыты порты $PORT и $SUBPORT"
fi

if [ ! -f "$SETUP_MARK" ]; then
  [ "$FRESH" = 1 ] || say "Прошлая установка не дошла до конца — продолжаю первичную настройку"
  # Уже установленные ядра: дополнить или удалить (порты панели и подписок с ними не пересекаются в любом случае)
  say "Сторонние VPN-ядра на этом сервере"
  /usr/local/bin/eskadra conflicts || warn "проверку ядер можно повторить: eskadra conflicts"
fi

# Сертификат панели — только Let's Encrypt, выпускается до первого запуска панели.
# Выпускается заново, если сертификата нет, он истекает или он самоподписанный (так было до v0.5.5).
/usr/local/bin/eskadra cert-migrate || warn "перенос сертификата: eskadra cert-migrate"
cert_ok() {
  local f="$DATA/tls/cert.pem"
  openssl x509 -in "$f" -noout -checkend 3600 >/dev/null 2>&1 || return 1
  [ "$(openssl x509 -in "$f" -noout -issuer -nameopt RFC2253 | cut -d= -f2-)" != "$(openssl x509 -in "$f" -noout -subject -nameopt RFC2253 | cut -d= -f2-)" ]
}
if ! cert_ok; then
  say "Сертификат панели (Let's Encrypt)"
  TLS_MODE="${ESKADRA_TLS:-}"
  if [ -z "$TLS_MODE" ]; then
    { : < /dev/tty; } 2>/dev/null || die "нет терминала для вопросов: задайте ESKADRA_TLS=ip или ESKADRA_TLS=domain ESKADRA_DOMAIN=…"
    printf '   1) На IP %s — без домена, сертификат на 6 дней, продлевается сам (рекомендуется)\n   2) На домен — нужна A-запись домена на %s\n' "$IP" "$IP"
    while read -r -t 0.05 _ < /dev/tty 2>/dev/null; do :; done   # не принимать за ответ то, что набрано заранее
    read -r -p "  Выберите [1]: " a < /dev/tty || true
    a="${a//[$'\r' ]/}"
    case "${a:-1}" in 2) TLS_MODE=domain ;; *) TLS_MODE=ip ;; esac
  fi
  case "$TLS_MODE" in
    ip|domain) ;;
    *) die "ESKADRA_TLS: ip или domain" ;;
  esac
  ESKADRA_INSTALL=1 /usr/local/bin/eskadra cert letsencrypt "$TLS_MODE" "${ESKADRA_DOMAIN:-}" \
    || die "сертификат не выпущен — установка остановлена. Исправьте причину (см. выше) и запустите ту же команду снова: она продолжит с этого места."
fi

systemctl enable --now eskadra >/dev/null 2>&1 || true
systemctl restart eskadra
sleep 2
systemctl is-active --quiet eskadra || { journalctl -u eskadra -n 30 --no-pager; die "панель не запустилась"; }
[ -f "$SETUP_MARK" ] || date -u +%FT%TZ > "$SETUP_MARK"

printf '\n%s\n' "${c_ok}${c_b}Эскадра установлена.${c_0}"
/usr/local/bin/eskadra url
printf '\n%s\n' "Управление в терминале: ${c_b}eskadra${c_0}  (меню), eskadra help — список команд."
