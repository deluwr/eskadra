#!/usr/bin/env bash
# Сборка релизного архива: scripts/build-release.sh <версия> <owner/repo>
# Результат: dist-release/eskadra.tar.gz и eskadra.tar.gz.sha256 (их скачивает install.sh).
set -euo pipefail
VERSION="${1:?версия, например v0.4.0}"
REPO="${2:?owner/repo}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist-release"
STAGE="$OUT/stage"

cd "$ROOT"
npm ci
npm run build -w web
npm run build -w server
npm test -w server
npm run i18n:check -w web

rm -rf "$OUT"; mkdir -p "$STAGE/server" "$STAGE/web" "$STAGE/scripts"
cp package.json package-lock.json "$STAGE/"
cp server/package.json "$STAGE/server/"; cp -r server/dist "$STAGE/server/dist"
rm -f "$STAGE"/server/dist/*.test.js
cp web/package.json "$STAGE/web/"; cp -r web/dist "$STAGE/web/dist"
cp -r nodekit "$STAGE/nodekit"
cp scripts/eskadra scripts/install.sh "$STAGE/scripts/"
echo "$VERSION" > "$STAGE/VERSION"
echo "$REPO" > "$STAGE/REPO"

# только прод-зависимости сервера; install-скрипты не нужны (нативных модулей нет)
(cd "$STAGE" && npm ci --omit=dev --ignore-scripts --workspace @fleet-ui/server --include-workspace-root=false --no-audit --no-fund)
rm -rf "$STAGE/web/node_modules"

tar -C "$STAGE" -czf "$OUT/eskadra.tar.gz" .
(cd "$OUT" && sha256sum eskadra.tar.gz > eskadra.tar.gz.sha256)
sed "s|deluwr/eskadra}|$REPO}|" scripts/install.sh > "$OUT/install.sh"
echo "готово: $OUT/eskadra.tar.gz ($(du -h "$OUT/eskadra.tar.gz" | cut -f1))"
