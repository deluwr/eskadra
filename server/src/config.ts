import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
// server/src -> repo root (and server/dist -> repo root)
export const REPO_ROOT = path.resolve(here, '..', '..');

/** Базовый путь панели: «/» в разработке, случайный («/k3x9…/») после установки. */
function normBase(p: string | undefined): string {
  const s = (p ?? '/').trim().replace(/^\/*/, '/').replace(/\/*$/, '/');
  if (!/^\/([A-Za-z0-9_-]+\/)*$/.test(s)) throw new Error(`FLEET_BASE_PATH: недопустимый путь ${p}`);
  return s;
}

export const config = {
  dataDir: process.env.FLEET_DATA ?? path.join(REPO_ROOT, 'data'),
  nodekitDir: process.env.FLEET_NODEKIT ?? path.join(REPO_ROOT, 'nodekit'),
  webDist: process.env.FLEET_WEB_DIST ?? path.join(REPO_ROOT, 'web', 'dist'),
  // По умолчанию — только loopback (разработка). Установщик задаёт 0.0.0.0 + случайный порт + случайный путь + TLS.
  host: process.env.FLEET_HOST ?? '127.0.0.1',
  port: Number(process.env.FLEET_PORT ?? 7070),
  basePath: normBase(process.env.FLEET_BASE_PATH),
  tlsCert: process.env.FLEET_TLS_CERT || null,
  tlsKey: process.env.FLEET_TLS_KEY || null,
  // подписки по HTTPS тем же сертификатом — только если он публичный (Let's Encrypt): самоподписанный клиенты не примут
  subTls: process.env.FLEET_SUB_TLS === '1',
  sessionTtlHours: 12,
  secureCookies: process.env.FLEET_SECURE_COOKIES === '1',
};
