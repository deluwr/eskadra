/**
 * Прокси до сервера, который недоступен с главного сервера (главный в РФ, сервер за границей): конфигурация
 * флота (служебный клиент svc.mgmt) или своя ссылка. Нужен для первичного доступа (onboard.ts) и, если сервер
 * недоступен из РФ целиком, — для постоянного туннеля управления (mgmt.ts, цепочка через dialerProxy).
 */
import { HttpError, type Ctx, type ServerRow } from './ctx.js';
import { parseProxyLink } from './proxylink.js';
import { Vpn } from './vpn.js';
import { specOf, xrayOutbound } from './protocols.js';
import { mgmtCredKey } from './botproxy.js';

/**
 * Как дойти до SSH сервера при первичном доступе: напрямую (по умолчанию) или через прокси — конфигурацию флота
 * (служебный клиент svc.mgmt) либо свою ссылку vless://, trojan://, vmess://, ss://. Нужно, когда главный сервер
 * в РФ и SSH до сервера за границей режется: панель заходит через прокси, а дальше узел работает по своему туннелю.
 */
export type BootstrapVia = { kind: 'fleet'; serverId: string; templateId: string } | { kind: 'link'; link: string };

/** Outbound Xray для первичного доступа через прокси. */
export function viaOutbound(ctx: Ctx, via: BootstrapVia): { outbound: Record<string, unknown>; label: string } {
  if (via.kind === 'link') {
    try { return { outbound: parseProxyLink(via.link, 'boot-out'), label: 'свою ссылку' }; } catch (e) { throw new HttpError(400, `ссылка прокси: ${(e as Error).message}`); }
  }
  const vpn = new Vpn(ctx);
  const t = vpn.template(via.templateId);
  const s = ctx.servers().find((x) => x.id === via.serverId);
  const ib = t && s ? vpn.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct' AND state = 'active'`, t.id, s.id)[0] : undefined;
  if (!t || !s || !ib) throw new HttpError(400, 'выбранная конфигурация не выкачена на этот сервер — выберите другую');
  return { outbound: xrayOutbound(specOf(t), ib, 'boot-out', s.host, vpn.svcCred(mgmtCredKey(t.id, s.id)), s.id), label: `${s.name} · ${t.name}` };
}


/** Сохранённый прокси управления сервером (servers.mgmt_via, зашифрован). */
export function mgmtVia(ctx: Ctx, r: ServerRow): BootstrapVia | null {
  if (!r.mgmt_via) return null;
  try { return JSON.parse(ctx.open(r.mgmt_via)) as BootstrapVia; } catch { return null; }
}

/** Человеческое описание прокси (без секретов ссылки). */
export function viaLabel(ctx: Ctx, v: BootstrapVia | null): string | null {
  if (!v) return null;
  if (v.kind === 'link') return `своя ссылка (${v.link.split('://')[0]})`;
  const s = ctx.servers().find((x) => x.id === v.serverId);
  const t = new Vpn(ctx).template(v.templateId);
  return `${s?.name ?? v.serverId} · ${t?.name ?? v.templateId}`;
}
