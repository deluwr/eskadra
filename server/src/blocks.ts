/**
 * Блокировки протоколов на всех узлах (вход и выходы): BitTorrent, почта SMTP, QUIC.
 *
 * BitTorrent режется в три слоя: протокол по содержимому (Xray: рукопожатие TCP и uTP; sing-box: TCP, uTP и
 * UDP-трекеры), домены публичных трекеров (geosite:category-public-tracker — база лежит рядом с Xray на узле).
 * Распознавание содержимого требует sniffing — при включённой блокировке он работает на каждом inbound, даже
 * если в конфигурации выключен (тогда только для маршрутизации, без подмены адреса назначения).
 * Ограничение: полностью зашифрованный BitTorrent (MSE/PE) по содержимому не отличить — режутся рукопожатие,
 * uTP и трекеры, на которых держится поиск пиров.
 */
import type { Db } from './db.js';
import { getSetting } from './db.js';

export interface Blocks { bittorrent: boolean; smtp: boolean; quic: boolean }
export const DEFAULT_BLOCKS: Blocks = { bittorrent: true, smtp: false, quic: false };
export const SMTP_PORTS = [25, 465, 587, 2525];

export const blocksOf = (db: Db): Blocks => ({ ...DEFAULT_BLOCKS, ...getSetting<Partial<Blocks>>(db, 'blocks', {}) });

/** Нужен ли sniffing на каждом inbound (распознавание протокола и доменов). */
export const needsSniff = (b: Blocks) => b.bittorrent;

/** Правила Xray — после служебных, раньше пользовательских маршрутов (действуют и на входе, и на выходах). */
export function xrayBlockRules(b: Blocks): object[] {
  const out: object[] = [];
  if (b.bittorrent) {
    out.push({ type: 'field', protocol: ['bittorrent'], outboundTag: 'block' });
    out.push({ type: 'field', domain: ['geosite:category-public-tracker'], outboundTag: 'block' });
  }
  if (b.smtp) out.push({ type: 'field', network: 'tcp', port: SMTP_PORTS.join(','), outboundTag: 'block' });
  // QUIC (HTTP/3): браузеры и приложения сами откатываются на TCP
  if (b.quic) out.push({ type: 'field', network: 'udp', port: '443', outboundTag: 'block' });
  return out;
}

/** Правила sing-box (route.rules, sing-box ≥ 1.11): sniff, затем reject. */
export function singboxBlockRules(b: Blocks): object[] {
  const out: object[] = [];
  if (b.bittorrent) out.push({ protocol: ['bittorrent'], action: 'reject' });
  if (b.smtp) out.push({ network: ['tcp'], port: SMTP_PORTS, action: 'reject' });
  if (b.quic) out.push({ network: ['udp'], port: [443], action: 'reject' });
  return out;
}
