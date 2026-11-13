/**
 * «Российские сайты напрямую»: на выбранных входах (серверах в РФ) трафик к российским доменам и адресам уходит в
 * интернет с самого входа, а не на зарубежный выход. Озон, банки, Госуслуги видят российский адрес — и пользователю
 * не нужно настраивать раздельную маршрутизацию в клиенте.
 *
 * Действует только на соединения, пришедшие на вход для пересылки на выход (inbound'ы relay и локальные SOCKS
 * Hysteria2 через вход). Прямые подключения к узлам и пересылка ядром ОС не затрагиваются. Выключено по умолчанию:
 * пока ни один вход не выбран, конфиги узлов не меняются.
 *
 * Всегда — по базам ядра (рядом с Xray на узле): домены geosite:category-ru и зоны .ru, .su, .рф, адреса geoip:ru
 * (ловит российские сервисы на чужих доменах и соединения по IP). Когда на узле есть набор runetfreedom (rugeo.ts),
 * к ним добавляются его сайты («доступно только из России», свежий category-ru) и адреса (свежий ru, сети Яндекса).
 * Чтобы домен был виден и у
 * клиентов, которые шлют IP (режим TUN), на таких inbound'ах включается sniffing только для маршрутизации.
 */
import type { Db } from './db.js';
import { getSetting } from './db.js';

export interface RuDirect { entries: string[] }
export const DEFAULT_RU_DIRECT: RuDirect = { entries: [] };

export const RU_DOMAINS = ['geosite:category-ru', 'domain:ru', 'domain:su', 'domain:xn--p1ai'];
export const RU_IPS = ['geoip:ru'];
/** Дополнение из набора runetfreedom на узле (rugeo.ts): категории называются так же, как в их базах. */
export const ruExtDomains = (file: string) => [`ext:${file}:ru-available-only-inside`, `ext:${file}:category-ru`];
export const ruExtIps = (ipFile: string) => [`ext:${ipFile}:ru`, `ext:${ipFile}:yandex`];

export const ruDirectOf = (db: Db): RuDirect => ({ ...DEFAULT_RU_DIRECT, ...getSetting<Partial<RuDirect>>(db, 'ruDirect', {}) });

/** Включено ли на этом сервере. */
export const ruDirectOn = (db: Db, serverId: string) => ruDirectOf(db).entries.includes(serverId);

/** Правила Xray: после служебных и лимита устройств, раньше маршрутов «пользователь → выход». */
export function xrayRuDirectRules(inboundTags: string[], ext: { file: string; ipFile: string } | null = null): object[] {
  if (!inboundTags.length) return [];
  return [
    { type: 'field', inboundTag: inboundTags, domain: [...RU_DOMAINS, ...(ext ? ruExtDomains(ext.file) : [])], outboundTag: 'direct' },
    { type: 'field', inboundTag: inboundTags, ip: [...RU_IPS, ...(ext ? ruExtIps(ext.ipFile) : [])], outboundTag: 'direct' },
  ];
}
