/**
 * Протоколы конфигураций (§8, §11): что поддерживает каждый, настройки шаблона с умолчаниями,
 * inbound/клиенты для ядра, ссылки для клиентов и outbound'ы (подписка sing-box, пересылка через вход).
 *
 * Xray: VLESS, VMess, Trojan, Shadowsocks-2022 — транспорты TCP/WS/gRPC/XHTTP/HTTPUpgrade, защита REALITY/TLS/нет.
 * sing-box: Hysteria2. telemt: MTProto (fake-TLS).
 */
import { createHash } from 'node:crypto';
import type { InboundRow, TemplateRow } from './ctx.js';

export type Protocol = 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'mtproto';
export type Core = 'xray' | 'sing-box' | 'telemt';
export type Security = 'reality' | 'tls' | 'none';
export type Transport = 'tcp' | 'ws' | 'grpc' | 'xhttp' | 'httpupgrade';
/** Откуда сертификат TLS: Let's Encrypt на IP узла, свой домен на каждом узле, загруженный (общий домен/wildcard), самоподписанный (Hysteria2). */
export type CertMode = 'ip' | 'domain' | 'custom' | 'self';

export interface ProtocolInfo {
  core: Core; name: string; securities: Security[]; transports: Transport[]; udp?: boolean; relay: boolean; certModes: CertMode[];
}

export const PROTOCOLS: Record<Protocol, ProtocolInfo> = {
  vless: { core: 'xray', name: 'VLESS', securities: ['reality', 'tls', 'none'], transports: ['tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade'], relay: true, certModes: ['ip', 'domain', 'custom'] },
  vmess: { core: 'xray', name: 'VMess', securities: ['tls', 'none'], transports: ['tcp', 'ws', 'grpc', 'httpupgrade'], relay: true, certModes: ['ip', 'domain', 'custom'] },
  trojan: { core: 'xray', name: 'Trojan', securities: ['tls', 'reality'], transports: ['tcp', 'ws', 'grpc', 'httpupgrade'], relay: true, certModes: ['ip', 'domain', 'custom'] },
  shadowsocks: { core: 'xray', name: 'Shadowsocks-2022', securities: ['none'], transports: ['tcp'], relay: true, certModes: [] },
  hysteria2: { core: 'sing-box', name: 'Hysteria2', securities: ['tls'], transports: [], udp: true, relay: false, certModes: ['self', 'ip', 'domain', 'custom'] },
  mtproto: { core: 'telemt', name: 'MTProto (Telegram)', securities: ['none'], transports: [], relay: false, certModes: [] },
};

export const SS_METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'] as const;

/** Настройки шаблона (столбец settings, JSON) — всё, что зависит от протокола. */
export interface Spec {
  protocol: Protocol;
  security: Security;
  transport: Transport;
  /** REALITY: сайты маскировки (serverNames); TLS: имя сертификата для клиентов при общем домене */
  sni: string[];
  fingerprint: string;
  flow: string;              // vless: xtls-rprx-vision или ''
  path: string;              // ws / httpupgrade / xhttp
  host: string;              // заголовок Host (ws/httpupgrade/xhttp), необязательно
  serviceName: string;       // grpc
  xhttpMode: 'auto' | 'packet-up' | 'stream-up' | 'stream-one';
  alpn: string[];
  certMode: CertMode;
  domain: string;            // общий домен (certMode custom)
  domains: Record<string, string>; // домен на узел (certMode domain): serverId → домен
  ssMethod: typeof SS_METHODS[number];
  hy2Obfs: string;           // пароль obfs salamander, пусто — без obfs
  mtDomain: string;          // MTProto fake-TLS: домен маскировки
  sniffing: boolean;
}

/** Настройки шаблона с умолчаниями; старый протокол «vless-reality» = VLESS + REALITY + Vision. */
export function specOf(t: Pick<TemplateRow, 'protocol' | 'sni' | 'fingerprint'> & { settings?: string | null }): Spec {
  const raw = (() => { try { return JSON.parse(t.settings || '{}') as Partial<Spec>; } catch { return {}; } })();
  const protocol: Protocol = (t.protocol as string) === 'vless-reality' ? 'vless' : (t.protocol as Protocol);
  const info = PROTOCOLS[protocol];
  const security = raw.security && info.securities.includes(raw.security) ? raw.security : info.securities[0]!;
  const transport = raw.transport && info.transports.includes(raw.transport) ? raw.transport : 'tcp';
  const sni = (() => { try { return JSON.parse(t.sni) as string[]; } catch { return []; } })();
  return {
    protocol, security, transport, sni,
    fingerprint: t.fingerprint || 'chrome',
    flow: raw.flow ?? (protocol === 'vless' && transport === 'tcp' && security !== 'none' ? 'xtls-rprx-vision' : ''),
    path: raw.path || (transport === 'grpc' ? '' : '/'),
    host: raw.host ?? '',
    serviceName: raw.serviceName || 'grpc',
    xhttpMode: raw.xhttpMode ?? 'auto',
    alpn: raw.alpn ?? (transport === 'grpc' ? ['h2'] : ['h2', 'http/1.1']),
    certMode: raw.certMode && info.certModes.includes(raw.certMode) ? raw.certMode : (info.certModes[0] ?? 'self'),
    domain: raw.domain ?? '',
    domains: raw.domains ?? {},
    ssMethod: raw.ssMethod ?? '2022-blake3-aes-128-gcm',
    hy2Obfs: raw.hy2Obfs ?? '',
    mtDomain: raw.mtDomain || sni[0] || 'www.apple.com',
    sniffing: raw.sniffing ?? true,
  };
}

/** Порт inbound'а — TCP или UDP. */
export const protoOf = (p: Protocol) => (PROTOCOLS[p].udp ? 'udp' : 'tcp') as 'tcp' | 'udp';

// ───── секреты пользователя в нужном протоколу виде (из одного UUID профиля) ─────

const digest = (s: string) => createHash('sha256').update(s).digest();
/** Ключ Shadowsocks-2022 нужной длины, детерминированно из секрета. */
export const ssKey = (secret: string, method: Spec['ssMethod']) => digest('ss:' + secret).subarray(0, method === '2022-blake3-aes-128-gcm' ? 16 : 32).toString('base64');
/** Секрет MTProto: 16 байт hex. */
export const mtSecret = (secret: string) => digest('mt:' + secret).subarray(0, 16).toString('hex');

// ───── сертификаты TLS на узле ─────

/** Имя сертификата на узле (каталог /etc/eskadra/tls/<имя>/) или null, если TLS здесь не нужен. */
export function certName(sp: Spec, templateId: string, serverId: string, host: string): string | null {
  const tls = sp.security === 'tls' || sp.protocol === 'hysteria2';
  if (!tls) return null;
  switch (sp.certMode) {
    case 'ip': return /^[0-9.]+$|:/.test(host) ? 'ip' : null;
    case 'domain': { const d = sp.domains[serverId]; return d ? 'dom-' + d.replace(/[^A-Za-z0-9.-]/g, '') : null; }
    case 'custom': return 'tpl-' + templateId;
    default: return null; // self — у Hysteria2 свой самоподписанный
  }
}
export const certPaths = (name: string) => ({ certificateFile: `/etc/eskadra/tls/${name}/fullchain.pem`, keyFile: `/etc/eskadra/tls/${name}/privkey.pem` });

/** Имя сервера, которое клиент проверяет в сертификате (пусто — адрес подключения, для сертификата на IP). */
export function tlsServerName(sp: Spec, serverId: string): string {
  if (sp.certMode === 'domain') return sp.domains[serverId] ?? '';
  if (sp.certMode === 'custom') return sp.domain || sp.sni[0] || '';
  if (sp.certMode === 'self') return sp.sni[0] ?? 'localhost';
  return '';
}

// ───── Xray: inbound ─────

export interface XrayClient { id?: string; password?: string; email: string; flow?: string }

/** Клиент Xray для протокола из секрета профиля. */
export function xrayClient(sp: Spec, secret: string, email: string): XrayClient {
  switch (sp.protocol) {
    case 'vless': return { id: secret, email, ...(sp.flow ? { flow: sp.flow } : {}) };
    case 'vmess': return { id: secret, email };
    case 'trojan': return { password: secret, email };
    case 'shadowsocks': return { password: ssKey(secret, sp.ssMethod), email };
    default: throw new Error(`${sp.protocol} не работает на Xray`);
  }
}

function transportSettings(sp: Spec): Record<string, unknown> {
  const h = sp.host ? { host: sp.host } : {};
  switch (sp.transport) {
    case 'ws': return { wsSettings: { path: sp.path, ...h } };
    case 'grpc': return { grpcSettings: { serviceName: sp.serviceName } };
    case 'xhttp': return { xhttpSettings: { path: sp.path, mode: sp.xhttpMode, ...h } };
    case 'httpupgrade': return { httpupgradeSettings: { path: sp.path, ...h } };
    default: return {};
  }
}

/**
 * Inbound Xray. ssServerKey — ключ сервера для Shadowsocks-2022 (общий на inbound).
 * cert — имя сертификата на узле для TLS.
 */
export function xrayInbound(sp: Spec, ib: InboundRow, tag: string, clients: XrayClient[], opts: { privateKey?: string; cert?: string | null; ssServerKey?: string }): Record<string, unknown> {
  let settings: Record<string, unknown>;
  if (sp.protocol === 'shadowsocks') settings = { method: sp.ssMethod, password: opts.ssServerKey, clients, network: 'tcp' };
  else if (sp.protocol === 'vmess') settings = { clients };
  else if (sp.protocol === 'trojan') settings = { clients };
  else settings = { clients, decryption: 'none' };
  const stream: Record<string, unknown> = { network: sp.transport, security: sp.security, ...transportSettings(sp) };
  if (sp.security === 'reality') {
    stream.realitySettings = { show: false, target: `${sp.sni[0] ?? 'www.apple.com'}:443`, serverNames: sp.sni, privateKey: opts.privateKey ?? '', shortIds: [ib.short_id ?? ''] };
  } else if (sp.security === 'tls') {
    if (!opts.cert) throw new Error('для TLS нет сертификата на узле (проверьте режим сертификата и адрес узла)');
    stream.tlsSettings = { alpn: sp.alpn, certificates: [certPaths(opts.cert)] };
  }
  return {
    tag, listen: '0.0.0.0', port: ib.port, protocol: sp.protocol, settings,
    streamSettings: sp.protocol === 'shadowsocks' ? undefined : stream,
    ...(sp.sniffing ? { sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] } } : {}),
  };
}

/** Outbound Xray к inbound'у узла (пересылка со входа на выход). */
export function xrayOutbound(sp: Spec, ib: InboundRow, tag: string, address: string, secret: string, serverId: string): Record<string, unknown> {
  const stream: Record<string, unknown> = { network: sp.transport, security: sp.security, ...transportSettings(sp) };
  if (sp.security === 'reality') stream.realitySettings = { serverName: sp.sni[0] ?? '', fingerprint: sp.fingerprint, publicKey: ib.public_key ?? '', shortId: ib.short_id ?? '' };
  if (sp.security === 'tls') stream.tlsSettings = { serverName: tlsServerName(sp, serverId) || address, fingerprint: sp.fingerprint, alpn: sp.alpn };
  let settings: Record<string, unknown>;
  switch (sp.protocol) {
    case 'vless': settings = { vnext: [{ address, port: ib.port, users: [{ id: secret, encryption: 'none', ...(sp.flow ? { flow: sp.flow } : {}) }] }] }; break;
    case 'vmess': settings = { vnext: [{ address, port: ib.port, users: [{ id: secret, security: 'auto' }] }] }; break;
    case 'trojan': settings = { servers: [{ address, port: ib.port, password: secret }] }; break;
    case 'shadowsocks': settings = { servers: [{ address, port: ib.port, method: sp.ssMethod, password: `${ib.public_key ?? ''}:${ssKey(secret, sp.ssMethod)}` }] }; break;
    default: throw new Error(`${sp.protocol}: пересылка через вход не поддерживается`);
  }
  return { tag, protocol: sp.protocol, settings, ...(sp.protocol === 'shadowsocks' ? {} : { streamSettings: stream }) };
}

// ───── ссылки для клиентов ─────

const hostForUri = (h: string) => (h.includes(':') && !h.startsWith('[') ? `[${h}]` : h);

export interface LinkTarget { host: string; port: number; name: string; serverId: string; inbound: InboundRow }

export function link(sp: Spec, secret: string, to: LinkTarget): string {
  const tag = encodeURIComponent(to.name);
  const at = `${hostForUri(to.host)}:${to.port}`;
  const ib = to.inbound;
  if (sp.protocol === 'hysteria2') {
    const sni = tlsServerName(sp, to.serverId);
    const q = new URLSearchParams({
      ...(sni ? { sni } : {}),
      ...(sp.certMode === 'self' ? { insecure: '1', ...(ib.tls_pin ? { pinSHA256: ib.tls_pin } : {}) } : {}),
      ...(sp.hy2Obfs ? { obfs: 'salamander', 'obfs-password': sp.hy2Obfs } : {}),
    });
    return `hysteria2://${encodeURIComponent(secret)}@${at}/?${q}#${tag}`;
  }
  if (sp.protocol === 'mtproto') {
    const s = 'ee' + mtSecret(secret) + Buffer.from(sp.mtDomain).toString('hex');
    return `tg://proxy?server=${encodeURIComponent(to.host)}&port=${to.port}&secret=${s}`;
  }
  if (sp.protocol === 'shadowsocks') {
    return `ss://${encodeURIComponent(`${sp.ssMethod}:${ib.public_key ?? ''}:${ssKey(secret, sp.ssMethod)}`)}@${at}#${tag}`;
  }
  // общие параметры транспорта и защиты (формат v2rayN / Xray share link)
  const q: Record<string, string> = { type: sp.transport, security: sp.security };
  if (sp.transport === 'ws' || sp.transport === 'httpupgrade' || sp.transport === 'xhttp') { q.path = sp.path; if (sp.host) q.host = sp.host; }
  if (sp.transport === 'xhttp') q.mode = sp.xhttpMode;
  if (sp.transport === 'grpc') { q.serviceName = sp.serviceName; q.mode = 'gun'; }
  if (sp.security === 'reality') Object.assign(q, { sni: sp.sni[0] ?? '', fp: sp.fingerprint, pbk: ib.public_key ?? '', sid: ib.short_id ?? '' });
  if (sp.security === 'tls') { const sni = tlsServerName(sp, to.serverId); Object.assign(q, { fp: sp.fingerprint, alpn: sp.alpn.join(','), ...(sni ? { sni } : {}) }); }
  if (sp.protocol === 'vless') {
    if (sp.flow) q.flow = sp.flow;
    return `vless://${secret}@${at}?${new URLSearchParams({ encryption: 'none', ...q })}#${tag}`;
  }
  if (sp.protocol === 'trojan') return `trojan://${encodeURIComponent(secret)}@${at}?${new URLSearchParams(q)}#${tag}`;
  // VMess — JSON в base64 (формат v2rayN)
  const v = {
    v: '2', ps: to.name, add: to.host, port: String(to.port), id: secret, aid: '0', scy: 'auto', net: sp.transport, type: 'none',
    host: sp.host, path: sp.transport === 'grpc' ? sp.serviceName : sp.path, tls: sp.security === 'tls' ? 'tls' : '',
    sni: sp.security === 'tls' ? tlsServerName(sp, to.serverId) : '', alpn: sp.security === 'tls' ? sp.alpn.join(',') : '', fp: sp.fingerprint,
  };
  return `vmess://${Buffer.from(JSON.stringify(v)).toString('base64')}`;
}

// ───── подписка sing-box ─────

/** Outbound sing-box для клиента; null — протокол/транспорт sing-box не поддерживает (XHTTP, MTProto). */
export function singboxOutbound(sp: Spec, secret: string, to: LinkTarget): Record<string, unknown> | null {
  const base = { tag: to.name, server: to.host, server_port: to.port };
  if (sp.protocol === 'mtproto' || sp.transport === 'xhttp') return null;
  if (sp.protocol === 'hysteria2') {
    const sni = tlsServerName(sp, to.serverId);
    return {
      type: 'hysteria2', ...base, password: secret,
      tls: { enabled: true, ...(sni ? { server_name: sni } : {}), ...(sp.certMode === 'self' ? { insecure: true } : {}) },
      ...(sp.hy2Obfs ? { obfs: { type: 'salamander', password: sp.hy2Obfs } } : {}),
    };
  }
  if (sp.protocol === 'shadowsocks') return { type: 'shadowsocks', ...base, method: sp.ssMethod, password: `${to.inbound.public_key ?? ''}:${ssKey(secret, sp.ssMethod)}` };
  const transport = sp.transport === 'ws' ? { type: 'ws', path: sp.path, ...(sp.host ? { headers: { Host: sp.host } } : {}) }
    : sp.transport === 'grpc' ? { type: 'grpc', service_name: sp.serviceName }
    : sp.transport === 'httpupgrade' ? { type: 'httpupgrade', path: sp.path, ...(sp.host ? { host: sp.host } : {}) } : undefined;
  const tls = sp.security === 'reality'
    ? { enabled: true, server_name: sp.sni[0] ?? '', utls: { enabled: true, fingerprint: sp.fingerprint }, reality: { enabled: true, public_key: to.inbound.public_key ?? '', short_id: to.inbound.short_id ?? '' } }
    : sp.security === 'tls'
      ? { enabled: true, ...(tlsServerName(sp, to.serverId) ? { server_name: tlsServerName(sp, to.serverId) } : {}), alpn: sp.alpn, utls: { enabled: true, fingerprint: sp.fingerprint } }
      : undefined;
  const cred = sp.protocol === 'trojan' ? { password: secret } : { uuid: secret };
  return {
    type: sp.protocol, ...base, ...cred,
    ...(sp.protocol === 'vless' && sp.flow ? { flow: sp.flow } : {}),
    ...(sp.protocol === 'vmess' ? { security: 'auto', alter_id: 0 } : {}),
    ...(tls ? { tls } : {}), ...(transport ? { transport } : {}),
  };
}

// ───── telemt (MTProto) ─────

const tomlStr = (s: string) => JSON.stringify(s);

/** config.toml для telemt: один fake-TLS listener на порту inbound'а; пользователи — в [access.users] (подхватываются без перезапуска). */
export function telemtConfig(sp: Spec, port: number, users: Array<{ name: string; secret: string; maxIps?: number | null }>, publicHost: string): string {
  const lines = [
    '# Эскадра: MTProto (telemt). Файл генерирует панель — правки вручную будут перезаписаны.',
    '[general]', 'use_middle_proxy = true', 'log_level = "normal"', '',
    '[general.modes]', 'classic = false', 'secure = false', 'tls = true', '',
    '[general.links]', 'show = "*"', `public_host = ${tomlStr(publicHost)}`, `public_port = ${port}`, '',
    '[server]', `port = ${port}`, '',
    '[server.api]', 'enabled = false', '',
    '[[server.listeners]]', 'ip = "0.0.0.0"', '',
    '[censorship]', `tls_domain = ${tomlStr(sp.mtDomain)}`, 'mask = true', 'tls_emulation = true', 'tls_front_dir = "tlsfront"', '',
    // секция access — последней: при изменениях только в ней ядро не перезапускается (telemt подхватывает её сам)
    '[access.users]',
    ...users.map((u) => `${tomlStr(u.name)} = ${tomlStr(mtSecret(u.secret))}`),
  ];
  const limited = users.filter((u) => u.maxIps);
  if (limited.length) lines.push('', '[access.user_max_unique_ips]', ...limited.map((u) => `${tomlStr(u.name)} = ${u.maxIps}`));
  return lines.join('\n') + '\n';
}
