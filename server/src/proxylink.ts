/**
 * Ссылка на прокси (vless://, trojan://, vmess://, ss://) или JSON outbound Xray → outbound Xray-клиента панели.
 * Нужно для первичного доступа к серверу, до которого с главного сервера SSH напрямую не доходит
 * (главный сервер в РФ): панель заходит на SSH сервера через этот прокси.
 */

export type XrayOutbound = Record<string, unknown> & { protocol: string };

const NETWORKS = ['tcp', 'raw', 'ws', 'grpc', 'xhttp', 'httpupgrade', 'splithttp'];

function stream(q: URLSearchParams, net: string, security: string, hostFallback: string): Record<string, unknown> {
  const network = net === 'raw' ? 'tcp' : net === 'splithttp' ? 'xhttp' : net || 'tcp';
  if (!NETWORKS.includes(network)) throw new Error(`транспорт ${network} не поддерживается`);
  const s: Record<string, unknown> = { network, security: security || 'none' };
  const host = q.get('host') ?? '';
  const path = q.get('path') ?? '/';
  if (network === 'ws') s.wsSettings = { path, ...(host ? { host } : {}) };
  if (network === 'httpupgrade') s.httpupgradeSettings = { path, ...(host ? { host } : {}) };
  if (network === 'xhttp') s.xhttpSettings = { path, mode: q.get('mode') || 'auto', ...(host ? { host } : {}) };
  if (network === 'grpc') s.grpcSettings = { serviceName: q.get('serviceName') ?? '' };
  const fp = q.get('fp') || 'chrome';
  if (security === 'reality') {
    const pbk = q.get('pbk');
    if (!pbk) throw new Error('в ссылке REALITY нет публичного ключа (pbk)');
    s.realitySettings = { serverName: q.get('sni') ?? '', fingerprint: fp, publicKey: pbk, shortId: q.get('sid') ?? '', spiderX: q.get('spx') ?? '' };
  } else if (security === 'tls') {
    const alpn = q.get('alpn');
    s.tlsSettings = { serverName: q.get('sni') || host || hostFallback, fingerprint: fp, ...(alpn ? { alpn: alpn.split(',') } : {}), ...(q.get('allowInsecure') === '1' ? { allowInsecure: true } : {}) };
  } else if (security && security !== 'none') throw new Error(`защита ${security} не поддерживается`);
  return s;
}

function hostPort(u: URL): { address: string; port: number } {
  const address = u.hostname.replace(/^\[|\]$/g, '');
  const port = Number(u.port);
  if (!address || !port) throw new Error('в ссылке нет адреса или порта');
  return { address, port };
}

export function parseProxyLink(raw: string, tag = 'proxy'): XrayOutbound {
  const text = raw.trim();
  if (!text) throw new Error('пустая ссылка');
  if (text.startsWith('{')) return fromJson(text, tag);
  const scheme = text.slice(0, text.indexOf('://')).toLowerCase();
  if (scheme === 'vmess') return vmess(text.slice(8), tag);
  if (scheme === 'ss') return shadowsocks(text, tag);
  if (scheme !== 'vless' && scheme !== 'trojan') throw new Error('нужна ссылка vless://, trojan://, vmess:// или ss://');
  let u: URL;
  try { u = new URL(text.replace(/^[a-z]+:\/\//i, 'http://')); } catch { throw new Error('ссылка не разбирается — скопируйте её целиком'); }
  const { address, port } = hostPort(u);
  const q = u.searchParams;
  const secret = decodeURIComponent(u.username);
  if (!secret) throw new Error('в ссылке нет UUID или пароля');
  const st = stream(q, q.get('type') ?? 'tcp', q.get('security') ?? 'none', address);
  if (scheme === 'vless') {
    const flow = q.get('flow');
    return { tag, protocol: 'vless', settings: { vnext: [{ address, port, users: [{ id: secret, encryption: 'none', ...(flow ? { flow } : {}) }] }] }, streamSettings: st };
  }
  return { tag, protocol: 'trojan', settings: { servers: [{ address, port, password: secret }] }, streamSettings: st };
}

function vmess(b64: string, tag: string): XrayOutbound {
  let v: Record<string, string>;
  try { v = JSON.parse(Buffer.from(b64.split('#')[0]!, 'base64').toString('utf8')); } catch { throw new Error('ссылка vmess:// не разбирается'); }
  const q = new URLSearchParams({ host: v.host ?? '', path: v.path ?? '/', sni: v.sni ?? '', fp: v.fp ?? '', alpn: v.alpn ?? '', serviceName: v.path ?? '' });
  const st = stream(q, v.net ?? 'tcp', v.tls === 'tls' ? 'tls' : 'none', v.add ?? '');
  if (!v.add || !v.port || !v.id) throw new Error('в ссылке vmess:// нет адреса, порта или id');
  return { tag, protocol: 'vmess', settings: { vnext: [{ address: v.add, port: Number(v.port), users: [{ id: v.id, security: v.scy || 'auto' }] }] }, streamSettings: st };
}

function shadowsocks(text: string, tag: string): XrayOutbound {
  // SIP002: ss://base64url(method:password)@host:port#name или ss://method:password@host:port
  const body = text.slice(5).split('#')[0]!;
  let method: string, password: string, address: string, port: number;
  if (body.includes('@')) {
    const at = body.lastIndexOf('@');
    let user = decodeURIComponent(body.slice(0, at));
    if (!user.includes(':')) user = Buffer.from(user, 'base64').toString('utf8');
    [method, password] = [user.slice(0, user.indexOf(':')), user.slice(user.indexOf(':') + 1)];
    const hp = new URL(`http://${body.slice(at + 1).split('?')[0]!.replace(/\/$/, '')}`);
    ({ address, port } = hostPort(hp));
  } else {
    const dec = Buffer.from(body, 'base64').toString('utf8');   // старый формат: всё в base64
    const m = dec.match(/^([^:]+):(.*)@([^@]+):(\d+)$/);
    if (!m) throw new Error('ссылка ss:// не разбирается');
    [, method, password, address] = m as unknown as [string, string, string, string];
    port = Number(m[4]);
  }
  if (!method || !password) throw new Error('в ссылке ss:// нет метода или пароля');
  return { tag, protocol: 'shadowsocks', settings: { servers: [{ address, port, method, password }] } };
}

function fromJson(text: string, tag: string): XrayOutbound {
  let j: Record<string, unknown>;
  try { j = JSON.parse(text); } catch { throw new Error('JSON не разбирается'); }
  const list = Array.isArray(j.outbounds) ? (j.outbounds as XrayOutbound[]) : [j as XrayOutbound];
  const o = list.find((x) => ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(String(x?.protocol)));
  if (!o) throw new Error('в JSON нет outbound vless, vmess, trojan или shadowsocks');
  return { ...o, tag };
}
