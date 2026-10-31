import dns from 'node:dns/promises';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { isIP } from 'node:net';
import type { Ctx, NodeSession, ServerRow } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { Ops } from './ops.js';
import { CDN_PORTS } from './protocols.js';
import { Vpn } from './vpn.js';

/**
 * Выпуск TLS-сертификата узла с вкладки «Хост» — способ выбирает админ, каждый шаг пишется в журнал задачи:
 *  - ip     — Let's Encrypt на IP сервера (короткий профиль, 6 дней, узел продлевает сам);
 *  - domain — Let's Encrypt на домен, который смотрит на сервер (HTTP-01 через порт 80);
 *  - cdn    — Cloudflare Origin CA через API-токен: сертификат на 15 лет, его принимает Cloudflare в режиме
 *             «Full (strict)». Вход XHTTP за CDN (конфигурация с доменом CDN) берёт его вместо самоподписанного.
 * Ключ Origin CA создаёт панель (CSR — здесь же), хранит запечатанным, как загруженные сертификаты конфигураций.
 * Токен Cloudflare нужен один раз и не сохраняется.
 */
export type IssueMethod = 'ip' | 'domain' | 'cdn';

export interface IssueRequest {
  method: IssueMethod;
  domain?: string;
  /** cdn: имена в сертификате (первое — основное), можно *.example.com */
  hostnames?: string[];
  cfToken?: string;
  /** cdn: создать или поправить A/AAAA-запись основного имени — на адрес сервера, через прокси Cloudflare */
  cfDns?: boolean;
  /** cdn: перевести зону в SSL/TLS «Full (strict)» */
  cfStrict?: boolean;
}

/** Сертификат Cloudflare Origin CA сервера (settings `tls.cf.<serverId>`). */
export interface CfOrigin { name: string; hostnames: string[]; certId: string; expiresOn: string; zone: string; fullchain: string; privkey: string; at: string }

const DOMAIN_RE = /^(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
export const validHostname = (h: string) => DOMAIN_RE.test(h.startsWith('*.') ? h.slice(2) : h);

/** Имя покрыто сертификатом: точное совпадение или *.zone на один уровень. */
export function covers(hostnames: string[], name: string): boolean {
  const n = name.toLowerCase();
  return hostnames.some((h) => {
    const x = h.toLowerCase();
    if (!x.startsWith('*.')) return x === n;
    const rest = n.slice(n.indexOf('.') + 1);
    return n.includes('.') && rest === x.slice(2);
  });
}

/** Каталог сертификата Cloudflare на узле: cf-<основное имя>, «*» → «_» (fleet-exec: до 64 символов вместе с .crt). */
export const cfCertName = (host: string) => ('cf-' + host.replace(/^\*/, '_').replace(/[^A-Za-z0-9._-]/g, '')).slice(0, 57);

export const cfOriginOf = (ctx: Ctx, serverId: string) => getSetting<CfOrigin | null>(ctx.db, `tls.cf.${serverId}`, null);

/** Сертификат Cloudflare сервера, если он покрывает домен CDN конфигурации. */
export function cfOriginFor(ctx: Ctx, serverId: string, cdn: string): CfOrigin | null {
  const cf = cfOriginOf(ctx, serverId);
  return cf && cdn && covers(cf.hostnames, cdn) && Date.parse(cf.expiresOn) > Date.now() ? cf : null;
}

/** Поставить сертификат Cloudflare на узел под именем name (cf-… или cdn-<конфигурация>). */
export async function installCf(ctx: Ctx, n: NodeSession, name: string, cf: CfOrigin): Promise<string> {
  await n.stage(`${name}.crt`, cf.fullchain);
  await n.stage(`${name}.key`, ctx.open(cf.privkey));
  return (await n.must(['tls-set', name, `${name}.crt`, `${name}.key`])).trim();
}

// ───── CSR без внешних библиотек: ECDSA P-256, подпись SHA-256 ─────

const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const tlv = (tag: number, ...parts: Buffer[]) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(body.length), body]); };
const seq = (...p: Buffer[]) => tlv(0x30, ...p);
const oid = (s: string) => {
  const [a, b, ...rest] = s.split('.').map(Number);
  const out = [a! * 40 + b!];
  for (const v of rest) { const bytes = [v & 0x7f]; let x = v >> 7; while (x) { bytes.unshift((x & 0x7f) | 0x80); x >>= 7; } out.push(...bytes); }
  return tlv(0x06, Buffer.from(out));
};
const OID_CN = '2.5.4.3', OID_EXT_REQ = '1.2.840.113549.1.9.14', OID_SAN = '2.5.29.17', OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';

/** Ключ и запрос на сертификат (PKCS#10) с CN и SAN. */
export function makeCsr(hostnames: string[]): { csr: string; key: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const subject = seq(tlv(0x31, seq(oid(OID_CN), tlv(0x0c, Buffer.from(hostnames[0]!, 'utf8')))));
  const san = seq(...hostnames.map((h) => tlv(0x82, Buffer.from(h, 'ascii'))));
  const extReq = seq(oid(OID_EXT_REQ), tlv(0x31, seq(seq(oid(OID_SAN), tlv(0x04, san)))));
  const info = seq(tlv(0x02, Buffer.from([0])), subject, spki, tlv(0xa0, extReq));
  const sig = createSign('sha256').update(info).sign(privateKey);   // DER (r, s)
  const der = seq(info, seq(oid(OID_ECDSA_SHA256)), tlv(0x03, Buffer.from([0]), sig));
  const pem = (label: string, b: Buffer) => `-----BEGIN ${label}-----\n${b.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;
  return { csr: pem('CERTIFICATE REQUEST', der), key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
}

// ───── Cloudflare API ─────

interface CfResp<T> { success: boolean; errors?: Array<{ code: number; message: string }>; result: T }

async function cfApi<T>(token: string, method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (e) { throw new Error(`Cloudflare API недоступен с панели: ${(e as Error).message}`); }
  const j = await res.json().catch(() => null) as CfResp<T> | null;
  if (!j?.success) {
    const err = j?.errors?.map((e) => `${e.message} (${e.code})`).join('; ') || `HTTP ${res.status}`;
    throw new Error(res.status === 403 || /auth/i.test(err) ? `${err} — у токена не хватает прав (см. подсказку в форме)` : err);
  }
  return j.result;
}

/** Зона Cloudflare, в которой лежит имя: перебор от полного имени к домену второго уровня. */
async function findZone(token: string, host: string): Promise<{ id: string; name: string; plan?: { name: string } }> {
  const parts = host.replace(/^\*\./, '').split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const name = parts.slice(i).join('.');
    const z = await cfApi<Array<{ id: string; name: string; plan?: { name: string } }>>(token, 'GET', `/zones?name=${encodeURIComponent(name)}`);
    if (z[0]) return z[0];
  }
  throw new Error(`зона для ${host} не найдена в аккаунте Cloudflare (или у токена нет доступа к ней)`);
}

/** IP сервера: host — IP или имя (тогда — его адреса). */
async function serverIps(s: ServerRow): Promise<string[]> {
  if (isIP(s.host)) return [s.host];
  const [a, b] = await Promise.all([dns.resolve4(s.host).catch(() => []), dns.resolve6(s.host).catch(() => [])]);
  return [...a, ...b];
}

// ───── выпуск ─────

export async function issueCert(ctx: Ctx, s: ServerRow, r: IssueRequest, log: (l: string) => void): Promise<void> {
  if (r.method === 'cdn') return issueCf(ctx, s, r, log);
  const ops = new Ops(ctx);
  let name: string, kind: 'ip' | 'domain', value: string;
  if (r.method === 'ip') {
    if (!isIP(s.host)) throw new Error(`адрес сервера ${s.host} — не IP; выберите «Домен»`);
    name = 'ip'; kind = 'ip'; value = s.host;
    log(`Способ: Let's Encrypt на IP ${value} (профиль shortlived — 6 дней, узел продлевает за 3 дня до конца)`);
  } else {
    const d = (r.domain ?? '').trim().toLowerCase();
    if (!DOMAIN_RE.test(d)) throw new Error('укажите домен, например vpn.example.com');
    name = 'dom-' + d; kind = 'domain'; value = d;
    log(`Способ: Let's Encrypt на домен ${d} (90 дней, узел продлевает за 30 дней до конца)`);
    log('Шаг 1: DNS — куда смотрит домен');
    const [a, b] = await Promise.all([dns.resolve4(d).catch(() => [] as string[]), dns.resolve6(d).catch(() => [] as string[])]);
    const got = [...a, ...b];
    if (!got.length) throw new Error(`у ${d} нет записей A/AAAA — добавьте запись на адрес сервера и подождите обновления DNS`);
    const mine = await serverIps(s);
    log(`  ${d} → ${got.join(', ')}; сервер — ${mine.join(', ') || s.host}`);
    if (!got.some((ip) => mine.includes(ip))) {
      log(`  ⚠ домен смотрит не на этот сервер. Если запись проксируется CDN (оранжевое облако Cloudflare), проверка Let's Encrypt может не пройти — для CDN выберите способ «CDN»`);
    } else log('  ✓ домен указывает на сервер');
    setSetting(ctx.db, `tls.domain.${s.id}`, d);
  }
  log(`Шаг ${kind === 'ip' ? 1 : 2}: выпуск на сервере (certbot, проверка HTTP-01 через порт 80 — откроется только на время проверки)`);
  await ctx.onNode(s, async (n) => {
    await ops.ensureKit(s, n, log);
    const x = await n.op(['tls-issue', name, kind, value], { timeoutMs: 600_000 });
    for (const l of `${x.stdout}\n${x.stderr}`.split('\n').map((v) => v.trim()).filter(Boolean)) log('  ' + l);
    if (x.code !== 0) throw new Error('certbot не выпустил сертификат — причина выше');
  });
  log('Шаг 3: проверка сроков');
  const st = await ops.checkCerts(s);
  const c = st.certs.find((v) => v.name === name);
  log(c?.notAfter ? `  ✓ ${name}: действует до ${c.notAfter.slice(0, 16).replace('T', ' ')} UTC, автопродление ${st.timer ? 'включено' : 'НЕ включено'}` : '  ⚠ сертификат не виден в статусе узла');
  log(kind === 'ip'
    ? 'Готово. В конфигурациях с TLS выберите «Сертификат: на IP» — выкат возьмёт этот сертификат.'
    : `Готово. В конфигурациях с TLS выберите «свой домен на сервере» и укажите ${value} для ${s.name}.`);
}

async function issueCf(ctx: Ctx, s: ServerRow, r: IssueRequest, log: (l: string) => void): Promise<void> {
  const token = (r.cfToken ?? '').trim();
  if (!token) throw new Error('нужен API-токен Cloudflare');
  const hostnames = [...new Set((r.hostnames ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean))];
  if (!hostnames.length) throw new Error('укажите домен CDN, например cdn.example.com');
  const bad = hostnames.find((h) => !validHostname(h));
  if (bad) throw new Error(`неверное имя: ${bad}`);
  if (hostnames.length > 10) throw new Error('не больше 10 имён');
  const main = hostnames[0]!;
  const ops = new Ops(ctx);
  log(`Способ: Cloudflare Origin CA для ${hostnames.join(', ')} — сертификат на 15 лет для связи Cloudflare → сервер`);

  log('Шаг 1: токен Cloudflare');
  await cfApi<{ status: string }>(token, 'GET', '/user/tokens/verify').then((v) => log(`  ✓ токен действителен (${v.status})`));
  const zone = await findZone(token, main);
  log(`  зона ${zone.name}${zone.plan ? ` (тариф ${zone.plan.name})` : ''}`);
  for (const h of hostnames) if (h.replace(/^\*\./, '') !== zone.name && !h.endsWith('.' + zone.name)) throw new Error(`${h} не из зоны ${zone.name} — один сертификат выпускается на имена одной зоны`);

  log('Шаг 2: DNS-запись');
  if (main.startsWith('*.')) log('  основное имя — wildcard, запись не проверяю: заведите проксируемую запись для нужного поддомена сами');
  else {
    const ips = (await serverIps(s)).filter((ip) => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|fc|fd|fe80)/i.test(ip));
    const recs = await cfApi<Array<{ id: string; type: string; content: string; proxied: boolean }>>(token, 'GET', `/zones/${zone.id}/dns_records?name=${encodeURIComponent(main)}`);
    const addr = recs.filter((x) => x.type === 'A' || x.type === 'AAAA');
    for (const x of recs) log(`  ${x.type} ${main} → ${x.content}${x.proxied ? ' (через прокси Cloudflare)' : ' (без прокси — DNS only)'}`);
    if (!recs.length) log(`  записи ${main} нет`);
    const ok = addr.length > 0 && addr.every((x) => x.proxied && ips.includes(x.content));
    if (ok) log('  ✓ запись указывает на сервер и проксируется Cloudflare');
    else if (r.cfDns) {
      const ip4 = ips.find((ip) => isIP(ip) === 4), ip = ip4 ?? ips[0];
      if (!ip) throw new Error('не удалось определить публичный адрес сервера для записи');
      const rec = { type: isIP(ip) === 4 ? 'A' : 'AAAA', name: main, content: ip, proxied: true, ttl: 1, comment: 'eskadra' };
      const same = addr.find((x) => x.type === rec.type);
      if (recs.some((x) => x.type === 'CNAME')) throw new Error(`у ${main} есть CNAME — поправьте запись в Cloudflare вручную`);
      if (same) await cfApi(token, 'PATCH', `/zones/${zone.id}/dns_records/${same.id}`, rec);
      else await cfApi(token, 'POST', `/zones/${zone.id}/dns_records`, rec);
      for (const x of addr.filter((v) => v !== same)) await cfApi(token, 'DELETE', `/zones/${zone.id}/dns_records/${x.id}`);
      log(`  ✓ ${same ? 'исправлена' : 'создана'} запись ${rec.type} ${main} → ${ip} через прокси Cloudflare`);
    } else log(`  ⚠ запись должна указывать на ${ips.join(' или ') || s.host} и проксироваться (оранжевое облако) — иначе клиенты пойдут мимо CDN`);
  }

  log('Шаг 3: ключ и запрос на сертификат (ключ создаётся на панели и хранится зашифрованным)');
  const { csr, key } = makeCsr(hostnames);
  log('Шаг 4: выпуск в Cloudflare Origin CA');
  const cert = await cfApi<{ id: string; certificate: string; expires_on: string }>(token, 'POST', '/certificates',
    { hostnames, requested_validity: 5475, request_type: 'origin-ecc', csr });
  log(`  ✓ сертификат ${cert.id}, действует до ${cert.expires_on}`);
  const name = cfCertName(main);
  const cf: CfOrigin = { name, hostnames, certId: cert.id, expiresOn: new Date(cert.expires_on).toISOString(), zone: zone.name,
    fullchain: cert.certificate.trim() + '\n', privkey: ctx.seal(key), at: new Date().toISOString() };

  log('Шаг 5: установка на сервер');
  const vpn = new Vpn(ctx);
  const cdnTpls = vpn.templates().filter((t) => t.entry_id === s.id && covers(hostnames, vpn.spec(t).cdn));
  await ctx.onNode(s, async (n) => {
    await ops.ensureKit(s, n, log);
    log('  ' + await installCf(ctx, n, name, cf));
    // входы за CDN на этом сервере сразу переходят с самоподписанного на сертификат Cloudflare
    for (const t of cdnTpls) log(`  «${t.name}»: ` + await installCf(ctx, n, 'cdn-' + t.id, cf));
    if (cdnTpls.length) {
      const x = await n.op(['core-restart', 'xray'], { timeoutMs: 60_000 });
      log(x.code === 0 ? '  ✓ Xray перезапущен с новым сертификатом' : `  ⚠ Xray не перезапустился: ${(x.stderr || x.stdout).trim()}`);
    }
  });
  setSetting(ctx.db, `tls.cf.${s.id}`, cf);

  log('Шаг 6: режим SSL/TLS зоны');
  try {
    const ssl = await cfApi<{ value: string }>(token, 'GET', `/zones/${zone.id}/settings/ssl`);
    log(`  сейчас: ${SSL_LABEL[ssl.value] ?? ssl.value}`);
    if (ssl.value !== 'strict' && r.cfStrict) {
      await cfApi(token, 'PATCH', `/zones/${zone.id}/settings/ssl`, { value: 'strict' });
      log('  ✓ переведено в «Full (strict)» — Cloudflare проверяет сертификат сервера');
    } else if (ssl.value === 'off' || ssl.value === 'flexible') log('  ⚠ в этом режиме Cloudflare идёт к серверу без TLS — вход XHTTP+TLS работать не будет; включите «Full (strict)»');
    else if (ssl.value === 'full') log('  режим «Full» работает; «Full (strict)» надёжнее — сертификат теперь подходит');
  } catch (e) { log(`  не удалось прочитать режим (нужно право Zone Settings: Read): ${(e as Error).message}`); }

  log(`Готово. Для XHTTP через CDN: конфигурация VLESS «через вход» на ${s.name} с доменом CDN ${main.startsWith('*.') ? '<поддомен>.' + zone.name : main}; порт входа — один из ${CDN_PORTS.join(', ')}.`);
  log('Для режима stream-up включите gRPC в Cloudflare (Network → gRPC); packet-up работает и без этого.');
  if (!cdnTpls.length) log('Конфигураций за CDN на этом сервере пока нет — при выкате вход возьмёт этот сертификат вместо самоподписанного.');
  await ops.checkCerts(s);
}

const SSL_LABEL: Record<string, string> = { off: 'выключен', flexible: 'Flexible', full: 'Full', strict: 'Full (strict)' };
