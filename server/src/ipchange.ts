/**
 * Смена IP главного сервера: машина та же, а хостер выдал новый адрес (переезд в другую стойку, смена тарифа).
 *
 * Панель на главном сервере — исполнитель (с его IP она ходит на узлы по SSH) и часто вход/relay (его IP — в ссылках
 * пользователей и в firewall выходов: скрытый выход пускает к сервисам только адреса флота). Старый IP остаётся в базе,
 * на узлах и в сертификате, поэтому:
 *  1. обнаружение (checkPanelIp, раз в несколько минут): прежний адрес пропал с интерфейсов, а наружу сервер выходит
 *     с другого публичного адреса — два раза подряд. Если наблюдаемый адрес никогда не совпадал с известным (NAT,
 *     выход в интернет через другой IP), ничего не меняется само — только кнопкой «IP уже сменился»;
 *  2. данные (applyPanelIp): адрес главного сервера-узла, executor.ips (новый первым, прежний убирается), адрес
 *     подписок, конфиги узлов переприменяются (ссылки и relay берут адрес из базы);
 *  3. узлы (followUp): новый адрес — в from= ключа панели и в firewall узлов с прямым SSH. Кому новый адрес не
 *     разрешили заранее, панель не пустит напрямую — тогда заходим через другой сервер флота, адрес которого узел уже
 *     пускает (syncPeerAccess заранее разрешает адреса флота). Адрес relay — в наборы флота (peer-add/peer-del),
 *     сертификат узла «на IP» — перевыпуск; адрес и сертификат самой панели — root-помощник (eskadra public-ip).
 * Плановая смена (prepareIp): новый адрес разрешается на узлах заранее, пока старый ещё работает.
 */
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import os from 'node:os';
import { isIP } from 'node:net';
import type { Ctx, ServerRow } from './ctx.js';
import type { NodeSession } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { audit } from './lib/audit.js';
import { Ops, peersAllowed } from './ops.js';
import { Vpn } from './vpn.js';
import { issueCert } from './tlsissue.js';
import { requestPublicIp, updateHelperInstalled, updateStatus } from './update.js';

type Log = (l: string) => void;

export interface IpProbe {
  /** IPv4 на интерфейсах этой машины */
  ifaces(): string[];
  /** адрес, с которого ядро отправит пакет в интернет (без отправки пакетов) */
  route(): Promise<string | null>;
  /** внешний адрес глазами интернета (за NAT отличается от адресов интерфейсов) */
  egress(): Promise<string | null>;
}

export const systemProbe: IpProbe = {
  ifaces: () => Object.values(os.networkInterfaces()).flat().filter((a) => !!a && a.family === 'IPv4' && !a.internal).map((a) => a!.address),
  route: () => new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    const done = (v: string | null) => { try { s.close(); } catch { /* уже закрыт */ } resolve(v); };
    s.on('error', () => done(null));
    s.connect(53, '1.1.1.1', () => { try { done(s.address().address); } catch { done(null); } });
  }),
  egress: async () => {
    try {
      const r = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(8000) });
      const { ip } = (await r.json()) as { ip: string };
      return isIP(ip) === 4 ? ip : null;
    } catch { return null; }
  },
};

/** Публичный IPv4: не частный, не loopback, не CGNAT, не link-local, не multicast. */
export function isPublicV4(ip: string): boolean {
  if (isIP(ip) !== 4) return false;
  const [a, b] = ip.split('.').map(Number) as [number, number];
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168));
}

/** Какой IP панель считает своим: главный сервер-узел, адрес панели (если это IP), первый адрес исполнителя. */
export function knownPanelIp(ctx: Ctx, env = process.env.FLEET_PUBLIC_HOST?.trim() ?? ''): string | null {
  const local = ctx.servers().find((s) => s.mgmt_mode === 'local');
  if (local && isIP(local.host) === 4) return local.host;
  if (isIP(env) === 4) return env;
  const ex = ctx.executorIps()[0];
  return ex && isIP(ex) === 4 ? ex : null;
}

interface IpState { seen: string | null; pending: { ip: string; n: number } | null }
const STATE = 'panel.ip.state';

/** Наблюдаемый адрес: маршрут в интернет, если он публичный, иначе — внешний адрес (NAT). */
async function observe(p: IpProbe): Promise<string | null> {
  const r = await p.route();
  if (r && isPublicV4(r)) return r;
  const e = await p.egress();
  return e && isPublicV4(e) ? e : null;
}

/**
 * Проверка: сменился ли IP. Изменение засчитывается со второй проверки подряд с тем же новым адресом и только если
 * раньше наблюдаемый адрес совпадал с известным (иначе это не смена, а другой адрес выхода в интернет).
 */
export async function checkPanelIp(ctx: Ctx, probe: IpProbe = systemProbe, env?: string): Promise<{ from: string; to: string } | null> {
  const pub = env ?? process.env.FLEET_PUBLIC_HOST?.trim() ?? '';
  const from = knownPanelIp(ctx, pub);
  if (!from) return null;
  const st = getSetting<IpState>(ctx.db, STATE, { seen: null, pending: null });
  const save = (v: IpState) => setSetting(ctx.db, STATE, v);
  if (probe.ifaces().includes(from)) { if (st.seen !== from || st.pending) save({ seen: from, pending: null }); return null; }
  // адрес панели уже новый (eskadra public-ip / cert letsencrypt ip записывают внешний IP самого сервера), а главный
  // сервер-узел в базе — на прежнем: смена была раньше, чем панель начала её отслеживать. Подтверждение — тот же
  // адрес на интерфейсе или снаружи; ждать второй проверки и базового адреса не нужно
  if (isIP(pub) === 4 && pub !== from && from === ctx.servers().find((s) => s.mgmt_mode === 'local')?.host) {
    const seenNow = probe.ifaces().includes(pub) ? pub : await observe(probe);
    if (seenNow === pub) return { from, to: pub };
  }
  const now = await observe(probe);
  if (!now) return null;   // адрес не узнать (нет сети) — ничего не решаем
  if (now === from) { if (st.seen !== from || st.pending) save({ seen: from, pending: null }); return null; }
  if (st.seen !== from) return null;
  const n = st.pending?.ip === now ? st.pending.n + 1 : 1;
  save({ seen: from, pending: { ip: now, n } });
  return n >= 2 ? { from, to: now } : null;
}

export interface IpChange {
  at: string; from: string; to: string;
  /** адрес панели (FLEET_PUBLIC_HOST) — прежний IP: его и сертификат меняет root-помощник */
  panelHost: 'requested' | 'manual' | null;
  /** домены панели и подписок, которые ещё смотрят на прежний IP: A-запись — на новый */
  domains: string[];
  /** узлы с прямым SSH, куда новый адрес разрешить не удалось (id) */
  cut: string[];
  /** узлы ещё не обработаны (followUp идёт или не запускался) */
  running?: boolean;
}

export const ipChangeOf = (ctx: Ctx) => getSetting<IpChange | null>(ctx.db, 'panel.ipchange', null);

/** Данные под новый адрес — сразу, без узлов. */
export async function applyPanelIp(ctx: Ctx, from: string, to: string, by = 'system', env = process.env.FLEET_PUBLIC_HOST?.trim() ?? ''): Promise<IpChange> {
  const { db } = ctx;
  if (isIP(to) !== 4) throw new Error(`неверный адрес: ${to}`);
  const local = ctx.servers().find((s) => s.mgmt_mode === 'local');
  if (local && local.host === from) ctx.updateServer(local.id, { host: to });
  setSetting(db, 'executor.ips', [to, ...ctx.executorIps().filter((x) => x !== to && x !== from)]);
  const sub = getSetting<string>(db, 'sub.host', '');
  if (sub === from) setSetting(db, 'sub.host', to);
  // домены панели и подписок, которые смотрят на прежний адрес
  const names = [...new Set([env, sub].filter((h) => h && !isIP(h)))];
  const domains: string[] = [];
  for (const d of names) if ((await dns.resolve4(d).catch(() => [] as string[])).includes(from)) domains.push(d);
  const c: IpChange = { at: new Date().toISOString(), from, to, panelHost: env === from ? 'manual' : null, domains, cut: [], running: true };
  setSetting(db, 'panel.ipchange', c);
  setSetting(db, STATE, { seen: to, pending: null } satisfies IpState);
  new Vpn(ctx).markDirty();   // ссылки, relay и выходы берут адрес из базы — переприменить, что изменилось
  audit(db, by, 'panel.ip_changed', local?.id, { from, to });
  return c;
}

/** Операция на узле по его каналу; узел с прямым SSH не пускает панель — через другой сервер флота. */
async function onNodeRescue<T>(ctx: Ctx, ops: Ops, x: ServerRow, fn: (n: NodeSession) => Promise<T>, log: Log): Promise<T> {
  try { return await ctx.onNode(x, fn); } catch (e) {
    if (x.mgmt_mode !== 'direct') throw e;
    const allowed = peersAllowed(ctx, x.id);
    const cands = ctx.servers().filter((j) => j.id !== x.id && j.mgmt_mode !== 'jump' && j.mgmt_mode !== 'local' && j.sudo_mode === 'restricted'
      && !j.fail_since && isIP(j.host) && allowed.includes(j.host));
    for (const j of cands) {
      const target = `${x.host}:${x.ssh_port}`;
      try {
        await ctx.onNode(j, async (n) => {
          await ops.ensureKit(j, n, () => undefined);
          const r = await n.op(['jump-add', target], { timeoutMs: 60_000 });
          if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim());
        });
      } catch { continue; }
      try {
        const res = await ctx.onNode({ ...x, mgmt_mode: 'jump', mgmt_jump: j.id }, fn);
        log(`${x.name}: напрямую панель не пускает — зашла через ${j.name}`);
        return res;
      } catch { /* следующий посредник */ } finally {
        await ctx.onNode(j, (n) => n.op(['jump-del', target])).catch(() => undefined);
      }
    }
    throw e;
  }
}

/** Разрешить адрес панели на узлах с прямым SSH (from= и firewall) и в наборах флота у всех; вернуть, где не вышло. */
export async function allowEverywhere(ctx: Ctx, ip: string, log: Log, opts: { rescue?: boolean; dropPeer?: string } = {}): Promise<string[]> {
  const ops = new Ops(ctx);
  const failed: string[] = [];
  for (const s of ctx.servers().filter((x) => x.sudo_mode === 'restricted' && x.host_key_fp && x.mgmt_mode !== 'local')) {
    const direct = s.mgmt_mode === 'direct';
    const work = async (n: NodeSession) => {
      if (direct) {
        const r = await n.op(['allow', ip], { timeoutMs: 60_000 });
        if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
      }
      // адрес главного сервера — в наборе флота: relay на нём ходит к скрытым выходам
      await n.op(['peer-add', ip], { timeoutMs: 60_000 });
      if (opts.dropPeer) await n.op(['peer-del', opts.dropPeer], { timeoutMs: 60_000 });
    };
    try {
      await (opts.rescue ? onNodeRescue(ctx, ops, s, work, log) : ctx.onNode(s, work));
      if (direct) setSetting(ctx.db, `peers.allowed.${s.id}`, [...new Set([...peersAllowed(ctx, s.id), ip])]);
      log(`${s.name}: адрес ${ip} разрешён${direct ? '' : ' (в наборе флота)'}`);
    } catch (e) {
      if (direct) failed.push(s.id);
      log(`${s.name}: не удалось — ${(e as Error).message}${direct ? `. В консоли хостера: fleetctl allow ${ip}` : ''}`);
    }
  }
  return failed;
}

/** Плановая смена: новый адрес — в executor.ips и на узлах заранее, пока старый ещё работает. */
export async function prepareIp(ctx: Ctx, ip: string, log: Log): Promise<string[]> {
  if (isIP(ip) !== 4) throw new Error(`неверный адрес: ${ip}`);
  setSetting(ctx.db, 'executor.ips', [...new Set([...ctx.executorIps(), ip])]);
  log(`адрес ${ip} добавлен в адреса исполнителя`);
  const failed = await allowEverywhere(ctx, ip, log);
  setSetting(ctx.db, 'panel.ip.prepared', { ip, at: new Date().toISOString() });
  return failed;
}

/** После смены: адрес и сертификат панели, узлы, сертификат главного сервера-узла на IP. */
export async function followUp(ctx: Ctx, c: IpChange, log: Log): Promise<IpChange> {
  // адрес панели и её сертификат (на IP) — root-помощник; он перезапустит панель, поэтому — в конце
  let panelHost = c.panelHost;
  const helper = panelHost === 'manual' && updateHelperInstalled() && !updateStatus().running;
  const cut = await allowEverywhere(ctx, c.to, log, { rescue: true, dropPeer: c.from });
  const local = ctx.servers().find((s) => s.mgmt_mode === 'local');
  const hasIpCert = (s: ServerRow) => { try { return (JSON.parse(s.tls_state ?? '{}').certs ?? []).some((x: { name: string }) => x.name === 'ip'); } catch { return false; } };
  if (local && hasIpCert(local)) {
    try { await issueCert(ctx, local, { method: 'ip' }, (l) => log(`${local.name}: ${l}`)); }
    catch (e) { log(`${local.name}: сертификат на IP не перевыпущен — ${(e as Error).message}. Выпустите заново на вкладке «Сертификаты»`); }
  }
  if (helper) { requestPublicIp(); panelHost = 'requested'; log('адрес и сертификат панели меняет помощник на сервере — панель перезапустится'); }
  const done: IpChange = { ...c, panelHost, cut, running: false };
  setSetting(ctx.db, 'panel.ipchange', done);
  return done;
}

/** Текст для уведомления. */
export function ipChangeText(ctx: Ctx, c: IpChange): string {
  const names = (ids: string[]) => ids.map((id) => ctx.servers().find((s) => s.id === id)?.name ?? id).join(', ');
  return [
    `🌐 IP главного сервера сменился: ${c.from} → ${c.to}. Адрес исполнителя, главного сервера и подписок обновлён.`,
    ...(c.cut.length ? [`Не пускают панель: ${names(c.cut)} — в консоли хостера: fleetctl allow ${c.to}`] : []),
    ...(c.domains.length ? [`Домены ${c.domains.join(', ')} смотрят на прежний адрес — поменяйте A-запись на ${c.to}`] : []),
  ].join('\n');
}
