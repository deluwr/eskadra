import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { coreMode, foreignCore, panelPorts, type Ctx, type InboundRow, type NodeSession, type ServerRow, type TemplateRow } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { json, orderBalancer, Vpn } from './vpn.js';
import { releaseFor, type Core } from './releases.js';
import { certName, entrySpec, natRelayOf, probePort, PROTOCOLS, protoOf } from './protocols.js';
import { blockedDevices, limitRules, updateDevices, userOfEmail } from './devices.js';
import { parseHostStat } from './hoststats.js';
import { parseAutoUserStats, counterDeltas, planSpread, SPREAD_COOLDOWN_MIN, spreadBal, spreadChain, spreadCaps, spreadGroupOf, spreadLayout, spreadLoop, parseLinkTest, type LinkTest, type SpreadExit, type SpreadGroup, type SpreadMove } from './spread.js';

/** Ядра узла, остановленные вручную на вкладке «Хост». */
export const coresOff = (ctx: Ctx, serverId: string) => getSetting<string[]>(ctx.db, `core.off.${serverId}`, []);

/** Адреса, с которых вход ключом панели на узле уже разрешён заранее (Ops.syncPeerAccess). */
export const peersAllowed = (ctx: Ctx, serverId: string) => getSetting<string[]>(ctx.db, `peers.allowed.${serverId}`, []);

/**
 * Отпечаток конфигов ядер, которые панель сейчас сформировала бы для узла. Хранится после выката; при запуске
 * панели (в т. ч. после обновления) узлы с другим отпечатком переприменяются сами — новая версия Эскадры
 * доходит до серверов без ручного «Выкатить».
 */
/** Подпись текущих блокировок устройств: узел с другой подписью получает новые правила (без перезапуска). */
export const limitsSig = (ctx: Ctx) => JSON.stringify(limitRules(blockedDevices(ctx)));

export function renderHash(vpn: Vpn, s: ServerRow): string {
  const part = (f: () => unknown) => { try { return JSON.stringify(f()); } catch (e) { return `error:${(e as Error).message}`; } };
  return createHash('sha256').update([part(() => vpn.renderXray(s, { limits: false })), part(() => vpn.renderSingbox(s)), part(() => vpn.renderTelemt(s)), part(() => vpn.hy2Hops(s)), part(() => vpn.hy2Relays(s))].join('\n')).digest('hex');
}

/** Метка в xui_user: для 3x-ui сохранён API-токен, а не логин и пароль. */
export const XUI_TOKEN = '@token';

export interface BalancerState { override: string | null; selected: string | null }

/** Вывод `xray api bi`: строки после «Selecting Override:» и «Selects:» — «  1   <tag>». */
export function parseBalancerInfo(out: string): BalancerState {
  const after = (title: string) => {
    const lines = out.split('\n');
    const i = lines.findIndex((l) => l.includes(title));
    const m = i >= 0 ? lines[i + 1]?.match(/^\s*\d+\s+(\S+)?/) : null;
    return m?.[1] ?? null;
  };
  return { override: after('Selecting Override:'), selected: after('Selects:') };
}

/** exitIp/exitLoc — адрес, с которым трафик выходит в интернет, и его страна по Cloudflare (проба через этот выход) */
export interface ExitHealth { exitId: string; name: string; rttMs: number | null; mbps: number | null; ok: boolean; error: string | null; exitIp: string | null; exitLoc: string | null; slow?: boolean }

/**
 * «По порядку» с порогом скорости: какие выходы медленные. Замер ниже порога — медленный; уже медленный снова
 * считается быстрым только от порога +10% (без дёрганья на границе). Не замеряли (выход не отвечал) — как было.
 */
export function slowExits(results: Array<{ exitId: string; ok: boolean; mbps: number | null }>, prevSlow: string[], thr: number, measured: boolean): string[] {
  if (!thr) return [];
  if (!measured) return prevSlow.filter((id) => results.some((r) => r.exitId === id));
  return results.filter((r) => {
    if (!r.ok) return prevSlow.includes(r.exitId);
    if (r.mbps === null) return true;   // отвечает, но скачать не смог — медленный
    return prevSlow.includes(r.exitId) ? r.mbps < thr * 1.1 : r.mbps < thr;
  }).map((r) => r.exitId);
}

/** Медиана замеров скорости выхода за последние windowMin минут (0 — последний замер); null — замеров нет. */
export function medianSpeed(ctx: Ctx, templateId: string, exitId: string, windowMin: number): number | null {
  const rows = (windowMin > 0
    ? ctx.db.prepare('SELECT mbps FROM exit_speed WHERE template_id = ? AND exit_id = ? AND at >= ? ORDER BY mbps').all(templateId, exitId, new Date(Date.now() - windowMin * 60_000).toISOString())
    : ctx.db.prepare('SELECT mbps FROM exit_speed WHERE template_id = ? AND exit_id = ? ORDER BY at DESC LIMIT 1').all(templateId, exitId)) as Array<{ mbps: number }>;
  if (!rows.length) return null;
  const m = rows.length >> 1;
  return rows.length % 2 ? rows[m]!.mbps : Math.round(((rows[m - 1]!.mbps + rows[m]!.mbps) / 2) * 10) / 10;
}

/** Какие уровни цепочки пропустить: медленный выход, если дальше по порядку есть отвечающий быстрый. Все медленные — никого. */
export function skipLevels(results: Array<{ exitId: string; ok: boolean }>, slow: string[]): boolean[] {
  return results.map((r, i) => slow.includes(r.exitId) && results.slice(i + 1).some((x) => x.ok && !slow.includes(x.exitId)));
}

const archOf = (s: ServerRow) => (s.arch === 'arm64' ? 'arm64' : 'amd64') as 'amd64' | 'arm64';
import { buildKitBundle, kitVersion } from './nodekit.js';
import { parseCertStatus, type TlsState } from './certs.js';
import { parseSections } from './preflight.js';

export interface JobHandle { id: number; log: (line: string) => void; finish: (s: 'ok' | 'failed') => void }

export function startJob(ctx: Ctx, serverId: string | null, kind: string): JobHandle {
  const id = Number(ctx.db.prepare('INSERT INTO jobs (server_id, kind) VALUES (?, ?)').run(serverId, kind).lastInsertRowid);
  return {
    id,
    log: (line) => ctx.db.prepare('UPDATE jobs SET log = log || ? WHERE id = ?').run(`[${new Date().toISOString()}] ${line}\n`, id),
    finish: (s) => ctx.db.prepare(`UPDATE jobs SET status = ?, finished_at = datetime('now') WHERE id = ?`).run(s, id),
  };
}

/** TCP-проба с панели: порт действительно отвечает снаружи (§11.2). */
export function tcpProbe(host: string, port: number, timeoutMs = 5000): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (ok: boolean) => { sock.destroy(); resolve(ok); };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

function inRange(port: number, spec: string): boolean {
  return spec.split(',').some((part) => {
    const [a, b] = part.trim().split('-').map(Number);
    return b === undefined ? port === a : port >= a! && port <= b;
  });
}

export class Ops {
  /** журнал текущего выката (для сообщений из ensureInbound, например о выпуске сертификата) */
  lastLog: ((l: string) => void) | null = null;
  readonly vpn: Vpn;
  constructor(readonly ctx: Ctx) { this.vpn = new Vpn(ctx); }

  /** Обновить nodekit на суженном узле через kit-install (если версия устарела). */
  async ensureKit(s: ServerRow, n: NodeSession, log: (l: string) => void) {
    const want = kitVersion();
    const have = (await n.op(['version'])).stdout.trim();
    if (have === want) return;
    const r = await n.op(['kit-install'], { stdin: buildKitBundle(), timeoutMs: 60_000 });
    if (r.code !== 0) throw new Error(`узел не принимает обновление nodekit (${have}): перезапустите bootstrap-сниппет и нажмите «Установить nodekit». ${r.stderr.trim()}`);
    log(`nodekit ${have} → ${want}`);
    this.ctx.updateServer(s.id, { kit_version: want });
  }

  /** Вызов fleet-xui на узле: учётные данные 3x-ui идут через stdin, не через argv. */
  async xui<T = unknown>(s: ServerRow, n: NodeSession, action: string, extra: Record<string, unknown> = {}): Promise<T> {
    const needsLogin = !['info', 'x25519', 'listening'].includes(action);
    if (needsLogin && (!s.xui_user || !s.xui_pass_sealed)) throw new Error(`${s.name}: укажите логин и пароль или API-токен 3x-ui (вкладка «Хост»)`);
    // xui_user = '@token' — вместо логина и пароля сохранён API-токен 3x-ui
    const secret = needsLogin ? this.ctx.open(s.xui_pass_sealed!) : '';
    const auth = !needsLogin ? {} : s.xui_user === XUI_TOKEN ? { token: secret } : { user: s.xui_user, pass: secret };
    const payload = JSON.stringify({ action, ...extra, ...auth });
    const out = await n.must(['xui'], { stdin: payload, timeoutMs: 60_000 });
    try { return JSON.parse(out) as T; } catch { return out.trim() as T; }
  }

  async ensureCore(s: ServerRow, n: NodeSession, core: Core, log: (l: string) => void) {
    const cores = json<Record<string, { version: string }>>(s.cores, {});
    if (cores[core]) return;
    if (core === 'xray' && coreMode(s) === 'xui') return; // Xray уже есть — у 3x-ui
    const foreign = foreignCore(s, core);
    if (foreign)
      throw new Error(`${s.name}: уже работает ${foreign.name} — Эскадра не запускает второе ядро ${core}, чтобы не было конфликта.` +
        (foreign.name === '3x-ui' ? ' Включите режим «через 3x-ui».' : ' Остановите его или используйте другой узел.'));
    const rel = await releaseFor(core, this.pinned(core), archOf(s));
    log(`установка ${core} ${rel.version} (${rel.asset}, sha256 ${rel.sha256.slice(0, 12)}…)`);
    await n.must(['core-install', core, rel.version, rel.sha256], { timeoutMs: 600_000 });
    cores[core] = { version: rel.version };
    this.ctx.updateServer(s.id, { cores: JSON.stringify(cores) });
    s.cores = JSON.stringify(cores);
  }

  /** Версия, которую ставят новые узлы: закреплённая в настройках или последняя стабильная. */
  pinned(core: Core): string {
    return getSetting<Record<string, string>>(this.ctx.db, 'cores.pin', {})[core] ?? 'latest';
  }

  /**
   * Обновление ядра на узле: узел ставит версию рядом, проверяет текущий конфиг новым бинарником,
   * переключает и перезапускает, а при неудаче возвращает прежнюю (fleet-core install).
   * Панель дополнительно проверяет, что порты inbounds снова слушаются; если нет — откат.
   */
  /**
   * Ядра узла при подключении: свои Xray и sing-box, если их место не занято. Xray узла с 3x-ui — его собственный;
   * если работает чужое ядро того же типа, своё не ставится (без конфликта за порты). Возвращает итог по ядрам.
   */
  async installCores(s: ServerRow, log: (l: string) => void): Promise<string[]> {
    const out: string[] = [];
    for (const core of ['xray', 'sing-box'] as Core[]) {
      const fresh = this.ctx.server(s.id);
      const have = json<Record<string, { version: string }>>(fresh.cores, {});
      if (core === 'xray' && coreMode(fresh) === 'xui') { out.push('Xray: используется Xray из 3x-ui'); continue; }
      const foreign = foreignCore(fresh, core);
      if (foreign) { out.push(`${core}: на сервере уже работает ${foreign.name} — своё ядро не ставится`); continue; }
      if (have[core]) { out.push(`${core} ${have[core]!.version}: уже установлен`); continue; }
      await this.ctx.onNode(fresh, (n) => this.ensureCore(fresh, n, core, log));
      out.push(`${core} ${json<Record<string, { version: string }>>(this.ctx.server(s.id).cores, {})[core]?.version ?? '?'}: установлен`);
    }
    return out;
  }

  async upgradeCore(s: ServerRow, core: Core, version: string, log: (l: string) => void): Promise<string> {
    if (core === 'xray' && coreMode(s) === 'xui') throw new Error(`${s.name}: Xray принадлежит 3x-ui — обновляйте его в самом 3x-ui`);
    const cores = json<Record<string, { version: string; previous?: string }>>(s.cores, {});
    if (!cores[core]) {
      // ядра ещё нет — ставим выбранную версию (ensureCore проверит 3x-ui и чужие ядра)
      const rel = await releaseFor(core, version === 'latest' ? this.pinned(core) : version, archOf(s));
      const foreign = foreignCore(s, core);
      if (foreign) throw new Error(`${s.name}: уже работает ${foreign.name} — Эскадра не ставит второе ядро ${core}`);
      log(`${s.name}: установка ${core} ${rel.version}`);
      await this.ctx.onNode(s, async (n) => {
        await this.ensureKit(s, n, log);
        await n.must(['core-install', core, rel.version, rel.sha256], { timeoutMs: 600_000 });
      });
      this.ctx.updateServer(s.id, { cores: JSON.stringify({ ...cores, [core]: { version: rel.version } }) });
      return rel.version;
    }
    const rel = await releaseFor(core, version, archOf(s));
    if (rel.version === cores[core]!.version) { log(`${s.name}: уже ${core} ${rel.version}`); return rel.version; }
    log(`${s.name}: ${core} ${cores[core]!.version} → ${rel.version}`);
    return this.ctx.onNode(s, async (n) => {
      await this.ensureKit(s, n, log);
      const out = await n.must(['core-install', core, rel.version, rel.sha256], { timeoutMs: 600_000 });
      log(`${s.name}: ${out.trim()}`);
      const ports = this.vpn.inbounds(`server_id = ? AND state = 'active'`, s.id)
        .filter((i) => this.vpn.template(i.template_id)?.core === core).map((i) => i.port);
      const st = await n.op(['core-status', core]);
      const missing = ports.filter((p) => !new RegExp(`:${p}\\b`).test(st.stdout));
      if (missing.length) {
        const rb = await n.op(['core-rollback', core]);
        log(`${s.name}: после обновления не слушаются порты ${missing.join(', ')} — откат: ${(rb.stdout || rb.stderr).trim()}`);
        throw new Error(`${s.name}: ${core} ${rel.version} не поднял порты ${missing.join(', ')}, возвращена ${cores[core]!.version}`);
      }
      cores[core] = { version: rel.version, previous: cores[core]!.version };
      this.ctx.updateServer(s.id, { cores: JSON.stringify(cores) });
      return rel.version;
    });
  }

  async rollbackCore(s: ServerRow, core: Core, log: (l: string) => void): Promise<string> {
    if (core === 'xray' && coreMode(s) === 'xui') throw new Error(`${s.name}: Xray принадлежит 3x-ui`);
    const out = await this.ctx.onNode(s, (n) => n.must(['core-rollback', core]));
    log(`${s.name}: ${out.trim()}`);
    const st = await this.ctx.onNode(s, (n) => n.op(['core-status', core]));
    const ver = st.stdout.match(/^version=(\S+)/m)?.[1] ?? '?';
    const prev = st.stdout.match(/^previous=(\S+)/m)?.[1];
    const cores = json<Record<string, { version: string; previous?: string }>>(s.cores, {});
    cores[core] = { version: ver, ...(prev && prev !== 'none' ? { previous: prev } : {}) };
    this.ctx.updateServer(s.id, { cores: JSON.stringify(cores) });
    return ver;
  }

  /** Линтер порта (§7.12.2): не SSH, не резерв, не занят чужим процессом, в разрешённом диапазоне группы. */
  lintPort(s: ServerRow, port: number, proto: 'tcp' | 'udp', templateId?: string): string | null {
    const other = this.ctx.db.prepare(`SELECT t.name FROM inbounds i JOIN templates t ON t.id = i.template_id
      WHERE i.server_id = ? AND i.port = ? AND i.proto = ? AND i.state IN ('active','deploying') AND i.template_id != ?`)
      .get(s.id, port, proto, templateId ?? '') as { name: string } | undefined;
    if (other) return `порт ${port}/${proto} уже занят шаблоном «${other.name}»`;
    // порт уже принадлежит этому шаблону на этом узле — повторный выкат, занятость не проверяем
    if (templateId && this.ctx.db.prepare(`SELECT 1 FROM inbounds WHERE server_id = ? AND port = ? AND template_id = ? AND state IN ('active','deploying')`).get(s.id, port, templateId)) return null;
    const ssh = json<number[]>(s.ssh_ports, []);
    if (ssh.includes(port)) return `порт ${port} — это SSH`;
    if ([10085, 51820].includes(port)) return `порт ${port} зарезервирован`;
    if (s.mgmt_port === port && proto === 'tcp') return `порт ${port} — служебный туннель управления`;
    if (s.mgmt_mode === 'local' && proto === 'tcp' && panelPorts(this.ctx.db).includes(port)) return `порт ${port} занят самой панелью или подписками`;
    const g = this.ctx.db.prepare('SELECT port_range FROM groups WHERE name = ?').get(s.group_name) as { port_range: string } | undefined;
    if (g && !inRange(port, g.port_range)) return `порт ${port} вне разрешённого диапазона группы (${g.port_range})`;
    const raw = this.ctx.db.prepare('SELECT raw FROM preflight_reports WHERE server_id = ? ORDER BY id DESC LIMIT 1').get(s.id) as { raw: string } | undefined;
    if (raw) {
      const listen = (parseSections(raw.raw).get('listen') ?? '').split('\n');
      const busy = listen.find((l) => l.startsWith(proto) && new RegExp(`:${port}\\s`).test(l));
      if (busy) return `порт ${port}/${proto} уже занят: ${busy.replace(/\s+/g, ' ').slice(0, 120)} (данные последнего preflight)`;
    }
    return null;
  }

  /** Создать запись inbound и ключи на узле (REALITY x25519 / самоподписанный TLS для Hysteria2). */
  async ensureInbound(t: TemplateRow, s: ServerRow, kind: 'direct' | 'relay', n: NodeSession): Promise<InboundRow> {
    const port = kind === 'relay' ? t.entry_port! : t.port;
    // вход eskadra может принимать Hysteria2: ключи, сертификат и протокол порта — по настройкам входа
    const sp = kind === 'relay' ? entrySpec(this.vpn.spec(t)) : this.vpn.spec(t);
    const proto = protoOf(sp.protocol);
    let ib = this.vpn.inbounds('template_id = ? AND server_id = ? AND kind = ?', t.id, s.id, kind)[0];
    if (!ib) {
      const id = 'ib-' + randomBytes(4).toString('hex');
      this.ctx.db.prepare('INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, short_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(id, t.id, s.id, kind, port, proto, randomBytes(4).toString('hex'));
      ib = this.vpn.inbounds('id = ?', id)[0]!;
    } else if (ib.port !== port || ib.proto !== proto) {
      // сменился порт или входной протокол eskadra (TCP ↔ UDP): прежний порт закрываем, если он больше никому не нужен
      const old = { port: ib.port, proto: ib.proto };
      this.ctx.db.prepare('UPDATE inbounds SET port = ?, proto = ? WHERE id = ?').run(port, proto, ib.id);
      Object.assign(ib, { port, proto });
      if (!this.portUsed(s.id, old.port, old.proto)) await n.op(['port-close', old.proto, old.port]);
    }
    // пересылка ядром ОС: на входе ни ядра, ни ключей, ни сертификата — всё у inbound'а выхода
    if (kind === 'relay' && natRelayOf(sp)) return ib;
    if (sp.security === 'reality' && !ib.private_key_sealed) {
      const out = coreMode(s) === 'xui' ? String(await this.xui(s, n, 'x25519')) : await n.must(['xray-x25519']);
      const priv = out.match(/^private=(\S+)/m)?.[1];
      const pub = out.match(/^public=(\S+)/m)?.[1];
      if (!priv || !pub) throw new Error('не удалось получить ключи REALITY с узла');
      this.ctx.db.prepare('UPDATE inbounds SET private_key_sealed = ?, public_key = ? WHERE id = ?').run(this.ctx.seal(priv), pub, ib.id);
    }
    // Shadowsocks-2022: ключ сервера (общий на inbound) — в public_key, он нужен и клиентам
    if (sp.protocol === 'shadowsocks' && !ib.public_key) {
      const key = randomBytes(sp.ssMethod === '2022-blake3-aes-128-gcm' ? 16 : 32).toString('base64');
      this.ctx.db.prepare('UPDATE inbounds SET public_key = ? WHERE id = ?').run(key, ib.id);
    }
    // TLS: сертификат на узле (Let's Encrypt на IP или домен узла, либо загруженный)
    if ((sp.security === 'tls' || sp.protocol === 'hysteria2') && sp.certMode !== 'self') {
      const name = certName(sp, t.id, s.id, s.host);
      if (!name) throw new Error(`${s.name}: нет сертификата для TLS — ${sp.certMode === 'ip' ? 'адрес сервера не IP' : 'не указан домен сервера'}`);
      if (sp.certMode === 'custom') {
        const c = getSetting<{ fullchain: string; privkey: string } | null>(this.ctx.db, `cert.${t.id}`, null);
        if (!c) throw new Error('загрузите сертификат и ключ в настройках конфигурации');
        await n.stage(`${name}.crt`, c.fullchain);
        await n.stage(`${name}.key`, this.ctx.open(c.privkey));
        await n.must(['tls-set', name, `${name}.crt`, `${name}.key`]);
      } else {
        const value = sp.certMode === 'ip' ? s.host : sp.domains[s.id]!;
        const out = await n.must(['tls-issue', name, sp.certMode, value], { timeoutMs: 600_000 });
        if (out.trim()) this.lastLog?.(`${s.name}: ${out.trim().split('\n').pop()}`);
      }
    }
    if (sp.protocol === 'hysteria2' && sp.certMode === 'self' && !ib.tls_pin) {
      const sni = sp.sni[0] ?? 'localhost';
      const out = await n.must(['singbox-tls', sni]);
      const pin = out.match(/^pin=([0-9a-f]{64})/m)?.[1];
      if (!pin) throw new Error('не удалось выпустить сертификат Hysteria2');
      this.ctx.db.prepare('UPDATE inbounds SET tls_pin = ? WHERE id = ?').run(pin, ib.id);
    }
    return this.vpn.inbounds('id = ?', ib.id)[0]!;
  }

  /** Отрендерить и применить все конфиги узла; ядро без inbounds останавливается. */
  async applyServer(s: ServerRow, n: NodeSession, log: (l: string) => void) {
    const cores = json<Record<string, unknown>>(s.cores, {});
    const xuiMode = coreMode(s) === 'xui';
    if (xuiMode) {
      // inbounds Эскадры в 3x-ui: активные — создать/обновить, снятые и упавшие — удалить
      for (const ib of this.vpn.inbounds('server_id = ?', s.id)) {
        const t = this.vpn.template(ib.template_id);
        if (!t || t.core !== 'xray') continue;
        if (['active', 'deploying'].includes(ib.state)) {
          const r = await this.xui<{ id: number; updated: boolean }>(s, n, 'upsert', { inbound: this.vpn.xuiInbound(s, ib) });
          this.ctx.db.prepare('UPDATE inbounds SET ext_id = ? WHERE id = ?').run(r.id, ib.id);
          log(`3x-ui: inbound eskadra-${t.name} ${r.updated ? 'обновлён' : 'создан'} (id ${r.id})`);
        } else {
          await this.xui(s, n, 'delete', { remark: `eskadra-${t.name}-${ib.id}` });
          log(`3x-ui: inbound eskadra-${t.name} удалён`);
        }
      }
    }
    for (const core of ['xray', 'sing-box', 'telemt'] as const) {
      if (core === 'xray' && xuiMode) continue;
      const cfg = core === 'xray' ? this.vpn.renderXray(s) : core === 'sing-box' ? this.vpn.renderSingbox(s) : this.vpn.renderTelemt(s);
      if (!cfg) {
        if (cores[core]) { await n.op(['core-stop', core]); log(`${core}: inbounds нет, ядро остановлено`); }
        if (core === 'sing-box' && cores[core]) await n.op(['singbox-net', '-']);
        continue;
      }
      await this.ensureCore(s, n, core, log);
      const name = `${core}-${Date.now()}.${core === 'telemt' ? 'toml' : 'json'}`;
      await n.stage(name, typeof cfg === 'string' ? cfg : JSON.stringify(cfg, null, 2));
      const out = await n.must(['core-apply', core, name], { timeoutMs: 60_000 });
      log(`${core}: ${out.trim()}`);
      // Hysteria2: буферы UDP ядра ОС (постоянно) и перенаправление диапазона портов на inbound (port hopping)
      if (core === 'sing-box') log(`hysteria2: ${(await n.must(['singbox-net', this.vpn.hy2Hops(s)])).trim()}`);
      // остановлено вручную (проверка отказоустойчивости) — конфиг обновлён, но ядро остаётся выключенным
      if (coresOff(this.ctx, s.id).includes(core)) { await n.op(['core-stop', core]); log(`${core}: остановлен вручную — не запускаю`); }
    }
    // Hysteria2 через вход: UDP пересылается на выход ядром ОС (nft DNAT); вызываем, только если пересылки есть или были —
    // узлам без них не нужна новая команда nodekit
    const relays = this.vpn.hy2Relays(s);
    if (relays !== '-' || getSetting<string>(this.ctx.db, `hy2relay.${s.id}`, '-') !== '-') {
      log(`hysteria2 через вход: ${(await n.must(['hy2-relay', relays])).trim()}`);
      setSetting(this.ctx.db, `hy2relay.${s.id}`, relays);
    }
    this.ctx.updateServer(s.id, { config_dirty: 0 });
    if (!xuiMode) setSetting(this.ctx.db, `applied.${s.id}`, renderHash(this.vpn, s));
    // блокировки устройств вошли в конфиг — на ходу узел догоняет только их изменения (Workers.devices)
    if (!xuiMode) setSetting(this.ctx.db, `limits.applied.${s.id}`, limitsSig(this.ctx));
    // перезапуск Xray сбрасывает переключение балансировщика — возвращаем выбранные выходы «Авто» входа
    // (с повтором: сразу после перезапуска API Xray может ещё не отвечать) и сверяем с тем, что реально выбрано
    if (!xuiMode) for (const t of this.vpn.templates().filter((x) => x.entry_id === s.id)) {
      const sp = this.vpn.spec(t);
      if (!sp.autoEnabled) continue;
      if (sp.autoMode === 'spread') {
        // «по нагрузке»: запоминаем раскладку, которую получил вход (по ней панель переводит группы, а не по черновику);
        // раскладка та же — переведённые группы снова на их выходы (дома балансировщику назначать нечего), другая — переводы сброшены
        const layout = spreadLayout(this.vpn, this.ctx.db, t);
        const { ids, homes } = layout;
        const same = JSON.stringify(getSetting(this.ctx.db, `spread.layout.${t.id}`, null)) === JSON.stringify(layout);
        if (!same) { setSetting(this.ctx.db, `spread.layout.${t.id}`, layout); setSetting(this.ctx.db, `spread.cur.${t.id}`, {}); }
        const assigned = same ? getSetting<Record<string, string>>(this.ctx.db, `spread.cur.${t.id}`, {}) : {};
        for (const [g, to] of Object.entries(assigned)) {
          const home = homes[Number(g)];
          if (!home || !ids.includes(to) || to === home) continue;
          if (!(await this.spreadAssign(n, t.id, Number(g), spreadChain(home, ids), to).catch(() => null))) log(`«${t.name}»: группа ${Number(g) + 1} не принята входом — повторю при следующей проверке`);
        }
        continue;
      }
      const ov = getSetting<string | null>(this.ctx.db, `auto.override.${t.id}`, null);
      if (ov && this.vpn.spec(t).autoEnabled && this.vpn.spec(t).autoMode !== 'random') {
        const st = await this.setOverride(n, t.id, ov).catch(() => null);
        if (st) setSetting(this.ctx.db, `auto.actual.${t.id}`, st.override || st.selected);
        else log(`«${t.name}»: вход не принял выбор выхода — повторю при следующей проверке`);
      }
    }
  }

  /**
   * «Авто через вход» по качеству: с входного узла через каждый выход меряются задержка и скорость скачивания.
   * Если текущий выход не проходит пороги (задержка > maxRttMs или скорость < minMbps), вход переключается на лучший
   * подходящий выход (без перезапуска Xray). Если подходящих нет — переключение снимается и выбор остаётся за Xray
   * (наименьшая задержка). Возвращает результаты и смену выхода (для уведомления).
   */
  /** Что выбрано в балансировщике входа: назначенный панелью выход (override) и тот, через который идёт трафик. */
  async balancerState(n: NodeSession, templateId: string, tag = `bal-${templateId}`): Promise<BalancerState | null> {
    const r = await n.op(['xray-bi', tag]);
    return r.code === 0 ? parseBalancerInfo(r.stdout) : null;
  }

  /** Назначить выход балансировщику (null — снять) и убедиться, что вход его принял; до 5 попыток. */
  async setOverride(n: NodeSession, templateId: string, tag: string | null, balancer = `bal-${templateId}`): Promise<BalancerState | null> {
    for (let i = 0; i < 5; i++) {
      if (i) await new Promise((r) => setTimeout(r, 1500));
      const r = await n.op(['xray-bo', balancer, tag ?? 'clear']);
      if (r.code !== 0) continue;
      const st = await this.balancerState(n, templateId, balancer);
      if (!st) return { override: tag, selected: tag };   // старый nodekit без xray-bi — проверить нечем
      if ((st.override ?? null) === tag) return st;
    }
    return null;
  }

  /** Быстрая проверка закреплённого выхода (только задержка, без скачивания): false — выход не отвечает или медленнее порога. */
  async pinnedAlive(t: TemplateRow): Promise<boolean> {
    const sp = this.vpn.spec(t);
    const ov = getSetting<string | null>(this.ctx.db, `auto.override.${t.id}`, null);
    if (!ov || !t.entry_id) return true;
    let ok = true;
    await this.ctx.onNode(this.ctx.server(t.entry_id), async (n) => {
      const r = await n.op(['exit-probe', probePort(t.id, ov.slice(`to-${t.id}-`.length)), 0], { timeoutMs: 60_000 });
      const rtt = Number(r.stdout.match(/^rtt_ms=(\d+)/m)?.[1] ?? NaN);
      ok = !Number.isNaN(rtt) && (sp.autoMode === 'order' || rtt <= sp.maxRttMs);
    });
    return ok;
  }

  /** Сертификаты узла: сроки и результат последнего продления (продлевает сам узел, панель следит). */
  async checkCerts(s: ServerRow, renew = false): Promise<TlsState> {
    let st: TlsState | null = null;
    await this.ctx.onNode(s, async (n) => {
      await this.ensureKit(s, n, () => undefined);   // cert-status появился в nodekit 0.12
      if (renew) await n.op(['tls-renew'], { timeoutMs: 300_000 });
      st = parseCertStatus(await n.must(['tls-status']));
    });
    this.ctx.updateServer(s.id, { tls_state: JSON.stringify(st) });
    return st!;
  }

  /** Ручное включение и выключение ядра (вкладка «Хост»): выключенное ядро панель не запускает при выкате. */
  async setCorePower(s: ServerRow, core: 'xray' | 'sing-box' | 'telemt', on: boolean): Promise<string> {
    const out = await this.ctx.onNode(s, async (n) => { await this.ensureKit(s, n, () => undefined); return n.must([on ? 'core-start' : 'core-stop', core], { timeoutMs: 60_000 }); });
    const off = coresOff(this.ctx, s.id).filter((c) => c !== core);
    setSetting(this.ctx.db, `core.off.${s.id}`, on ? off : [...off, core]);
    // вход сразу перепроверяет выходы «Авто»: выключили выход — трафик уходит на следующий без ожидания
    for (const t of this.vpn.templates().filter((x) => x.entry_id && this.vpn.spec(x).autoEnabled && this.vpn.spec(x).autoMode !== 'random' && (x.entry_id === s.id || this.vpn.relayTargets(x).some((r) => r.id === s.id))))
      void this.checkExits(t, () => undefined).catch(() => undefined);
    return out.trim();
  }

  /** Быстрые действия из списка серверов: перезапуск работающих ядер или перезагрузка хоста (через 5 секунд). */
  async restart(s: ServerRow, what: 'cores' | 'host'): Promise<string> {
    return this.ctx.onNode(s, async (n) => {
      await this.ensureKit(s, n, () => undefined);   // core-restart и host-reboot появились в nodekit 0.16
      if (what === 'host') return (await n.must(['host-reboot'])).trim();
      const done: string[] = [];
      for (const core of ['xray', 'sing-box', 'telemt'] as const) {
        const st = await n.op(['core-status', core]);
        if (/^version=none/m.test(st.stdout) || !/^active=active/m.test(st.stdout)) continue;   // не установлено или выключено (в т. ч. вручную)
        await n.must(['core-restart', core], { timeoutMs: 60_000 });
        done.push(core);
      }
      return done.length ? `перезапущено: ${done.join(', ')}` : 'работающих ядер нет';
    });
  }

  /** Состояние ядер узла: работает ли каждое установленное. */
  async coreStates(s: ServerRow): Promise<Record<string, { active: boolean; manualOff: boolean }>> {
    const off = coresOff(this.ctx, s.id);
    const out: Record<string, { active: boolean; manualOff: boolean }> = {};
    await this.ctx.onNode(s, async (n) => {
      for (const core of ['xray', 'sing-box', 'telemt'] as const) {
        const st = await n.op(['core-status', core]);
        if (/^version=none/m.test(st.stdout)) continue;
        out[core] = { active: /^active=active/m.test(st.stdout), manualOff: off.includes(core) };
      }
    });
    return out;
  }

  async checkExits(t: TemplateRow, log: (l: string) => void, opts: { force?: boolean } = {}): Promise<{ results: ExitHealth[]; switched: { from: string | null; to: string | null; slow?: boolean; spread?: { group: number; reason: SpreadMove['reason'] } } | null } | null> {
    const sp = this.vpn.spec(t);
    if (!sp.autoEnabled || sp.autoMode === 'random' || !t.entry_id) return null;
    const entry = this.ctx.server(t.entry_id);
    if (entry.sudo_mode !== 'restricted' || coreMode(entry) === 'xui') return null;
    const targets = this.vpn.relayTargets(t);
    if (!targets.length) return null;
    if (sp.autoMode === 'spread') return this.spreadTick(t, entry, targets, log, opts);
    const results: ExitHealth[] = [];
    const prev = getSetting<string | null>(this.ctx.db, `auto.override.${t.id}`, null);
    let next: string | null = prev;
    let actualBefore: string | null = getSetting<string | null>(this.ctx.db, `auto.actual.${t.id}`, prev);
    let actualAfter: string | null = null;
    // по порядку — только «отвечает ли выход» (таймаут = выход недоступен), без замера скорости и порогов
    const order = sp.autoMode === 'order';
    // по порядку с порогом скорости: замер каждые speedEveryMin минут, решение о пропуске — раз в decideMin минут по медиане
    // замеров за это время (одна неудачная минута трафик не перекидывает); по кнопке «Проверить сейчас» — и замер, и решение
    const thr = order ? sp.orderMinMbps : 0;
    const due = (key: string, min: number) => { const at = getSetting<string>(this.ctx.db, key, ''); return !at || Date.now() - Date.parse(at) >= min * 60_000 - 5_000; };
    const measure = !order || (thr > 0 && (opts.force || due(`auto.speedAt.${t.id}`, sp.speedEveryMin)));
    const decide = thr > 0 && (opts.force || due(`auto.decideAt.${t.id}`, sp.decideMin));
    const prevSlow = getSetting<string[]>(this.ctx.db, `auto.slow.${t.id}`, []);
    let slow: string[] = prevSlow;
    const tagOf = (exitId: string) => `to-${t.id}-${exitId}`;
    const actualOf = (st: BalancerState) => st.override || st.selected || null;
    // по порядку — цепочка уровней (vpn.ts): трафик идёт через первый уровень, где выход выбран; ни одного — через первый выход
    const orderActual = async (n: NodeSession, first: BalancerState | null): Promise<string | null> => {
      for (let i = 0; i < targets.length; i++) {
        const st = i ? await this.balancerState(n, t.id, orderBalancer(t.id, i)) : first;
        if (st?.override?.startsWith(`lb-${t.id}-`)) continue;   // уровень пропущен (медленный выход)
        if (st?.override) return st.override;
        if (st?.selected) return st.selected;
      }
      return tagOf(targets[0]!.id);
    };
    await this.ctx.onNode(entry, async (n) => {
      await this.ensureKit(entry, n, log);   // проба выходов появилась в nodekit 0.10 — старый nodekit обновляем сам
      // «откуда» — по прошлой проверке: вход переключается сам и раньше, чем панель на него посмотрит
      if (!getSetting<string | null>(this.ctx.db, `auto.actual.${t.id}`, null)) {
        const before = await this.balancerState(n, t.id);
        if (before) actualBefore = order ? await orderActual(n, before) : actualOf(before);
      }
      for (const x of targets) {
        const r = await n.op(['exit-probe', probePort(t.id, x.id), measure ? sp.testMB * 1_000_000 : 0], { timeoutMs: measure ? 120_000 : 60_000 });
        const rtt = Number(r.stdout.match(/^rtt_ms=(\d+)/m)?.[1] ?? NaN);
        const mbps = Number(r.stdout.match(/^mbps=([\d.]+)/m)?.[1] ?? NaN);
        const err = r.code !== 0 ? (r.stderr || r.stdout).trim().slice(0, 200) : Number.isNaN(rtt) ? 'выход не отвечает' : !order && Number.isNaN(mbps) ? 'скачивание не удалось' : null;
        // по порядку скорость не мерили — прошлый замер остаётся
        const ok = !err && (order || (rtt <= sp.maxRttMs && mbps >= sp.minMbps));
        const exitIp = r.stdout.match(/^exit_ip=([0-9a-fA-F.:]+)$/m)?.[1] ?? null;
        const exitLoc = r.stdout.match(/^exit_loc=([A-Z]{2})$/m)?.[1] ?? null;
        results.push({ exitId: x.id, name: x.name, rttMs: Number.isNaN(rtt) ? null : rtt, mbps: Number.isNaN(mbps) ? null : mbps, ok, error: err, exitIp, exitLoc });
        // адрес выхода из прошлой проверки не стираем, если в этой его узнать не удалось
        this.ctx.db.prepare(`INSERT INTO exit_health (template_id, exit_id, rtt_ms, mbps, ok, error, exit_ip, exit_loc, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
          ON CONFLICT(template_id, exit_id) DO UPDATE SET rtt_ms = excluded.rtt_ms, mbps = ${order && !measure ? 'mbps' : 'excluded.mbps'}, ok = excluded.ok, error = excluded.error,
            exit_ip = COALESCE(excluded.exit_ip, exit_ip), exit_loc = COALESCE(excluded.exit_loc, exit_loc), checked_at = excluded.checked_at`)
          .run(t.id, x.id, Number.isNaN(rtt) ? null : rtt, Number.isNaN(mbps) ? null : mbps, ok ? 1 : 0, err, exitIp, exitLoc);
        log(`${entry.name} → ${x.name}: ${err ?? (order && !measure ? `отвечает, ${rtt} мс` : `${rtt} мс, ${Number.isNaN(mbps) ? 'скорость не замерена' : `${mbps} Мбит/с`}`)}${ok || err ? '' : ' — не проходит пороги'}${exitIp ? ` · выход в интернет ${exitIp}${exitLoc ? ` (${exitLoc})` : ''}` : ''}`);
      }
      const good = results.filter((r) => r.ok).sort((a, b) => (b.mbps! - a.mbps!) || (a.rttMs! - b.rttMs!));
      const cur = prev ? results.find((r) => `to-${t.id}-${r.exitId}` === prev) : undefined;
      // по порядку — первый отвечающий выход (вернулся вышестоящий — возвращаемся к нему);
      // по качеству — текущий, пока проходит пороги (без лишних переключений), иначе лучший подходящий; никто — Xray сам
      // по порядку между первым и вторым переключает сам вход (за секунды) — панель не закрепляет выход; только если
      // не отвечают оба, закрепляет следующий отвечающий по списку (вернулся первый или второй — закрепление снимается)
      // по порядку на любой резервный выход переключает сам вход (цепочка уровней) — панель ничего не закрепляет
      // с порогом скорости медленный уровень пропускается: его балансировщику назначается переход на следующий уровень
      let skip: boolean[] = [];
      if (order) {
        if (measure && thr) {
          const ins = this.ctx.db.prepare('INSERT INTO exit_speed (template_id, exit_id, at, mbps) VALUES (?, ?, ?, ?)');
          const now = new Date().toISOString();
          for (const r of results) if (r.ok) ins.run(t.id, r.exitId, now, r.mbps ?? 0);   // отвечает, но не скачал — 0
          this.ctx.db.prepare(`DELETE FROM exit_speed WHERE at < ?`).run(new Date(Date.now() - 24 * 3600_000).toISOString());
        }
        // решение — по медиане замеров за окно decideMin (по кнопке — по только что сделанному замеру)
        const window = opts.force ? 0 : sp.decideMin;
        const basis = results.map((r) => ({ ...r, mbps: opts.force ? r.mbps : medianSpeed(this.ctx, t.id, r.exitId, window) }));
        slow = decide ? slowExits(basis, prevSlow, thr, true) : slowExits(results, prevSlow, thr, false);
        for (const r of results) r.slow = slow.includes(r.exitId);
        skip = skipLevels(results, slow);
        next = skip[0] ? `lb-${t.id}-2` : null;
        for (let i = 1; i < targets.length - 1; i++) {
          const st = await this.setOverride(n, t.id, skip[i] ? `lb-${t.id}-${i + 2}` : null, orderBalancer(t.id, i));
          if (!st) log(`${entry.name}: уровень ${i + 1} не принял ${skip[i] ? 'пропуск' : 'снятие пропуска'} — повторю при следующей проверке`);
        }
        if (thr && decide) for (const [i, r] of results.entries()) if (skip[i]) log(`${r.name}: медиана ${medianSpeed(this.ctx, t.id, r.exitId, opts.force ? 0 : sp.decideMin) ?? '—'} Мбит/с — медленнее ${thr} Мбит/с, трафик идёт на следующий по порядку`);
        setSetting(this.ctx.db, `auto.slow.${t.id}`, slow);
        if (measure && thr) setSetting(this.ctx.db, `auto.speedAt.${t.id}`, new Date().toISOString());
        if (decide) setSetting(this.ctx.db, `auto.decideAt.${t.id}`, new Date().toISOString());
      } else next = cur?.ok ? prev : good[0] ? `to-${t.id}-${good[0].exitId}` : null;
      // сверяемся с входом на каждой проверке, а не только при смене: выбор мог сброситься перезапуском Xray
      const st = await this.setOverride(n, t.id, next);
      if (!st) log(`${entry.name}: вход не принял выбор выхода ${next ?? '(по задержке)'} — повторю при следующей проверке`);
      setSetting(this.ctx.db, `auto.override.${t.id}`, next);
      actualAfter = st ? (order ? await orderActual(n, st) : actualOf(st)) : null;
      setSetting(this.ctx.db, `auto.actual.${t.id}`, actualAfter);
    });
    setSetting(this.ctx.db, `auto.checked.${t.id}`, new Date().toISOString());
    const nameOf = (tag: string | null) => (tag ? targets.find((x) => tag === `to-${t.id}-${x.id}`)?.name ?? tag : null);
    // уведомляем о реальной смене выхода, через который идёт трафик
    const fromSlow = !!actualBefore && slow.some((id) => tagOf(id) === actualBefore);
    return { results, switched: actualAfter && actualAfter !== actualBefore ? { from: nameOf(actualBefore), to: nameOf(actualAfter), ...(fromSlow ? { slow: true } : {}) } : !next && prev && sp.autoMode !== 'order' ? { from: nameOf(prev), to: null } : null };
  }

  /**
   * Замер канала сервера на нём самом: ~25 с канал занят целиком (скачивание, затем отдача). Результат — по серверу;
   * в «Авто по нагрузке» он ёмкость выхода, если в конфигурации не задано своё значение. Первый замер может
   * поставить speedtest от Ookla (snap / официальный архив) — до нескольких минут.
   */
  async measureLink(s: ServerRow, log: (l: string) => void = () => undefined): Promise<LinkTest> {
    const out = await this.ctx.onNode(s, async (n) => {
      await this.ensureKit(s, n, log);   // link-test появился вместе с замером каналов
      return n.must(['link-test'], { timeoutMs: 900_000 });
    });
    for (const l of out.trim().split('\n')) log(l);
    const res = parseLinkTest(out);
    if (!res) throw new Error(`замер не удался: ${out.trim().slice(-200) || 'нет ответа от speed.cloudflare.com'}`);
    setSetting(this.ctx.db, `link.${s.id}`, res);
    return res;
  }

  /** Пользователи «Авто» конфигурации по группам «по нагрузке» (как в рендере входа). */
  spreadMembers(t: TemplateRow, groups: number): number[] {
    const ready = this.vpn.relayTargets(t);
    const count = Array.from({ length: groups }, () => 0);
    for (const u of this.vpn.users(true))
      if (json<string[]>(u.modes, []).includes('via') && ready.some((x) => this.vpn.userAllows(u, x.id, t.id)) && !this.vpn.profileOff(u, `v:${t.id}:auto`))
        count[spreadGroupOf(u.id, groups)]!++;
    return count;
  }

  /** Назначить группе выход: балансировщик её первого уровня ведёт на уровень этого выхода в её цепочке (домашний — снять). */
  private spreadAssign(n: NodeSession, t: string, g: number, chain: string[], to: string) {
    const k = chain.indexOf(to);
    return this.setOverride(n, t, k > 0 ? spreadLoop(t, g, k) : null, spreadBal(t, g, 0));
  }

  /**
   * «Авто» по нагрузке (spread.ts), раз в минуту: доступность выходов (короткая проба), нагрузка групп (счётчики их
   * outbound'ов на входе) и каналов выходов (счётчики интерфейсов серверов) → не больше одного перевода группы.
   */
  async spreadTick(t: TemplateRow, entry: ServerRow, targets: ServerRow[], log: (l: string) => void, opts: { force?: boolean } = {}) {
    const sp = this.vpn.spec(t);
    const db = this.ctx.db;
    // раскладка групп — та, что выкачена на вход (запоминается при выкате); до первого выката переводить нечего
    const layout = getSetting<{ ids: string[]; homes: string[] } | null>(db, `spread.layout.${t.id}`, null);
    const ids = layout?.ids.filter((id) => targets.some((x) => x.id === id)) ?? [];
    const homes = layout && ids.length === layout.ids.length ? layout.homes : [];
    const assigned = getSetting<Record<string, string>>(db, `spread.cur.${t.id}`, {});   // группа → выход, куда переведена
    const curOf = (g: number) => (assigned[g] && ids.includes(assigned[g]!) ? assigned[g]! : homes[g]!);
    const nameOf = (id: string) => targets.find((x) => x.id === id)?.name ?? id;
    const caps = spreadCaps(db, sp.exitCapMbps, targets.map((x) => x.id));   // своё значение, иначе замер на сервере
    const cap = (id: string) => caps[id] ?? 0;
    // каналы выходов: счётчики интерфейсов сервера, скорость — по разнице с прошлой проверкой (первая — без неё)
    const linkLoad = new Map<string, number>();
    for (const x of targets) {
      if (x.fail_since) continue;
      // справедливое деление канала: cake чуть ниже ёмкости — очередь у нас, а не у хостера; меняем только при смене
      const fair = sp.spreadFair && cap(x.id) > 0 ? Math.round(cap(x.id) * 0.95) : 0;
      const fairWas = getSetting<number>(db, `netfair.${x.id}`, 0);
      if (fair !== fairWas) {
        try {
          const out = await this.ctx.onNode(x, async (n) => { await this.ensureKit(x, n, log); return n.must(fair ? ['net-fair', 'on', fair] : ['net-fair', 'off'], { timeoutMs: 60_000 }); });
          setSetting(db, `netfair.${x.id}`, fair);
          log(`${x.name}: ${fair ? `деление канала включено (cake ${fair} Мбит/с, BBR)` : 'деление канала выключено'} — ${out.trim()}`);
        } catch (e) { log(`${x.name}: деление канала не ${fair ? 'включилось' : 'выключилось'}: ${(e as Error).message}`); }
      }
      if (!(cap(x.id) > 0)) continue;
      try {
        const r = await this.ctx.onNode(x, (n) => n.op(['host-stat'], { timeoutMs: 20_000 }));
        const net = parseHostStat(`spread:${x.id}`, r.stdout).net;
        if (net?.rxBps != null && net.txBps != null) linkLoad.set(x.id, (Math.max(net.rxBps, net.txBps) * 8) / 1e6);
      } catch { /* нет связи — оценим по счётчикам входа */ }
    }
    const results: ExitHealth[] = [];
    const groupMbps = homes.map(() => 0);
    const viaEntry = new Map<string, number>();
    let move: SpreadMove | null = null;
    await this.ctx.onNode(entry, async (n) => {
      await this.ensureKit(entry, n, log);   // xray-ostats появился вместе с режимом «по нагрузке»
      for (const x of targets) {
        const r = await n.op(['exit-probe', probePort(t.id, x.id), 0], { timeoutMs: 60_000 });
        const rtt = Number(r.stdout.match(/^rtt_ms=(\d+)/m)?.[1] ?? NaN);
        const err = r.code !== 0 ? (r.stderr || r.stdout).trim().slice(0, 200) : Number.isNaN(rtt) ? 'выход не отвечает' : null;
        const exitIp = r.stdout.match(/^exit_ip=([0-9a-fA-F.:]+)$/m)?.[1] ?? null;
        const exitLoc = r.stdout.match(/^exit_loc=([A-Z]{2})$/m)?.[1] ?? null;
        results.push({ exitId: x.id, name: x.name, rttMs: Number.isNaN(rtt) ? null : rtt, mbps: null, ok: !err, error: err, exitIp, exitLoc });
        // сервер или конфигурацию могли удалить, пока шла проверка (FOREIGN KEY) — замер просто не сохраняем
        try {
          db.prepare(`INSERT INTO exit_health (template_id, exit_id, rtt_ms, mbps, ok, error, exit_ip, exit_loc, checked_at) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(template_id, exit_id) DO UPDATE SET rtt_ms = excluded.rtt_ms, ok = excluded.ok, error = excluded.error,
              exit_ip = COALESCE(excluded.exit_ip, exit_ip), exit_loc = COALESCE(excluded.exit_loc, exit_loc), checked_at = excluded.checked_at`)
            .run(t.id, x.id, Number.isNaN(rtt) ? null : rtt, err ? 0 : 1, err, exitIp, exitLoc);
        } catch { /* удалён во время проверки */ }
      }
      // нагрузка групп: счётчики их пользователей с прошлой проверки (читаются без обнуления; учёт трафика обнуляет сам)
      const prev = getSetting<{ at: number; v: Record<string, number> } | null>(db, `spread.ustats.${t.id}`, null);
      const st = await n.op(['xray-ustats'], { timeoutMs: 20_000 });
      const now = Date.now();
      if (st.code === 0) {
        const cur = parseAutoUserStats(st.stdout, t.id);
        const dt = prev ? (now - prev.at) / 1000 : 0;
        if (prev && dt >= 10 && dt <= 1800)
          for (const [u, bytes] of counterDeltas(cur, prev.v)) {
            const g = spreadGroupOf(u, homes.length);
            if (!homes.length) break;
            const mbps = (bytes * 8) / dt / 1e6;
            groupMbps[g]! += mbps;
            viaEntry.set(curOf(g), (viaEntry.get(curOf(g)) ?? 0) + mbps);
          }
        setSetting(db, `spread.ustats.${t.id}`, { at: now, v: Object.fromEntries(cur) });
      }
      const exits: SpreadExit[] = targets.map((x) => ({
        id: x.id, cap: cap(x.id), alive: !!results.find((r) => r.exitId === x.id)?.ok,
        // канал целиком (все конфигурации и прямые пользователи); нет счётчиков сервера — хотя бы эта конфигурация
        load: linkLoad.get(x.id) ?? viaEntry.get(x.id) ?? 0,
      }));
      const groups: SpreadGroup[] = homes.map((home, g) => ({ g, home, cur: curOf(g), mbps: groupMbps[g]! }));
      const movedAt = getSetting<string>(db, `spread.movedAt.${t.id}`, '');
      const cooldownOk = !!opts.force || !movedAt || now - Date.parse(movedAt) >= SPREAD_COOLDOWN_MIN * 60_000;
      move = homes.length ? planSpread(exits, groups, sp.spreadHighPct / 100, cooldownOk) : null;
      if (move) {
        const ok = await this.spreadAssign(n, t.id, move.g, spreadChain(homes[move.g]!, ids), move.to);
        if (ok) {
          if (move.to === homes[move.g]) delete assigned[move.g]; else assigned[move.g] = move.to;
          groups[move.g]!.cur = move.to;
          setSetting(db, `spread.cur.${t.id}`, assigned);
          setSetting(db, `spread.movedAt.${t.id}`, new Date(now).toISOString());
        } else {
          log(`${entry.name}: группа ${move.g + 1} не принята входом — повторю при следующей проверке`);
          move = null;
        }
      } else {
        // переведённые группы: вход мог перезапуститься и забыть назначение — сверяем и возвращаем
        for (const gr of groups) {
          if (gr.cur === gr.home) continue;
          const want = spreadLoop(t.id, gr.g, spreadChain(gr.home, ids).indexOf(gr.cur));
          const bi = await this.balancerState(n, t.id, spreadBal(t.id, gr.g, 0));
          if (bi && bi.override !== want) await this.spreadAssign(n, t.id, gr.g, spreadChain(gr.home, ids), gr.cur);
        }
      }
      const users = this.spreadMembers(t, homes.length);
      setSetting(db, `spread.state.${t.id}`, {
        at: new Date(now).toISOString(), high: sp.spreadHighPct,
        exits: exits.map((e) => ({ id: e.id, cap: e.cap, capFrom: (sp.exitCapMbps[e.id] ?? 0) > 0 ? 'manual' : e.cap > 0 ? 'test' : null, load: Math.round(e.load * 10) / 10, measured: linkLoad.has(e.id) })),
        groups: groups.map((gr) => ({ g: gr.g, home: gr.home, cur: gr.cur, mbps: Math.round(gr.mbps * 10) / 10, users: users[gr.g] ?? 0 })),
      });
      for (const e of exits) log(`${nameOf(e.id)}: ${e.alive ? 'отвечает' : 'не отвечает'}, канал ${Math.round(e.load)}${e.cap ? ` из ${e.cap} Мбит/с (${Math.round((e.load / e.cap) * 100)}%)` : ' Мбит/с'}, групп: ${groups.filter((gr) => gr.cur === e.id).length}`);
    });
    setSetting(db, `auto.checked.${t.id}`, new Date().toISOString());
    const mv = move as SpreadMove | null;
    if (mv) log(`группа ${mv.g + 1} переведена с ${nameOf(mv.from)} на ${nameOf(mv.to)}`);
    return {
      results,
      switched: mv ? { from: nameOf(mv.from), to: nameOf(mv.to), spread: { group: mv.g + 1, reason: mv.reason } } : null,
    };
  }

  /**
   * Лимит устройств: кто с каких IP онлайн на Xray-узлах → блокировки лишних устройств → правила на узлах,
   * где они изменились (на ходу, без перезапуска Xray). Узел, недоступный сейчас, догонит при следующем цикле.
   */
  async syncDevices(log: (l: string) => void = () => undefined): Promise<{ newlyLimited: string[]; blocked: Map<string, string[]> }> {
    const nodes = this.ctx.servers().filter((s) => s.sudo_mode === 'restricted' && s.host_key_fp && coreMode(s) !== 'xui'
      && json<Record<string, unknown>>(s.cores, {}).xray && this.vpn.inbounds(`server_id = ? AND state = 'active'`, s.id).length);
    const online = new Map<string, Set<string>>();
    let seen = 0;
    for (const s of nodes) {
      try {
        const out = await this.ctx.onNode(s, async (n) => {
          let r = await n.op(['xray-online'], { timeoutMs: 60_000 });
          if (r.code === 126) { await this.ensureKit(s, n, log); r = await n.op(['xray-online'], { timeoutMs: 60_000 }); }   // старый nodekit
          return r.code === 0 ? r.stdout : null;
        });
        if (out === null) continue;
        for (const [email, ips] of Object.entries(JSON.parse(out || '{}') as Record<string, string[]>)) {
          const uid = userOfEmail(email);
          if (!uid) continue;
          const set = online.get(uid) ?? new Set<string>();
          for (const ip of ips) set.add(ip);
          online.set(uid, set);
        }
        seen++;
      } catch (e) { log(`${s.name}: онлайн не получен — ${(e as Error).message}`); }
    }
    // ни один узел не ответил — не делаем выводов (иначе все устройства «ушли» и освободили места)
    if (nodes.length && !seen) return { newlyLimited: [], blocked: blockedDevices(this.ctx) };
    const res = updateDevices(this.ctx, online);
    const sig = limitsSig(this.ctx);
    for (const s of nodes) {
      if (getSetting<string>(this.ctx.db, `limits.applied.${s.id}`, '') === sig) continue;
      const gen = 'r' + Date.now().toString(36);
      const rules = this.vpn.routingTail(s, gen);
      if (!rules) continue;
      try {
        await this.ctx.onNode(s, async (n) => {
          const r = await n.op(['xray-rules'], { stdin: JSON.stringify({ gen, rules }), timeoutMs: 60_000 });
          if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
        });
        setSetting(this.ctx.db, `limits.applied.${s.id}`, sig);
      } catch (e) { log(`${s.name}: правила лимита устройств не применены — ${(e as Error).message}`); }
    }
    return res;
  }

  /** Выкат шаблона: canary → остальные direct-узлы → вход. Ошибка — откат inbound и остановка. */
  async rollout(t: TemplateRow, log: (l: string) => void): Promise<void> {
    const nodeIds = json<string[]>(t.node_ids, []);
    const plan: Array<{ s: ServerRow; kind: 'direct' | 'relay' }> = nodeIds.map((id) => ({ s: this.ctx.server(id), kind: 'direct' as const }));
    if (t.entry_id) plan.push({ s: this.ctx.server(t.entry_id), kind: 'relay' });
    if (!plan.length) throw new Error('у шаблона нет узлов');
    log(`ревизия ${t.revision}: ${plan.map((p) => `${p.s.name}(${p.kind})`).join(' → ')}`);

    for (const [i, { s, kind }] of plan.entries()) {
      if (s.sudo_mode !== 'restricted') throw new Error(`${s.name}: сначала установите nodekit`);
      const port = kind === 'relay' ? t.entry_port! : t.port;
      // вход eskadra может принимать Hysteria2 (sing-box, UDP)
      const sp = kind === 'relay' ? entrySpec(this.vpn.spec(t)) : this.vpn.spec(t);
      const core = PROTOCOLS[sp.protocol].core;
      const proto = protoOf(sp.protocol);
      // Hysteria2 через вход: вход только пересылает UDP ядром ОС — ядро VPN на нём не нужно, 3x-ui не мешает
      const nat = kind === 'relay' && natRelayOf(sp);
      const bad = this.lintPort(s, port, proto, t.id);
      if (bad) throw new Error(`${s.name}: ${bad}`);
      if (kind === 'relay' && !nat && coreMode(s) === 'xui')
        throw new Error(`${s.name}: на узле с 3x-ui «вход» недоступен — нужны собственные маршруты Xray. Выберите вход без 3x-ui.`);
      log(`${i === 0 ? 'canary' : 'волна'}: ${s.name}`);
      let ib: InboundRow | undefined;
      try {
        await this.ctx.onNode(s, async (n) => {
          await this.ensureKit(s, n, log);
          if (!nat) await this.ensureCore(s, n, core, log);
          this.lastLog = log;
          ib = await this.ensureInbound(t, s, kind, n);
          this.ctx.db.prepare(`UPDATE inbounds SET state = 'deploying', error = NULL WHERE id = ?`).run(ib.id);
          await n.must(['port-open', proto, port]);
          await this.applyServer(this.ctx.server(s.id), n, log);
          if (nat) {
            // слушать на входе некому: проверяем, что пересылка порта на выход стоит в ядре ОС
            const st = (await n.must(['hy2-relay', 'status'])).trim();
            if (!st.split(/\s+/).includes(`${port}=${this.vpn.natExit(t)?.server.host}:${this.vpn.natExit(t)?.inbound.port}`))
              throw new Error(`после применения пересылка порта ${port} на выход не стоит (${st || 'пусто'})`);
          } else if (coreMode(s) === 'xui' && t.core === 'xray') {
            // 3x-ui применяет inbound сам (иногда с перезапуском Xray) — ждём до 30 с
            let up = false;
            for (let i = 0; i < 10 && !up; i++) {
              up = String(await this.xui(s, n, 'listening', { port })) === 'yes';
              if (!up) await new Promise((r) => setTimeout(r, 3000));
            }
            if (!up) throw new Error(`3x-ui не поднял порт ${port} за 30 с — проверьте журнал Xray в 3x-ui`);
          } else {
            const st = await n.op(['core-status', core]);
            if (!new RegExp(`:${port}\\b`).test(st.stdout)) throw new Error(`после применения порт ${port} не слушается`);
          }
        });
        if (proto === 'tcp') {
          const ok = await tcpProbe(s.host, port);
          log(`внешняя проба ${s.host}:${port}/tcp — ${ok ? 'ок' : 'НЕТ ОТВЕТА'}`);
          if (!ok) throw new Error(`порт ${port} не отвечает снаружи (firewall провайдера, ufw или firewalld?)`);
        }
        this.ctx.db.prepare(`UPDATE inbounds SET state = 'active', applied_at = datetime('now') WHERE id = ?`).run(ib!.id);
      } catch (e) {
        const msg = (e as Error).message;
        log(`ошибка: ${msg}`);
        if (ib) {
          this.ctx.db.prepare(`UPDATE inbounds SET state = 'error', error = ? WHERE id = ?`).run(msg, ib.id);
          try {
            await this.ctx.onNode(s, async (n) => {
              await this.applyServer(this.ctx.server(s.id), n, log);
              if (!this.portUsed(s.id, port, proto)) await n.op(['port-close', proto, port]);
            });
            log(`${s.name}: inbound откатан`);
          } catch (e2) { log(`откат не удался: ${(e2 as Error).message}`); }
        }
        throw e;
      }
    }
    this.ctx.db.prepare('UPDATE templates SET applied_revision = revision WHERE id = ?').run(t.id);
    // входы других шаблонов могли получить новые цели — переприменим их
    this.vpn.markDirty();
  }

  portUsed(serverId: string, port: number, proto: string): boolean {
    return !!this.ctx.db.prepare(`SELECT 1 FROM inbounds WHERE server_id = ? AND port = ? AND proto = ? AND state IN ('active','deploying')`).get(serverId, port, proto);
  }

  /** Снять шаблон с узлов: inbounds убираются, конфиги переприменяются, порты закрываются. */
  async removeTemplate(t: TemplateRow, log: (l: string) => void) {
    const ibs = this.vpn.inbounds('template_id = ?', t.id);
    this.ctx.db.prepare(`UPDATE inbounds SET state = 'removed' WHERE template_id = ?`).run(t.id);
    for (const sid of [...new Set(ibs.map((i) => i.server_id))]) {
      const s = this.ctx.server(sid);
      await this.ctx.onNode(s, async (n) => {
        await this.applyServer(s, n, log);
        for (const ib of ibs.filter((i) => i.server_id === sid))
          if (!this.portUsed(sid, ib.port, ib.proto)) await n.op(['port-close', ib.proto, ib.port]);
      });
      log(`${s.name}: снято`);
    }
    this.ctx.db.prepare('DELETE FROM templates WHERE id = ?').run(t.id);
  }

  /**
   * Заранее разрешить на узлах вход ключом панели с адресов всех серверов флота (fleetctl allow: from= и firewall).
   * Пока узел доступен, это делается само; когда станет недоступен — его можно перевести на «через сервер» или
   * «через конфигурацию» без команд в консоли хостера. Что уже разрешено — в peers.allowed.<узел>, повторно не шлём.
   */
  async syncPeerAccess(log: (l: string) => void) {
    for (const s of this.ctx.servers().filter((x) => x.sudo_mode === 'restricted' && x.host_key_fp && !x.fail_since)) {
      const done = peersAllowed(this.ctx, s.id);
      const todo = this.ctx.panelSources(s).filter((ip) => net.isIP(ip) && !done.includes(ip));
      if (!todo.length) continue;
      try {
        await this.ctx.onNode(s, async (n) => {
          for (const ip of todo) {
            const r = await n.op(['allow', ip], { timeoutMs: 60_000 });
            if (r.code === 0) done.push(ip);
            else log(`${s.name}: не удалось разрешить ${ip} — ${(r.stderr || r.stdout).trim()}`);
          }
        });
      } catch (e) { log(`${s.name}: адреса флота не разрешены — ${(e as Error).message}`); }
      setSetting(this.ctx.db, `peers.allowed.${s.id}`, done);
    }
  }

  /** Раздать адрес ноды соседям (fleet4/6) — §7.12.1. */
  async peerSync(log: (l: string) => void) {
    const all = this.ctx.servers().filter((s) => s.sudo_mode === 'restricted');
    for (const s of all) {
      try {
        await this.ctx.onNode(s, async (n) => {
          for (const p of all) if (p.id !== s.id && net.isIP(p.host)) await n.op(['peer-add', p.host]);
        });
      } catch (e) { log(`${s.name}: ${(e as Error).message}`); }
    }
  }

  failThresholdMin = () => getSetting<number>(this.ctx.db, 'check.failThresholdMin', 120);
}
