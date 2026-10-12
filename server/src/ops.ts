import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { coreMode, foreignCore, panelPorts, type Ctx, type InboundRow, type NodeSession, type ServerRow, type TemplateRow } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { json, Vpn } from './vpn.js';
import { releaseFor, type Core } from './releases.js';
import { certName, probePort, PROTOCOLS, protoOf } from './protocols.js';

/** Ядра узла, остановленные вручную на вкладке «Хост». */
export const coresOff = (ctx: Ctx, serverId: string) => getSetting<string[]>(ctx.db, `core.off.${serverId}`, []);

/**
 * Отпечаток конфигов ядер, которые панель сейчас сформировала бы для узла. Хранится после выката; при запуске
 * панели (в т. ч. после обновления) узлы с другим отпечатком переприменяются сами — новая версия Эскадры
 * доходит до серверов без ручного «Выкатить».
 */
export function renderHash(vpn: Vpn, s: ServerRow): string {
  const part = (f: () => unknown) => { try { return JSON.stringify(f()); } catch (e) { return `error:${(e as Error).message}`; } };
  return createHash('sha256').update([part(() => vpn.renderXray(s)), part(() => vpn.renderSingbox(s)), part(() => vpn.renderTelemt(s))].join('\n')).digest('hex');
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
export interface ExitHealth { exitId: string; name: string; rttMs: number | null; mbps: number | null; ok: boolean; error: string | null; exitIp: string | null; exitLoc: string | null }

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
    const sp = this.vpn.spec(t);
    const proto = protoOf(sp.protocol);
    let ib = this.vpn.inbounds('template_id = ? AND server_id = ? AND kind = ?', t.id, s.id, kind)[0];
    if (!ib) {
      const id = 'ib-' + randomBytes(4).toString('hex');
      this.ctx.db.prepare('INSERT INTO inbounds (id, template_id, server_id, kind, port, proto, short_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(id, t.id, s.id, kind, port, proto, randomBytes(4).toString('hex'));
      ib = this.vpn.inbounds('id = ?', id)[0]!;
    } else if (ib.port !== port) {
      this.ctx.db.prepare('UPDATE inbounds SET port = ? WHERE id = ?').run(port, ib.id);
      ib.port = port;
    }
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
      const sni = json<string[]>(t.sni, [])[0] ?? 'localhost';
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
        continue;
      }
      await this.ensureCore(s, n, core, log);
      const name = `${core}-${Date.now()}.${core === 'telemt' ? 'toml' : 'json'}`;
      await n.stage(name, typeof cfg === 'string' ? cfg : JSON.stringify(cfg, null, 2));
      const out = await n.must(['core-apply', core, name], { timeoutMs: 60_000 });
      log(`${core}: ${out.trim()}`);
      // остановлено вручную (проверка отказоустойчивости) — конфиг обновлён, но ядро остаётся выключенным
      if (coresOff(this.ctx, s.id).includes(core)) { await n.op(['core-stop', core]); log(`${core}: остановлен вручную — не запускаю`); }
    }
    this.ctx.updateServer(s.id, { config_dirty: 0 });
    if (!xuiMode) setSetting(this.ctx.db, `applied.${s.id}`, renderHash(this.vpn, s));
    // перезапуск Xray сбрасывает переключение балансировщика — возвращаем выбранные выходы «Авто» входа
    // (с повтором: сразу после перезапуска API Xray может ещё не отвечать) и сверяем с тем, что реально выбрано
    if (!xuiMode) for (const t of this.vpn.templates().filter((x) => x.entry_id === s.id)) {
      const ov = getSetting<string | null>(this.ctx.db, `auto.override.${t.id}`, null);
      if (ov && this.vpn.spec(t).autoMode !== 'random') {
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
  async balancerState(n: NodeSession, templateId: string): Promise<BalancerState | null> {
    const r = await n.op(['xray-bi', `bal-${templateId}`]);
    return r.code === 0 ? parseBalancerInfo(r.stdout) : null;
  }

  /** Назначить выход балансировщику (null — снять) и убедиться, что вход его принял; до 5 попыток. */
  async setOverride(n: NodeSession, templateId: string, tag: string | null): Promise<BalancerState | null> {
    for (let i = 0; i < 5; i++) {
      if (i) await new Promise((r) => setTimeout(r, 1500));
      const r = await n.op(['xray-bo', `bal-${templateId}`, tag ?? 'clear']);
      if (r.code !== 0) continue;
      const st = await this.balancerState(n, templateId);
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
    for (const t of this.vpn.templates().filter((x) => x.entry_id && this.vpn.spec(x).autoMode !== 'random' && (x.entry_id === s.id || this.vpn.relayTargets(x).some((r) => r.id === s.id))))
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

  async checkExits(t: TemplateRow, log: (l: string) => void): Promise<{ results: ExitHealth[]; switched: { from: string | null; to: string | null } | null } | null> {
    const sp = this.vpn.spec(t);
    if (sp.autoMode === 'random' || !t.entry_id) return null;
    const entry = this.ctx.server(t.entry_id);
    if (entry.sudo_mode !== 'restricted' || coreMode(entry) === 'xui') return null;
    const targets = this.vpn.relayTargets(t);
    if (!targets.length) return null;
    const results: ExitHealth[] = [];
    const prev = getSetting<string | null>(this.ctx.db, `auto.override.${t.id}`, null);
    let next: string | null = prev;
    let actualBefore: string | null = getSetting<string | null>(this.ctx.db, `auto.actual.${t.id}`, prev);
    let actualAfter: string | null = null;
    // по порядку — только «отвечает ли выход» (таймаут = выход недоступен), без замера скорости и порогов
    const order = sp.autoMode === 'order';
    const tagOf = (exitId: string) => `to-${t.id}-${exitId}`;
    // по порядку балансировщик видит только первый выход: не выбран он и не закреплён другой — трафик идёт через fallback (второй)
    const actualOf = (st: BalancerState) => st.override || st.selected || (order ? tagOf((targets[1] ?? targets[0])!.id) : null);
    await this.ctx.onNode(entry, async (n) => {
      await this.ensureKit(entry, n, log);   // проба выходов появилась в nodekit 0.10 — старый nodekit обновляем сам
      // «откуда» — по прошлой проверке: вход переключается сам и раньше, чем панель на него посмотрит
      if (!getSetting<string | null>(this.ctx.db, `auto.actual.${t.id}`, null)) {
        const before = await this.balancerState(n, t.id);
        if (before) actualBefore = actualOf(before);
      }
      for (const x of targets) {
        const r = await n.op(['exit-probe', probePort(t.id, x.id), order ? 0 : sp.testMB * 1_000_000], { timeoutMs: order ? 60_000 : 120_000 });
        const rtt = Number(r.stdout.match(/^rtt_ms=(\d+)/m)?.[1] ?? NaN);
        const mbps = Number(r.stdout.match(/^mbps=([\d.]+)/m)?.[1] ?? NaN);
        const err = r.code !== 0 ? (r.stderr || r.stdout).trim().slice(0, 200) : Number.isNaN(rtt) ? 'выход не отвечает' : !order && Number.isNaN(mbps) ? 'скачивание не удалось' : null;
        const ok = !err && (order || (rtt <= sp.maxRttMs && mbps >= sp.minMbps));
        const exitIp = r.stdout.match(/^exit_ip=([0-9a-fA-F.:]+)$/m)?.[1] ?? null;
        const exitLoc = r.stdout.match(/^exit_loc=([A-Z]{2})$/m)?.[1] ?? null;
        results.push({ exitId: x.id, name: x.name, rttMs: Number.isNaN(rtt) ? null : rtt, mbps: Number.isNaN(mbps) ? null : mbps, ok, error: err, exitIp, exitLoc });
        // адрес выхода из прошлой проверки не стираем, если в этой его узнать не удалось
        this.ctx.db.prepare(`INSERT INTO exit_health (template_id, exit_id, rtt_ms, mbps, ok, error, exit_ip, exit_loc, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
          ON CONFLICT(template_id, exit_id) DO UPDATE SET rtt_ms = excluded.rtt_ms, mbps = excluded.mbps, ok = excluded.ok, error = excluded.error,
            exit_ip = COALESCE(excluded.exit_ip, exit_ip), exit_loc = COALESCE(excluded.exit_loc, exit_loc), checked_at = excluded.checked_at`)
          .run(t.id, x.id, Number.isNaN(rtt) ? null : rtt, Number.isNaN(mbps) ? null : mbps, ok ? 1 : 0, err, exitIp, exitLoc);
        log(`${entry.name} → ${x.name}: ${err ?? (order ? `отвечает, ${rtt} мс` : `${rtt} мс, ${mbps} Мбит/с`)}${ok || err ? '' : ' — не проходит пороги'}${exitIp ? ` · выход в интернет ${exitIp}${exitLoc ? ` (${exitLoc})` : ''}` : ''}`);
      }
      const good = results.filter((r) => r.ok).sort((a, b) => (b.mbps! - a.mbps!) || (a.rttMs! - b.rttMs!));
      const cur = prev ? results.find((r) => `to-${t.id}-${r.exitId}` === prev) : undefined;
      // по порядку — первый отвечающий выход (вернулся вышестоящий — возвращаемся к нему);
      // по качеству — текущий, пока проходит пороги (без лишних переключений), иначе лучший подходящий; никто — Xray сам
      // по порядку между первым и вторым переключает сам вход (за секунды) — панель не закрепляет выход; только если
      // не отвечают оба, закрепляет следующий отвечающий по списку (вернулся первый или второй — закрепление снимается)
      if (order) { const further = !results[0]?.ok && !results[1]?.ok ? results.slice(2).find((r) => r.ok) : undefined; next = further ? tagOf(further.exitId) : null; }
      else next = cur?.ok ? prev : good[0] ? `to-${t.id}-${good[0].exitId}` : null;
      // сверяемся с входом на каждой проверке, а не только при смене: выбор мог сброситься перезапуском Xray
      const st = await this.setOverride(n, t.id, next);
      if (!st) log(`${entry.name}: вход не принял выбор выхода ${next ?? '(по задержке)'} — повторю при следующей проверке`);
      setSetting(this.ctx.db, `auto.override.${t.id}`, next);
      actualAfter = st ? actualOf(st) : null;
      setSetting(this.ctx.db, `auto.actual.${t.id}`, actualAfter);
    });
    setSetting(this.ctx.db, `auto.checked.${t.id}`, new Date().toISOString());
    const nameOf = (tag: string | null) => (tag ? targets.find((x) => tag === `to-${t.id}-${x.id}`)?.name ?? tag : null);
    // уведомляем о реальной смене выхода, через который идёт трафик
    return { results, switched: actualAfter && actualAfter !== actualBefore ? { from: nameOf(actualBefore), to: nameOf(actualAfter) } : !next && prev && sp.autoMode !== 'order' ? { from: nameOf(prev), to: null } : null };
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
      const sp = this.vpn.spec(t);
      const core = PROTOCOLS[sp.protocol].core;
      const proto = protoOf(sp.protocol);
      const bad = this.lintPort(s, port, proto, t.id);
      if (bad) throw new Error(`${s.name}: ${bad}`);
      if (kind === 'relay' && coreMode(s) === 'xui')
        throw new Error(`${s.name}: на узле с 3x-ui «вход» недоступен — нужны собственные маршруты Xray. Выберите вход без 3x-ui.`);
      log(`${i === 0 ? 'canary' : 'волна'}: ${s.name}`);
      let ib: InboundRow | undefined;
      try {
        await this.ctx.onNode(s, async (n) => {
          await this.ensureKit(s, n, log);
          await this.ensureCore(s, n, core, log);
          this.lastLog = log;
          ib = await this.ensureInbound(t, s, kind, n);
          this.ctx.db.prepare(`UPDATE inbounds SET state = 'deploying', error = NULL WHERE id = ?`).run(ib.id);
          await n.must(['port-open', proto, port]);
          await this.applyServer(this.ctx.server(s.id), n, log);
          if (coreMode(s) === 'xui' && t.core === 'xray') {
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
