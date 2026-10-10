import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { coreMode, foreignCore, panelPorts, type Ctx, type InboundRow, type NodeSession, type ServerRow, type TemplateRow } from './ctx.js';
import { getSetting } from './db.js';
import { json, Vpn } from './vpn.js';
import { releaseFor, type Core } from './releases.js';

const archOf = (s: ServerRow) => (s.arch === 'arm64' ? 'arm64' : 'amd64') as 'amd64' | 'arm64';
import { buildKitBundle, kitVersion } from './nodekit.js';
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
    if (needsLogin && (!s.xui_user || !s.xui_pass_sealed)) throw new Error(`${s.name}: укажите логин и пароль 3x-ui (вкладка «Хост»)`);
    const payload = JSON.stringify({ action, ...extra, ...(needsLogin ? { user: s.xui_user, pass: this.ctx.open(s.xui_pass_sealed!) } : {}) });
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
  async upgradeCore(s: ServerRow, core: Core, version: string, log: (l: string) => void): Promise<string> {
    if (core === 'xray' && coreMode(s) === 'xui') throw new Error(`${s.name}: Xray принадлежит 3x-ui — обновляйте его в самом 3x-ui`);
    const cores = json<Record<string, { version: string; previous?: string }>>(s.cores, {});
    if (!cores[core]) throw new Error(`${s.name}: ${core} не установлен — он появится при выкате конфигурации`);
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
    const proto: 'tcp' | 'udp' = t.protocol === 'hysteria2' ? 'udp' : 'tcp';
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
    if (t.protocol === 'vless-reality' && !ib.private_key_sealed) {
      const out = coreMode(s) === 'xui' ? String(await this.xui(s, n, 'x25519')) : await n.must(['xray-x25519']);
      const priv = out.match(/^private=(\S+)/m)?.[1];
      const pub = out.match(/^public=(\S+)/m)?.[1];
      if (!priv || !pub) throw new Error('не удалось получить ключи REALITY с узла');
      this.ctx.db.prepare('UPDATE inbounds SET private_key_sealed = ?, public_key = ? WHERE id = ?').run(this.ctx.seal(priv), pub, ib.id);
    }
    if (t.protocol === 'hysteria2' && !ib.tls_pin) {
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
    for (const core of ['xray', 'sing-box'] as const) {
      if (core === 'xray' && xuiMode) continue;
      const cfg = core === 'xray' ? this.vpn.renderXray(s) : this.vpn.renderSingbox(s);
      if (!cfg) {
        if (cores[core]) { await n.op(['core-stop', core]); log(`${core}: inbounds нет, ядро остановлено`); }
        continue;
      }
      await this.ensureCore(s, n, core, log);
      const name = `${core}-${Date.now()}.json`;
      await n.stage(name, JSON.stringify(cfg, null, 2));
      const out = await n.must(['core-apply', core, name], { timeoutMs: 60_000 });
      log(`${core}: ${out.trim()}`);
    }
    this.ctx.updateServer(s.id, { config_dirty: 0 });
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
      const proto = t.protocol === 'hysteria2' ? 'udp' : 'tcp';
      const bad = this.lintPort(s, port, proto, t.id);
      if (bad) throw new Error(`${s.name}: ${bad}`);
      if (kind === 'relay' && coreMode(s) === 'xui')
        throw new Error(`${s.name}: на узле с 3x-ui «вход» недоступен — нужны собственные маршруты Xray. Выберите вход без 3x-ui.`);
      log(`${i === 0 ? 'canary' : 'волна'}: ${s.name}`);
      let ib: InboundRow | undefined;
      try {
        await this.ctx.onNode(s, async (n) => {
          await this.ensureKit(s, n, log);
          if (t.protocol === 'vless-reality') await this.ensureCore(s, n, 'xray', log);
          else await this.ensureCore(s, n, 'sing-box', log);
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
            const st = await n.op(['core-status', t.protocol === 'hysteria2' ? 'sing-box' : 'xray']);
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
