import { isIP } from 'node:net';
import type { FastifyBaseLogger } from 'fastify';
import { coreMode, type Ctx, type ServerRow, type UserRow } from './ctx.js';
import { audit } from './lib/audit.js';
import { getSetting, setSetting } from './db.js';
import { cmpVersion, listReleases } from './releases.js';
import { Ops } from './ops.js';
import { effectiveLimits, json, period } from './vpn.js';
import type { Backups } from './backup.js';
import type { Bot } from './bot.js';
import { certLabel, certProblems } from './certs.js';

const minutesSince = (iso: string | null) => (iso ? (Date.now() - Date.parse(iso)) / 60_000 : 0);

export class Workers {
  private readonly ops: Ops;
  private timers: NodeJS.Timeout[] = [];
  private busy = new Set<string>();

  constructor(private readonly ctx: Ctx, private readonly log: FastifyBaseLogger, private readonly backups: Backups, private readonly bot: Bot) {
    this.ops = new Ops(ctx);
  }

  start() {
    this.every('heartbeat', 60_000, () => this.heartbeat());
    this.every('peers', 10 * 60_000, () => this.peerChecks());
    this.every('stats', 5 * 60_000, () => this.stats());
    this.every('sync', 20_000, () => this.syncDirty());
    this.every('exits', 60_000, () => this.exitChecks());
    this.every('cleanup', 10 * 60_000, async () => {
      this.ctx.db.prepare('DELETE FROM allowed_ips WHERE expires_at < ?').run(new Date().toISOString());
    });
    this.every('backup', 60_000, () => this.backups.tick());
    this.every('cores', 6 * 3600_000, () => this.coreCheck());
    this.every('certs', 3 * 3600_000, () => this.certCheck());
  }

  /**
   * Сертификаты узлов: сроки и результат продления (продлевает сам узел). О новой проблеме — одно сообщение в бот;
   * проблема ушла (сертификат продлён) — сообщение об этом.
   */
  async certCheck() {
    const notified = getSetting<Record<string, string>>(this.ctx.db, 'certs.notified', {});
    const seen = new Set<string>();
    const tplName = (id: string) => this.ops.vpn.template(id)?.name;
    for (const s of this.ctx.servers().filter((x) => x.sudo_mode === 'restricted' && !x.fail_since)) {
      try { await this.ops.checkCerts(s); } catch (e) { this.log.warn(`сертификаты ${s.name}: ${(e as Error).message}`); continue; }
      for (const p of certProblems(this.ctx.server(s.id), tplName)) {
        seen.add(p.key);
        if (notified[p.key]) continue;
        notified[p.key] = new Date().toISOString();
        void this.bot.notifyAdmins(`${p.level === 'fail' ? '⛔' : '⚠️'} ${p.title}. ${p.detail}`);
      }
      const gone = Object.keys(notified).filter((k) => k.startsWith(`${s.id}:`) && !seen.has(k));
      for (const k of gone) delete notified[k];
      // «всё в порядке» — только когда у узла не осталось проблем с сертификатами (иначе предупреждение просто сменилось)
      if (gone.length && ![...seen].some((k) => k.startsWith(`${s.id}:`)))
        void this.bot.notifyAdmins(`✅ ${s.name}: сертификаты в порядке${gone.some((k) => !/:(renew|timer)$/.test(k)) ? ` (${[...new Set(gone.filter((k) => !/:(renew|timer)$/.test(k)).map((k) => certLabel(k.split(':')[1]!, tplName)))].join(', ')})` : ''}`);
    }
    setSetting(this.ctx.db, 'certs.notified', notified);
  }

  /** Новые версии ядер: одно уведомление на версию; версия Xray у узлов с 3x-ui обновляется в карточке. */
  async coreCheck() {
    const notified = getSetting<Record<string, string>>(this.ctx.db, 'cores.notified', {});
    for (const core of ['xray', 'sing-box'] as const) {
      let latest: string | undefined;
      try { latest = (await listReleases(core)).find((r) => !r.prerelease)?.version; } catch { continue; }
      if (!latest) continue;
      const outdated = this.managed().filter((s) => {
        const v = json<Record<string, { version: string }>>(s.cores, {})[core]?.version;
        return v && cmpVersion(v, latest!) < 0;
      });
      if (outdated.length && notified[core] !== latest) {
        void this.bot.notifyAdmins(`⬆️ Доступен ${core} ${latest}. Устарел на: ${outdated.map((s) => s.name).join(', ')}. Обновить: Конфигурации → Ядра.`);
        notified[core] = latest;
      }
    }
    setSetting(this.ctx.db, 'cores.notified', notified);
    for (const s of this.managed().filter((x) => coreMode(x) === 'xui')) {
      try {
        const info = await this.ctx.onNode(s, (n) => this.ops.xui<{ xrayVersion: string | null; version: string | null }>(s, n, 'info'));
        const cores = json<Record<string, unknown>>(this.ctx.server(s.id).cores, {});
        cores.xui = { version: info.xrayVersion ?? '?', panel: info.version };
        this.ctx.updateServer(s.id, { cores: JSON.stringify(cores) });
      } catch { /* узел недоступен — это ловит heartbeat */ }
    }
  }

  stop() { for (const t of this.timers) clearInterval(t); }

  private every(name: string, ms: number, fn: () => Promise<void>) {
    const run = async () => {
      if (this.busy.has(name)) return;
      this.busy.add(name);
      try { await fn(); } catch (e) { this.log.warn({ err: e }, `worker ${name}`); } finally { this.busy.delete(name); }
    };
    this.timers.push(setInterval(run, ms));
    setTimeout(run, 5_000);
  }

  private managed(): ServerRow[] {
    return this.ctx.servers().filter((s) => s.sudo_mode === 'restricted' && s.host_key_fp);
  }

  /** Связь с узлом; сбой дольше порога сбрасывает чек-лист (проверять заново нужно только после сбоя). */
  async heartbeat() {
    const threshold = this.ops.failThresholdMin();
    await Promise.all(this.managed().map(async (s) => {
      try {
        const r = await this.ctx.onNode(s, (n) => n.op(['ping'], { timeoutMs: 15_000 }));
        if (r.stdout.trim() !== 'pong') throw new Error('no pong');
        if (s.fail_since) audit(this.ctx.db, 'system', 'server.recovered', s.id, { downMin: Math.round(minutesSince(s.fail_since)) });
        this.ctx.updateServer(s.id, { last_seen_at: new Date().toISOString(), fail_since: null });
        // таймер подтверждения firewall истёк без подтверждения → узел сам откатил правила
        if (s.fw_mode === 'pending' && s.fw_pending_until && Date.parse(s.fw_pending_until) < Date.now() - 15_000) {
          const st = await this.ctx.onNode(s, (n) => n.op(['fw-state']));
          if (st.stdout.trim() !== 'pending') this.ctx.updateServer(s.id, { fw_mode: 'observe', fw_pending_until: null });
        }
      } catch {
        const since = s.fail_since ?? new Date().toISOString();
        if (!s.fail_since) {
          this.ctx.updateServer(s.id, { fail_since: since });
          void this.bot.notifyAdmins(`⚠️ ${s.name} не отвечает панели`);
        }
        if (s.checklist_passed_at && minutesSince(since) > threshold) {
          this.ctx.updateServer(s.id, { checklist_passed_at: null, checklist: '{}' });
          audit(this.ctx.db, 'system', 'server.checklist_reset', s.id, { reason: `нет связи дольше ${threshold} мин` });
        }
      }
    }));
  }

  /** Связность нод: каждая нода проверяет соседей (сервисный порт или ping). */
  async peerChecks() {
    const nodes = this.managed();
    const threshold = this.ops.failThresholdMin();
    for (const a of nodes) {
      for (const b of nodes) {
        if (a.id === b.id || !isIP(b.host)) continue;
        const port = this.ctx.db.prepare(`SELECT port FROM inbounds WHERE server_id = ? AND proto = 'tcp' AND state = 'active' LIMIT 1`).get(b.id) as { port: number } | undefined;
        let result = 'fail';
        try {
          const r = await this.ctx.onNode(a, (n) => n.op(['peer-check', b.host, port ? port.port : 'icmp'], { timeoutMs: 15_000 }));
          result = r.stdout.trim() === 'ok' ? 'ok' : 'fail';
        } catch { /* узел недоступен — это ловит heartbeat */ continue; }
        const prev = this.ctx.db.prepare('SELECT fail_since FROM peer_checks WHERE from_id = ? AND to_id = ?').get(a.id, b.id) as { fail_since: string | null } | undefined;
        const failSince = result === 'fail' ? prev?.fail_since ?? new Date().toISOString() : null;
        this.ctx.db.prepare(`INSERT INTO peer_checks (from_id, to_id, result, checked_at, fail_since) VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(from_id, to_id) DO UPDATE SET result = excluded.result, checked_at = excluded.checked_at, fail_since = excluded.fail_since`)
          .run(a.id, b.id, result, new Date().toISOString(), failSince);
        if (failSince && minutesSince(failSince) > threshold) {
          for (const s of [a, b]) if (this.ctx.server(s.id).checklist_passed_at) {
            this.ctx.updateServer(s.id, { checklist_passed_at: null, checklist: '{}' });
            audit(this.ctx.db, 'system', 'server.checklist_reset', s.id, { reason: `нет связи ${a.name} → ${b.name} дольше ${threshold} мин` });
          }
        }
      }
    }
  }

  /** Трафик пользователей из Xray (с обнулением счётчиков) и применение лимитов (§16). */
  async stats() {
    const per = period();
    const add = (userId: string, col: 'up' | 'down', v: number) => {
      if (v > 0) this.ctx.db.prepare(`INSERT INTO traffic (user_id, period, ${col}) VALUES (?, ?, ?)
        ON CONFLICT(user_id, period) DO UPDATE SET ${col} = ${col} + excluded.${col}`).run(userId, per, v);
    };
    for (const s of this.managed()) {
      if (coreMode(s) === 'xui' && s.xui_pass_sealed) {
        // 3x-ui отдаёт накопительные счётчики клиентов: считаем прирост относительно прошлого опроса
        let list: Array<{ clientStats: Array<{ email: string; up: number; down: number }> }> = [];
        try { list = await this.ctx.onNode(s, (n) => this.ops.xui(s, n, 'list')); } catch { continue; }
        for (const c of list.flatMap((i) => i.clientStats)) {
          const m = c.email?.match(/^(u-[0-9a-f]+)\./);
          if (!m) continue;
          const prev = this.ctx.db.prepare('SELECT up, down FROM xui_counters WHERE server_id = ? AND email = ?').get(s.id, c.email) as { up: number; down: number } | undefined;
          const du = prev && c.up >= prev.up ? c.up - prev.up : c.up;
          const dd = prev && c.down >= prev.down ? c.down - prev.down : c.down;
          add(m[1]!, 'up', prev ? du : 0);
          add(m[1]!, 'down', prev ? dd : 0);
          this.ctx.db.prepare(`INSERT INTO xui_counters (server_id, email, up, down) VALUES (?, ?, ?, ?)
            ON CONFLICT(server_id, email) DO UPDATE SET up = excluded.up, down = excluded.down`).run(s.id, c.email, c.up, c.down);
        }
        continue;
      }
      if (!json<Record<string, unknown>>(s.cores, {}).xray) continue;
      let out = '';
      try { out = (await this.ctx.onNode(s, (n) => n.op(['xray-stats'], { timeoutMs: 20_000 }))).stdout; } catch { continue; }
      let data: { stat?: Array<{ name: string; value?: string | number }> } = {};
      try { data = JSON.parse(out || '{}'); } catch { continue; }
      for (const st of data.stat ?? []) {
        const m = st.name.match(/^user>>>(u-[0-9a-f]+)\.[^>]*>>>traffic>>>(uplink|downlink)$/);
        if (!m) continue;
        const v = Number(st.value ?? 0);
        if (!v) continue;
        const col = m[2] === 'uplink' ? 'up' : 'down';
        this.ctx.db.prepare(`INSERT INTO traffic (user_id, period, ${col}) VALUES (?, ?, ?)
          ON CONFLICT(user_id, period) DO UPDATE SET ${col} = ${col} + excluded.${col}`).run(m[1]!, per, v);
      }
    }
    this.enforceLimits();
  }

  enforceLimits() {
    const users = this.ctx.db.prepare(`SELECT * FROM users WHERE status = 'active'`).all() as unknown as UserRow[];
    let changed = false;
    for (const u of users) {
      const lim = effectiveLimits(this.ctx, u);
      const t = this.ctx.db.prepare('SELECT up, down FROM traffic WHERE user_id = ? AND period = ?').get(u.id, period()) as { up: number; down: number } | undefined;
      const used = (t?.up ?? 0) + (t?.down ?? 0);
      let reason: string | null = null;
      if (lim.expireAt && Date.parse(lim.expireAt) < Date.now()) reason = 'истёк срок';
      else if (lim.trafficGb && used > lim.trafficGb * 1024 ** 3) reason = 'исчерпан трафик';
      if (!reason) continue;
      if (u.over_action === 'notify') { void this.bot.notifyAdmins(`ℹ️ ${u.name}: ${reason}`); continue; }
      this.ctx.db.prepare(`UPDATE users SET status = 'disabled', disabled_reason = ? WHERE id = ?`).run(reason, u.id);
      audit(this.ctx.db, 'system', 'user.disabled', u.id, { reason });
      void this.bot.notifyAdmins(`⛔ ${u.name} отключён: ${reason}`);
      changed = true;
    }
    if (changed) this.ops.vpn.markDirty();
  }

  /** «Авто через вход» по качеству и по порядку: проверка выходов по расписанию каждой конфигурации, уведомление о переключении. */
  async exitChecks() {
    for (const t of this.ops.vpn.templates()) {
      const sp = this.ops.vpn.spec(t);
      if (sp.autoMode === 'random' || !t.entry_id) continue;
      const last = getSetting<string>(this.ctx.db, `auto.checked.${t.id}`, '');
      try {
        // между полными проверками — раз в минуту только задержка закреплённого выхода; не отвечает — проверяем всё сразу
        // по порядку — проверка каждую минуту (только доступность, дёшево); по качеству — полная по расписанию
        if (sp.autoMode === 'smart' && last && Date.now() - Date.parse(last) < sp.checkMin * 60_000 && (await this.ops.pinnedAlive(t).catch(() => true))) continue;
        const r = await this.ops.checkExits(t, () => undefined);
        if (r?.switched) {
          const msg = r.switched.to
            ? `«${t.name}»: «Авто» переключён ${r.switched.from ? `с ${r.switched.from} ` : ''}на ${r.switched.to}`
            : sp.autoMode === 'order' ? `«${t.name}»: ни один выход не отвечает`
            : `«${t.name}»: ни один выход не проходит пороги (задержка ≤ ${sp.maxRttMs} мс, скорость ≥ ${sp.minMbps} Мбит/с) — выбор по наименьшей задержке`;
          this.log.info(msg);
          void this.bot.notifyAdmins(msg, [[{ text: 'Выходы «Авто»', callback_data: 'ex' }]]);
        }
      } catch (e) {
        this.log.warn(`проверка выходов ${t.name}: ${(e as Error).message}`);
      }
    }
  }

  /** Переприменение конфигов узлов, где поменялись пользователи или шаблоны. */
  async syncDirty() {
    for (const s of this.ctx.servers().filter((x) => x.config_dirty && x.sudo_mode === 'restricted')) {
      try {
        await this.ctx.onNode(s, (n) => this.ops.applyServer(this.ctx.server(s.id), n, (l) => this.log.info(`${s.name}: ${l}`)));
      } catch (e) {
        this.log.warn(`sync ${s.name}: ${(e as Error).message}`);
      }
    }
  }
}
