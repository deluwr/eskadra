/**
 * Подключение узла целиком из панели (§6): администратор даёт одноразовый доступ (логин + пароль или ключ),
 * панель сама выполняет bootstrap, закрепляет host key, проверяет вход своим ключом, снимает preflight
 * и ставит nodekit. Одноразовые данные живут только в памяти задачи и нигде не сохраняются.
 */
import ssh2, { type Client as SshClient } from 'ssh2';
import { HttpError, type Ctx, type ServerRow, expectedPanelIps } from './ctx.js';
import { audit } from './lib/audit.js';
import { bootstrapSnippet } from './bootstrap.js';
import { credsOf, xrayPin } from './mgmt.js';
import { fetchHostKey, fingerprintOf, HostKeyError, mask, withNodeLock, withSession } from './ssh/executor.js';
import { parseSections, summarize } from './preflight.js';
import { buildInstallScript, readKitFile, SUDO_DROP_BOOTSTRAP, SUDO_NARROW_WRITE } from './nodekit.js';
import { Ops, startJob, type JobHandle } from './ops.js';
import { viaOutbound, type BootstrapVia } from './via.js';

const { Client } = ssh2;

/** Одноразовый доступ к узлу для первичной настройки; via — зайти через прокси (via.ts). */
export interface BootstrapAuth { user: string; password?: string; privateKey?: string; passphrase?: string; via?: BootstrapVia; keepVia?: boolean }
export type { BootstrapVia };

type Log = (line: string) => void;

/** Сниппет под канал узла (прямой или туннель). */
export async function snippetOf(ctx: Ctx, r: ServerRow): Promise<string> {
  if (r.mgmt_mode !== 'tunnel') return bootstrapSnippet({ panelIps: ctx.executorIps(), pubkey: r.key_pub });
  const creds = credsOf(ctx, r);
  if (!creds) throw new HttpError(409, 'у узла нет данных служебного туннеля — переключите канал заново');
  const xray = await xrayPin(ctx).catch((e: Error) => { throw new HttpError(502, `не удалось получить релиз Xray с GitHub: ${e.message}`); });
  return bootstrapSnippet({ panelIps: ctx.executorIps(), pubkey: r.key_pub, mgmt: { creds, sshPort: r.ssh_port, xray } });
}

/**
 * Bootstrap по одноразовому доступу: прямое SSH-подключение к узлу, сниппет от root (или через sudo).
 * Host key закрепляется по этому подключению; если ключ уже закреплён и отличается — стоп.
 */
export async function bootstrapWithAuth(ctx: Ctx, r: ServerRow, auth: BootstrapAuth, log: Log): Promise<void> {
  const snippet = await snippetOf(ctx, r);
  let seenFp = '';
  // через прокси: временный проброс 127.0.0.1:<порт> → прокси → сервер:SSH (отдельный процесс Xray панели)
  let via: { port: number; close: () => Promise<void> } | null = null;
  if (auth.via) {
    const o = viaOutbound(ctx, auth.via);
    if (!ctx.mgmt) throw new Error('клиент туннелей панели не запущен');
    const v = await ctx.mgmt.openVia(o.outbound, r.host, r.ssh_port);
    via = v;
    log(`первичный доступ через прокси (${o.label}): 127.0.0.1:${v.port} → ${r.host}:${r.ssh_port}`);
  }
  try {
    const client: SshClient = await new Promise((resolve, reject) => {
      const c = new Client();
      let mismatch: string | null = null;
      c.on('ready', () => resolve(c));
      c.on('error', (e) => reject(mismatch ? new HostKeyError(mismatch) : explainConnect(e, r, !!via)));
      // часть серверов спрашивает пароль через keyboard-interactive
      c.on('keyboard-interactive', (_n, _i, _l, prompts, finish) => finish(prompts.map(() => auth.password ?? '')));
      c.connect({
        host: via ? '127.0.0.1' : r.host, port: via ? via.port : r.ssh_port, username: auth.user,
        ...(auth.privateKey ? { privateKey: auth.privateKey, passphrase: auth.passphrase || undefined } : { password: auth.password }),
        tryKeyboard: !auth.privateKey,
        readyTimeout: 20_000,
        algorithms: { serverHostKey: ['ssh-ed25519'] },
        hostVerifier: (key: Buffer) => {
          seenFp = fingerprintOf(key).fp;
          if (r.host_key_fp && r.host_key_fp !== seenFp) {
            mismatch = `ключ сервера изменился: был ${r.host_key_fp}, сейчас ${seenFp}. Если сервер переустанавливали — удалите его из панели и добавьте заново`;
            return false;
          }
          return true;
        },
      });
    });
    try {
      log(`вход ${auth.user}@${r.host}:${r.ssh_port} выполнен, ключ сервера ${seenFp}`);
      const run = (cmd: string, stdin: string) => new Promise<{ code: number | null; out: string }>((resolve, reject) => {
        client.exec(cmd, (err, stream) => {
          if (err) return reject(err);
          let out = '';
          const timer = setTimeout(() => { stream.close(); reject(new Error('bootstrap не завершился за 10 минут')); }, 600_000);
          stream.on('data', (d: Buffer) => (out += d.toString('utf8')));
          stream.stderr.on('data', (d: Buffer) => (out += d.toString('utf8')));
          stream.on('close', (code: number | null) => { clearTimeout(timer); resolve({ code, out }); });
          stream.end(stdin);
        });
      });
      let res;
      if (auth.user === 'root') res = await run('bash -s', snippet);
      else {
        const nopass = await run('sudo -n true', '');
        if (nopass.code === 0) res = await run('sudo -n bash -s', snippet);
        else if (auth.password) res = await run(`sudo -S -p '' bash -s`, auth.password + '\n' + snippet);
        else throw new Error(`у пользователя ${auth.user} нет sudo без пароля — укажите root или пароль пользователя`);
      }
      const secrets = [auth.password ?? '', auth.privateKey ?? ''];
      log(mask(`bootstrap: exit ${res.code}\n${res.out.trim()}`, secrets));
      if (res.code !== 0) throw new Error(`bootstrap завершился с ошибкой (код ${res.code}): ${mask(res.out.trim().split('\n').slice(-2).join(' '), secrets)}`);
      if (!res.out.includes(seenFp.replace(/^SHA256:/, ''))) log('предупреждение: отпечаток в выводе сниппета не найден (нестандартный ssh-keygen?)');
    } finally {
      client.end();
    }
    ctx.updateServer(r.id, { host_key_fp: seenFp, host_key_pending_fp: null, host_key_algo: 'ssh-ed25519' });
    // сервер недоступен из РФ целиком: туннель управления дальше идёт через тот же прокси (цепочка в mgmt.ts)
    if (auth.via && auth.keepVia && r.mgmt_mode === 'tunnel') {
      ctx.updateServer(r.id, { mgmt_via: ctx.seal(JSON.stringify(auth.via)) });
      log('туннель управления будет идти через этот же прокси');
    }
  } finally {
    await via?.close();
  }
}

function explainConnect(e: Error & { level?: string; code?: string }, r: ServerRow, viaProxy = false): Error {
  if (e.level === 'client-authentication') return new Error('сервер не принял логин/пароль или ключ');
  if (viaProxy && (e.code === 'ECONNRESET' || e.code === 'ETIMEDOUT' || /Timed out|handshake|closed/i.test(e.message)))
    return new Error(`через прокси ${r.host}:${r.ssh_port} не ответил. Проверьте, что прокси рабочий (подключитесь им с телефона) и что порт SSH ${r.ssh_port} на сервере открыт`);
  if (e.code === 'ECONNREFUSED') return new Error(`порт SSH ${r.ssh_port} закрыт на ${r.host}`);
  if (e.code === 'ETIMEDOUT' || /Timed out/i.test(e.message))
    return new Error(`${r.host}:${r.ssh_port} не отвечает по SSH напрямую. Если главный сервер в РФ и SSH режется — выберите «Первичный доступ: через прокси» (конфигурация панели или своя ссылка vless://)`);
  return e;
}

/** Вход ключом панели: пользователь, sudo, адрес, с которого узел видит панель. */
export async function checkLogin(ctx: Ctx, r: ServerRow) {
  const res = await withNodeLock(r.id, () => withSession(ctx.target(r), async (s) => {
    if (r.sudo_mode === 'restricted') {
      const w = await s.exec('sudo -n /usr/local/sbin/fleet-exec whoami');
      if (w.code === 0) return { ok: true, conn: w.stdout.split('\n')[0] ?? '', user: 'fleet', err: '' };
      const p = await s.exec('sudo -n /usr/local/sbin/fleet-exec ping');
      return { ok: p.stdout.trim() === 'pong', conn: '', user: 'fleet', err: p.stderr.trim() };
    }
    const w = await s.exec('echo "$SSH_CONNECTION"; id -un');
    const sudo = await s.exec('sudo -n true && echo sudo_ok');
    const [conn, user] = w.stdout.trim().split('\n');
    return { ok: sudo.code === 0, conn: conn ?? '', user: user ?? '', err: sudo.stderr.trim() };
  }));
  const seen = res.conn.split(' ')[0] || r.seen_from_ip;
  ctx.updateServer(r.id, {
    seen_from_ip: seen, last_seen_at: new Date().toISOString(), fail_since: null,
    status: r.status === 'pending_bootstrap' && res.ok ? 'connected' : r.status,
  });
  return { ok: res.ok, user: res.user, seenFromIp: seen, sudo: res.ok ? 'ok' : res.err };
}

/** Root-операция до сужения sudo — скрипт через bootstrap-sudo; после — операция fleet-exec. */
function rootScript(ctx: Ctx, r: ServerRow, op: 'preflight' | 'baseline') {
  return withNodeLock(r.id, () =>
    withSession(ctx.target(r), (s) =>
      r.sudo_mode === 'restricted'
        ? s.exec(`sudo -n /usr/local/sbin/fleet-exec ${op}`, { timeoutMs: 60_000 })
        : s.exec(`sudo -n bash -s -- "$SSH_CONNECTION"`, { stdin: readKitFile(`sbin/fleet-${op}`), timeoutMs: 60_000 }),
    ),
  );
}

/** Preflight + baseline (только чтение). */
export async function runPreflight(ctx: Ctx, r: ServerRow, job: JobHandle) {
  const pre = await rootScript(ctx, r, 'preflight');
  const base = await rootScript(ctx, r, 'baseline');
  if (pre.code !== 0) throw new Error(`preflight exit ${pre.code}: ${pre.stderr}`);
  job.log(`baseline: ${base.code === 0 ? base.stdout.trim() : 'FAILED ' + base.stderr.trim()}`);
  const summary = summarize(pre.stdout, expectedPanelIps(r, ctx.executorIps()));
  const kernel = (parseSections(pre.stdout).get('kernel') ?? '').split('\n');
  const arch = /aarch64|arm64/.test(kernel[1] ?? '') ? 'arm64' : 'amd64';
  ctx.db.prepare('INSERT INTO preflight_reports (server_id, summary, raw) VALUES (?, ?, ?)').run(
    r.id, JSON.stringify({ ...summary, baselinePath: base.stdout.trim() }), pre.stdout);
  ctx.updateServer(r.id, {
    os_info: JSON.stringify(summary.os), ssh_ports: JSON.stringify(summary.sshPorts), ufw_active: summary.ufwActive ? 1 : 0,
    external_cores: JSON.stringify(summary.externalCores),
    arch, last_seen_at: new Date().toISOString(), ...(summary.clientIp ? { seen_from_ip: summary.clientIp } : {}),
  });
  job.log(`checks: ${summary.checks.map((c) => `${c.id}=${c.status}`).join(' ')}`);
  return { ...summary, baselinePath: base.stdout.trim() };
}

/**
 * Nodekit + сужение sudo + строгий режим ключа (шаг 3 runbook).
 * Если узел уже сужен, но nodekit устарел и не умеет kit-install, нужен повторный bootstrap.
 */
export async function installNodekit(ctx: Ctx, r: ServerRow, job: JobHandle): Promise<string> {
  const ops = new Ops(ctx);
  const t = ctx.target(r);
  const wide = await withNodeLock(r.id, () => withSession(t, (s) => s.exec('sudo -n true')));
  if (wide.code !== 0) {
    if (r.sudo_mode !== 'restricted') throw new Error('нет ни bootstrap-sudo, ни fleet-exec: повторите подключение');
    await ctx.onNode(r, (n) => ops.ensureKit(r, n, job.log));
  } else {
    await withNodeLock(r.id, () => withSession(t, async (s) => {
      const inst = await s.exec('sudo -n bash -s', { stdin: buildInstallScript(), timeoutMs: 600_000 });
      job.log(mask(`install: exit ${inst.code}\n${inst.stdout}${inst.stderr}`, [t.privateKey]));
      if (inst.code !== 0) throw new Error('nodekit install failed');
      const w = await s.exec('sudo -n bash -s', { stdin: SUDO_NARROW_WRITE });
      job.log(`sudoers 90-fleet: exit ${w.code} ${w.stdout.trim()} ${w.stderr.trim()}`);
      if (w.code !== 0) throw new Error('writing 90-fleet failed');
      const ping = await s.exec('sudo -n /usr/local/sbin/fleet-exec ping');
      if (ping.stdout.trim() !== 'pong') throw new Error('fleet-exec ping failed — широкий sudo НЕ удалён');
      const drop = await s.exec('sudo -n bash -s', { stdin: SUDO_DROP_BOOTSTRAP });
      job.log(`drop 90-fleet-bootstrap: ${drop.stdout.trim()} ${drop.stderr.trim()}`);
      if (drop.code !== 0) throw new Error('could not drop bootstrap sudo');
    }));
  }
  // Строгий режим: ключ панели — только через fleet-gate. Проверяем НОВОЙ сессией.
  await ctx.onNode(r, (n) => n.must(['ssh-mode', 'strict']));
  const verify = await withSession(t, async (s) => ({
    wide: await s.exec('sudo -n true'),
    raw: await s.exec('id -un'),
    ping: await s.exec('sudo -n /usr/local/sbin/fleet-exec ping'),
    ver: await s.exec('sudo -n /usr/local/sbin/fleet-exec version'),
  }));
  const ok = verify.wide.code !== 0 && verify.raw.code !== 0 && verify.ping.stdout.trim() === 'pong';
  job.log(`verify: wide sudo ${verify.wide.code === 0 ? 'STILL WORKS' : 'denied'}; raw shell ${verify.raw.code === 0 ? 'STILL WORKS' : 'denied'}; fleet-exec ${verify.ping.stdout.trim()}; version ${verify.ver.stdout.trim()}`);
  if (!ok) throw new Error('строгий режим не подтвердился: широкий sudo или shell всё ещё доступны');
  const fresh = ctx.server(r.id);
  ctx.updateServer(r.id, {
    sudo_mode: 'restricted', ssh_mode: 'strict', kit_version: verify.ver.stdout.trim(),
    status: fresh.status === 'connected' ? 'configured' : fresh.status,
  });
  // новая нода попадает в наборы соседей (§7.12.1)
  void ops.peerSync(() => undefined);
  return verify.ver.stdout.trim();
}

/** Состояние автоподключения узла: идёт ли сейчас задача. */
const running = new Set<string>();
export const onboardingRunning = (id: string) => running.has(id);

/**
 * Полный цикл подключения в фоне: bootstrap (если дан доступ) → вход ключом панели → preflight → nodekit.
 * Шаги, уже пройденные раньше, пропускаются, поэтому «Повторить» продолжает с места остановки.
 */
export function startOnboarding(ctx: Ctx, id: string, who: string, auth?: BootstrapAuth): number {
  if (running.has(id)) throw new HttpError(409, 'подключение уже идёт');
  const job = startJob(ctx, id, 'onboard');
  running.add(id);
  void (async () => {
    try {
      let r = ctx.server(id);
      if (auth) {
        job.log('шаг 1/5: первичный доступ (одноразовые данные не сохраняются)');
        await bootstrapWithAuth(ctx, r, auth, job.log);
        r = ctx.server(id);
      } else if (!r.host_key_fp) {
        // сниппет выполнен вручную: ключ сервера закрепляется при первом подключении панели (через туннель — тоже)
        job.log('шаг 1/5: сниппет выполнен вручную — получаю ключ сервера');
        const t = ctx.target(r);
        const hk = await fetchHostKey(t.host, t.port, 15_000, t);
        ctx.updateServer(id, { host_key_fp: hk.fp, host_key_algo: hk.algo, host_key_pending_fp: null });
        job.log(`ключ сервера ${hk.fp} закреплён`);
        r = ctx.server(id);
      }
      // повторный bootstrap (например, смена канала) снова выдаёт широкий sudo — поэтому с доступом проходим цикл целиком
      if (r.sudo_mode !== 'restricted' || auth) {
        job.log('шаг 2/5: вход ключом панели и sudo');
        const c = await checkLogin(ctx, r);
        if (!c.ok) throw new Error(`ключ панели работает, но sudo нет: ${c.sudo}`);
        r = ctx.server(id);
        job.log('шаг 3/5: проверка сервера (только чтение)');
        const pre = await runPreflight(ctx, r, job);
        if (pre.blocking) throw new Error(`проверка нашла блокирующие проблемы: ${pre.checks.filter((c) => c.status === 'fail').map((c) => c.title).join('; ')}`);
        r = ctx.server(id);
        job.log('шаг 4/5: служебные скрипты, сужение sudo, строгий режим');
        const v = await installNodekit(ctx, r, job);
        job.log(`nodekit ${v} установлен`);
      } else {
        job.log('узел уже настроен — проверяю вход');
        await checkLogin(ctx, r);
      }
      job.log('шаг 5/5: ядра Xray и sing-box');
      for (const line of await new Ops(ctx).installCores(ctx.server(id), job.log)) job.log(line);
      job.log('готово');
      job.finish('ok');
      audit(ctx.db, who, 'server.onboarded', id);
    } catch (e) {
      job.log(`ошибка: ${(e as Error).message}`);
      job.finish('failed');
    } finally {
      running.delete(id);
    }
  })();
  return job.id;
}
