/**
 * Перенос панели на другой сервер (кнопка в «Настройках», только owner, с кодом 2FA).
 *
 * 1. Вход на новый сервер по SSH (root или пользователь с sudo; пароль или ключ) и проверки: там ещё нет Эскадры.
 * 2. Новый адрес разрешается на узлах (fleetctl allow: firewall и from= у ключа панели) и в executor.ips —
 *    иначе новая панель не зайдёт на узлы. Узлы в режиме туннеля ходят к панели через свой адрес — им ничего не нужно.
 * 3. Снимок данных (база и мастер-ключ) с правками для нового места: главный сервер становится обычным узлом
 *    (панель на нём больше не работает), адрес подписок на IP старого сервера меняется на новый.
 * 4. На новом сервере ставится та же версия Эскадры с тем же портом и путём, данные подставляются до первого
 *    запуска (install.sh, ESKADRA_RESTORE). Сертификат панели — Let's Encrypt на IP или домен.
 * 5. Новая панель отвечает — эта помечается перенесённой: фоновые задачи и бот останавливаются, изменения
 *    запрещены (две панели не управляют узлами одновременно). Вернуть управление можно кнопкой.
 */
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';
import ssh2, { type Client as SshClient } from 'ssh2';
import type { Ctx } from './ctx.js';
import { config } from './config.js';
import { getSetting, setSetting, type Db } from './db.js';
import { snapshotArchive } from './backup.js';
import { fingerprintOf, mask } from './ssh/executor.js';
import { panelRepo, panelVersion } from './version.js';

const { Client } = ssh2;
/** Строка в одинарных кавычках для shell. */
const shq = (s: string) => `'${s.split("'").join(`'"'"'`)}'`;

export interface MoveTarget {
  host: string; sshPort: number; user: string; password?: string; privateKey?: string;
  /** сертификат новой панели: Let's Encrypt на IP или на домен (A-запись домена уже должна вести на новый сервер) */
  tls: 'ip' | 'domain'; domain?: string;
}

/** Куда перенесена панель (адрес новой); null — работает здесь. */
export const movedTo = (db: Db) => getSetting<string | null>(db, 'panel.movedTo', null);

/** Правки копии базы для нового места: главный сервер — обычный узел, подписки — на новый адрес, флаг переноса снят. */
export function prepareMovedDb(file: string, oldHost: string, newIp: string) {
  const db = new DatabaseSync(file);
  try {
    db.prepare(`UPDATE servers SET mgmt_mode = 'direct' WHERE mgmt_mode = 'local'`).run();
    db.prepare(`DELETE FROM settings WHERE key = 'panel.movedTo'`).run();
    const sub = db.prepare(`SELECT value FROM settings WHERE key = 'sub.host'`).get() as { value: string } | undefined;
    if (sub && oldHost && JSON.parse(sub.value) === oldHost) db.prepare(`UPDATE settings SET value = ? WHERE key = 'sub.host'`).run(JSON.stringify(newIp));
    // сессии старого адреса новой панели не нужны: войти придётся заново
    db.prepare('DELETE FROM sessions').run();
  } finally { db.close(); }
}

/** Адрес новой панели — тот же порт и путь. */
export const movedUrl = (t: MoveTarget, ip: string) => `https://${t.tls === 'domain' ? t.domain : ip}:${config.port}${config.basePath}`;

export async function movePanel(ctx: Ctx, t: MoveTarget, log: (l: string) => void, stopHere: () => void): Promise<string> {
  const version = panelVersion();
  if (version === 'dev') throw new Error('перенос работает из релизной версии панели (установленной install.sh), а не из исходников');
  if (t.tls === 'domain' && !t.domain) throw new Error('укажите домен новой панели');
  const ip = net.isIP(t.host) ? t.host : (await dns.lookup(t.host, { family: 4 }).catch(() => { throw new Error(`адрес ${t.host} не найден в DNS`); })).address;
  if (ip === process.env.FLEET_PUBLIC_HOST) throw new Error('это адрес текущей панели — укажите новый сервер');
  const secrets = [t.password ?? '', t.privateKey ?? ''];

  // ── 1. вход на новый сервер ──
  let fp = '';
  const client: SshClient = await new Promise((resolve, reject) => {
    const c = new Client();
    c.on('ready', () => resolve(c));
    c.on('error', (e) => reject(new Error(`SSH ${t.user}@${ip}:${t.sshPort}: ${e.message}`)));
    c.on('keyboard-interactive', (_n, _i, _l, prompts, finish) => finish(prompts.map(() => t.password ?? '')));
    c.connect({
      host: ip, port: t.sshPort, username: t.user, readyTimeout: 20_000, tryKeyboard: !t.privateKey,
      ...(t.privateKey ? { privateKey: t.privateKey } : { password: t.password }),
      hostVerifier: (key: Buffer) => { fp = fingerprintOf(key).fp; return true; },
    });
  });
  try {
    log(`вход ${t.user}@${ip}:${t.sshPort} выполнен, ключ сервера ${fp}`);
    const exec = (cmd: string, stdin: Buffer | string = '', timeoutMs = 120_000) => new Promise<{ code: number | null; out: string }>((resolve, reject) => {
      client.exec(cmd, (err, stream) => {
        if (err) return reject(err);
        let out = '';
        const timer = setTimeout(() => { stream.close(); reject(new Error(`команда не завершилась за ${Math.round(timeoutMs / 60_000)} мин`)); }, timeoutMs);
        stream.on('data', (d: Buffer) => (out += d.toString('utf8')));
        stream.stderr.on('data', (d: Buffer) => (out += d.toString('utf8')));
        stream.on('close', (code: number | null) => { clearTimeout(timer); resolve({ code, out }); });
        stream.end(stdin);
      });
    });
    // от root — как есть; иначе через sudo (без пароля или с паролем пользователя первой строкой stdin)
    let sudo = '';
    if (t.user !== 'root') {
      if ((await exec('sudo -n true')).code === 0) sudo = 'sudo -n ';
      else if (t.password) sudo = `sudo -S -p '' `;
      else throw new Error(`у ${t.user} нет sudo без пароля — укажите root или пароль пользователя`);
    }
    const root = (script: string, stdin: Buffer | string = '', timeoutMs?: number) =>
      exec(`${sudo}bash -c ${shq(script)}`, sudo.startsWith('sudo -S') ? Buffer.concat([Buffer.from(t.password + '\n'), Buffer.from(stdin)]) : stdin, timeoutMs);

    const pre = await root('id -u; uname -m; test -f /etc/eskadra/eskadra.env && echo ESKADRA-EXISTS; command -v curl || command -v wget || echo NO-DOWNLOADER');
    if (pre.code !== 0 || !/^0$/m.test(pre.out)) throw new Error(`нет прав root на новом сервере: ${mask(pre.out.trim(), secrets)}`);
    if (pre.out.includes('ESKADRA-EXISTS')) throw new Error('на новом сервере уже установлена Эскадра — перенос ставит её с нуля; удалите её там (eskadra uninstall) или выберите другой сервер');
    if (pre.out.includes('NO-DOWNLOADER')) throw new Error('на новом сервере нет ни curl, ни wget — установите curl');
    if (!/x86_64|aarch64|arm64/.test(pre.out)) throw new Error(`архитектура нового сервера не поддерживается: ${pre.out.split('\n')[1]}`);

    // ── 2. новый адрес — на узлах и в executor.ips ──
    setSetting(ctx.db, 'executor.ips', [...new Set([...ctx.executorIps(), ip])]);
    const failed: string[] = [];
    for (const s of ctx.servers().filter((x) => x.sudo_mode === 'restricted' && x.mgmt_mode !== 'tunnel')) {
      try {
        await ctx.onNode(s, async (n) => { const r = await n.op(['allow', ip], { timeoutMs: 60_000 }); if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim()); });
        log(`${s.name}: новый адрес панели ${ip} разрешён`);
      } catch (e) {
        failed.push(s.name);
        log(`${s.name}: не удалось разрешить ${ip} — ${(e as Error).message}. После переноса выполните на нём в консоли хостера: fleetctl allow ${ip}`);
      }
    }

    // ── 3. снимок данных для нового места ──
    const oldHost = process.env.FLEET_PUBLIC_HOST ?? '';
    const snap = snapshotArchive(ctx.db, 'move', (file) => prepareMovedDb(file, oldHost, ip));
    log(`данные упакованы: ${Math.round(snap.archive.length / 1024)} КБ`);
    const up = await root('umask 077; cat > /root/eskadra-move.tar.gz', snap.archive);
    if (up.code !== 0) throw new Error(`данные не переданы: ${mask(up.out.trim(), secrets)}`);

    // ── 4. установка той же версии с данными ──
    const repo = panelRepo();
    const url = `https://raw.githubusercontent.com/${repo}/${version}/scripts/install.sh`;
    const env = [
      `ESKADRA_REPO=${repo}`, `ESKADRA_VERSION=${version}`, `ESKADRA_PORT=${config.port}`, `ESKADRA_BASE_PATH=${config.basePath}`,
      `ESKADRA_TLS=${t.tls}`, ...(t.tls === 'domain' ? [`ESKADRA_DOMAIN=${t.domain}`] : []), 'ESKADRA_XUI=keep', 'ESKADRA_RESTORE=/root/eskadra-move.tar.gz',
    ].join(' ');
    log(`установка Эскадры ${version} на ${ip} (порт ${config.port}, путь ${config.basePath}) — несколько минут…`);
    const inst = await root(`set -o pipefail; (curl -fsSL ${url} || wget -qO- ${url}) > /root/eskadra-install.sh && ${env} bash /root/eskadra-install.sh < /dev/null`, '', 30 * 60_000);
    log(mask(inst.out.trim().split('\n').slice(-15).join('\n'), secrets));
    if (inst.code !== 0) throw new Error(`установка на новом сервере не прошла (код ${inst.code}) — подробности выше и в /var/log/eskadra-install.log там`);
  } finally {
    client.end();
  }

  // ── 5. новая панель отвечает — эта отходит ──
  const target = movedUrl(t, ip);
  const probe = `https://${ip}:${config.port}${config.basePath}api/v1/auth/state`;
  let ok = false;
  for (let i = 0; i < 24 && !ok; i++) {
    ok = await new Promise<boolean>((resolve) => {
      const req = https.get(probe, { rejectUnauthorized: false, timeout: 5000, headers: t.tls === 'domain' ? { Host: t.domain! } : {} }, (res) => { res.resume(); resolve(res.statusCode === 200); });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
    });
    if (!ok) await new Promise((r) => setTimeout(r, 5000));
  }
  if (!ok) throw new Error(`новая панель не ответила по ${target} за 2 минуты — проверьте её на новом сервере (eskadra status); эта панель продолжает работать`);
  setSetting(ctx.db, 'panel.movedTo', target);
  stopHere();
  log(`готово: панель работает на ${target}. Здесь фоновые задачи и бот остановлены. Войдите на новом адресе тем же логином`);
  return target;
}
