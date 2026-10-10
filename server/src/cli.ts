/**
 * eskadra-cli — служебные команды для терминального меню (scripts/eskadra).
 * Работает с той же базой, что и панель; запускается под root на главном сервере.
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, randomInt } from 'node:crypto';
import { config } from './config.js';
import { openDb, getSetting, setSetting } from './db.js';
import { hashPassword, loadOrCreateMasterKey, randomToken, Sealer } from './lib/crypto.js';
import { audit } from './lib/audit.js';
import { Ctx } from './ctx.js';

fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
const db = openDb(config.dataDir);
const [cmd, ...args] = process.argv.slice(2);
const out = (s: string) => process.stdout.write(s + '\n');
const fail = (s: string): never => { process.stderr.write(s + '\n'); process.exit(1); };

switch (cmd) {
  case 'setup-token': {
    if (db.prepare('SELECT 1 FROM admins LIMIT 1').get()) fail('владелец уже создан — токен не нужен');
    const t = randomToken(24);
    fs.writeFileSync(path.join(config.dataDir, 'setup-token'), t + '\n', { mode: 0o600 });
    out(t);
    break;
  }
  case 'reset-password': {
    const user = args[0] ?? (db.prepare(`SELECT username FROM admins WHERE role = 'owner' ORDER BY id LIMIT 1`).get() as { username: string } | undefined)?.username;
    if (!user) fail('администраторов нет — используйте ссылку первичной настройки');
    const row = db.prepare('SELECT id FROM admins WHERE username = ?').get(user!) as { id: number } | undefined;
    if (!row) fail(`нет администратора ${user}`);
    const pw = randomBytes(15).toString('base64url');
    db.prepare('UPDATE admins SET pw_hash = ? WHERE id = ?').run(hashPassword(pw), row!.id);
    db.prepare('DELETE FROM sessions WHERE admin_id = ?').run(row!.id);
    audit(db, 'console', 'admin.password_reset', user);
    out(`${user} ${pw}`);
    break;
  }
  case 'disable-2fa': {
    const user = args[0] ?? fail('usage: disable-2fa <username>');
    const r = db.prepare('UPDATE admins SET totp_enabled = 0, totp_sealed = NULL WHERE username = ?').run(user);
    if (!r.changes) fail(`нет администратора ${user}`);
    audit(db, 'console', 'admin.2fa_disabled', user);
    out(`2FA для ${user} отключена`);
    break;
  }
  case 'admins': {
    for (const a of db.prepare('SELECT username, role, totp_enabled FROM admins ORDER BY id').all() as Array<{ username: string; role: string; totp_enabled: number }>)
      out(`${a.username}\t${a.role}\t2FA:${a.totp_enabled ? 'да' : 'нет'}`);
    break;
  }
  case 'sub-port': {
    let port = getSetting<number>(db, 'sub.port', 0);
    if (args[0] === 'random' || (!port && !args[0])) { do port = randomInt(10000, 60000); while ([10085, 51820].includes(port)); }
    else if (args[0]) port = Number(args[0]);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) fail('порт 1024–65535');
    setSetting(db, 'sub.port', port);
    if (args[1]) setSetting(db, 'sub.host', args[1]);
    out(String(port));
    break;
  }
  case 'executor': {
    // главный сервер сам является исполнителем: его внешний IP — адрес, с которого он ходит на узлы
    if (args[0]) setSetting(db, 'executor.ips', args[0].split(',').filter(Boolean));
    out(getSetting<string[]>(db, 'executor.ips', []).join(','));
    break;
  }
  case 'status': {
    const n = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
    out(JSON.stringify({
      admins: n('SELECT COUNT(*) AS n FROM admins'),
      servers: n('SELECT COUNT(*) AS n FROM servers'),
      offline: n('SELECT COUNT(*) AS n FROM servers WHERE fail_since IS NOT NULL'),
      users: n('SELECT COUNT(*) AS n FROM users'),
      subPort: getSetting(db, 'sub.port', 0),
      subHost: getSetting(db, 'sub.host', ''),
      executorIps: getSetting(db, 'executor.ips', []),
      lastBackup: (db.prepare('SELECT created_at, status FROM backups ORDER BY id DESC LIMIT 1').get() as object | undefined) ?? null,
    }));
    break;
  }
  case 'backup': {
    const { Bot } = await import('./bot.js');
    const { Backups } = await import('./backup.js');
    const ctx = new Ctx(db, new Sealer(loadOrCreateMasterKey(config.dataDir)));
    const log = { warn: (m: unknown) => console.warn(m), info: () => undefined } as never;
    const r = await new Backups(ctx, new Bot(ctx, log)).run('manual', 'console');
    out(`${r.file} · доставлен ${r.delivered} из ${r.total}`);
    break;
  }
  default:
    out('usage: eskadra-cli setup-token | reset-password [user] | disable-2fa <user> | admins | sub-port [port|random] [host] | executor [ip,ip] | status | backup');
    process.exit(cmd ? 2 : 0);
}
