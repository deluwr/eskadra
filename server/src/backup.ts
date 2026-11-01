import fs from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import type { Ctx } from './ctx.js';
import { config } from './config.js';
import { getSetting, setSetting, type Db } from './db.js';
import { sha256hex } from './lib/crypto.js';
import { encryptWithPassword } from './lib/backupcrypt.js';
import { tarPack } from './lib/tar.js';
import { audit } from './lib/audit.js';
import type { Bot } from './bot.js';

/** tgIds — кому бот отправляет копию (Telegram ID человека или группы; получатель должен написать боту /start). */
/** every — как часто: каждый день, раз в неделю (в понедельник) или раз в месяц (1-го числа), в time по UTC. encrypt — шифровать паролем (без него копия с мастер-ключом лежит и уходит открытой). */
export type BackupEvery = 'day' | 'week' | 'month';
export interface BackupSettings { tgIds: string[]; time: string; enabled: boolean; every: BackupEvery; encrypt: boolean }

/** Пароль бэкапа: хранится зашифрованным мастер-ключом; нужен, чтобы копии делались сами по расписанию. */
export const backupPassword = (ctx: Ctx): string | null => {
  const sealed = getSetting<string>(ctx.db, 'backup.password', '');
  return sealed ? ctx.open(sealed) : null;
};

export function backupSettings(db: Db): BackupSettings {
  const s = getSetting<Partial<BackupSettings> & { recipients?: string[] }>(db, 'backup', {});
  // до v0.37 получатели — админы с отметкой «получает бэкапы»: их Telegram становится первым списком
  const tgIds = s.tgIds ?? (db.prepare(`SELECT tg_id FROM admins WHERE backup_recipient = 1 AND tg_id IS NOT NULL ORDER BY id`).all() as Array<{ tg_id: string }>).map((a) => a.tg_id);
  return { tgIds, time: s.time ?? '03:00', enabled: s.enabled ?? true, every: s.every ?? 'day', encrypt: s.encrypt ?? true };
}

/**
 * Снимок данных панели: база (VACUUM INTO, без незавершённых транзакций) и мастер-ключ, с манифестом sha256.
 * edit — правка копии базы перед упаковкой (перенос панели меняет в копии адреса); живая база не трогается.
 */
export function snapshotArchive(db: Db, profile: string, edit?: (copy: string) => void, extra: Array<{ name: string; data: Buffer }> = []): { archive: Buffer; manifestSha: string; created: string } {
  const dir = path.join(config.dataDir, 'backups');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmpDb = path.join(dir, `.snap-${Date.now()}.db`);
  db.exec(`VACUUM INTO '${tmpDb.replace(/'/g, "''")}'`);
  try {
    edit?.(tmpDb);
    const files = [
      { name: 'fleet.db', data: fs.readFileSync(tmpDb) },
      { name: 'master.key', data: fs.readFileSync(path.join(config.dataDir, 'master.key')) },
      ...extra,
    ];
    const prev = db.prepare(`SELECT sha256 FROM backups WHERE status IN ('ok','partial','local') ORDER BY id DESC LIMIT 1`).get() as { sha256: string } | undefined;
    const manifest = {
      format: 2, created: new Date().toISOString(), profile, panel: 'eskadra',
      contents: files.map((f) => ({ file: f.name, sha256: sha256hex(f.data), size: f.data.length })),
      prev_manifest_sha256: prev?.sha256 ?? null,
    };
    const manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2));
    return { archive: gzipSync(tarPack([{ name: 'manifest.json', data: manifestBuf }, ...files])), manifestSha: sha256hex(manifestBuf), created: manifest.created };
  } finally {
    fs.rmSync(tmpDb, { force: true });
  }
}

/**
 * Бэкап панели: база и мастер-ключ → tar.gz → AES-256-GCM на пароле бэкапа → бот отправляет файл на Telegram ID
 * из настроек. Локально хранятся последние 14 копий. Восстановить — файл копии и пароль.
 */
export class Backups {
  constructor(private readonly ctx: Ctx, private readonly bot: Bot) {}

  settings(): BackupSettings {
    return backupSettings(this.ctx.db);
  }

  dir() {
    const d = path.join(config.dataDir, 'backups');
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    return d;
  }

  async run(profile: 'full' | 'manual', actor = 'system'): Promise<{ id: number; file: string; size: number; delivered: number; total: number }> {
    const s = this.settings();
    const db = this.ctx.db;
    const password = s.encrypt ? backupPassword(this.ctx) : null;
    if (s.encrypt && !password) {
      const id = Number(db.prepare(`INSERT INTO backups (profile, status, detail) VALUES (?, 'failed', ?)`).run(profile, 'не задан пароль бэкапа').lastInsertRowid);
      throw Object.assign(new Error('задайте пароль бэкапа в «Настройках» — без него копию не зашифровать'), { backupId: id });
    }
    const snap = snapshotArchive(db, profile);
    // без шифрования — сам tar.gz: открывается без пароля, восстановление принимает и его
    const ct = password ? encryptWithPassword(snap.archive, password) : snap.archive;
    const stamp = snap.created.replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    const file = path.join(this.dir(), `eskadra-${profile}-${stamp}.tar.gz${password ? '.enc' : ''}`);
    fs.writeFileSync(file, ct, { mode: 0o600 });
    this.prune();

    const sent = await this.bot.sendBackup(path.basename(file), ct, s.tgIds);
    const status = sent.total === 0 ? 'local' : sent.ok === sent.total ? 'ok' : sent.ok ? 'partial' : 'failed';
    const id = Number(db.prepare('INSERT INTO backups (profile, size, sha256, status, detail) VALUES (?, ?, ?, ?, ?)')
      .run(profile, ct.length, snap.manifestSha, status, JSON.stringify({ file: path.basename(file), delivered: sent.ok, total: sent.total, errors: sent.errors })).lastInsertRowid);
    audit(db, actor, 'backup.created', String(id), { profile, size: ct.length, delivered: sent.ok, total: sent.total, encrypted: !!password });
    return { id, file: path.basename(file), size: ct.length, delivered: sent.ok, total: sent.total };
  }

  /** Локально храним последние 14 копий (и старые .age, пока не вытеснены); основная копия — у получателей в Telegram. */
  prune() {
    const files = fs.readdirSync(this.dir()).filter((f) => f.endsWith('.enc') || f.endsWith('.age') || f.endsWith('.tar.gz')).sort((a, b) => fs.statSync(path.join(this.dir(), a)).mtimeMs - fs.statSync(path.join(this.dir(), b)).mtimeMs);
    for (const f of files.slice(0, Math.max(0, files.length - 14))) fs.unlinkSync(path.join(this.dir(), f));
  }

  /** Копия по расписанию: каждый день, по понедельникам или 1-го числа — в заданное время (UTC). */
  async tick(now = new Date()) {
    const s = this.settings();
    if (!s.enabled || (s.encrypt && !backupPassword(this.ctx))) return;
    const due = lastDue(s, now);
    if (now < due) return;
    const last = this.ctx.db.prepare(`SELECT created_at FROM backups WHERE profile = 'full' ORDER BY id DESC LIMIT 1`).get() as { created_at: string } | undefined;
    if (last && Date.parse(last.created_at.replace(' ', 'T') + 'Z') >= due.getTime()) return;
    await this.run('full').catch(() => undefined);
  }
}

/** Последний момент по расписанию, не позже now (UTC): сегодня, ближайший прошедший понедельник или 1-е число в time. */
export function lastDue(s: Pick<BackupSettings, 'time' | 'every'>, now: Date): Date {
  const [hh, mm] = s.time.split(':').map(Number);
  const at = (y: number, m: number, d: number) => new Date(Date.UTC(y, m, d, hh ?? 3, mm ?? 0));
  const y = now.getUTCFullYear(), m = now.getUTCMonth(), d = now.getUTCDate();
  if (s.every === 'month') { const t = at(y, m, 1); return t <= now ? t : at(y, m - 1, 1); }
  if (s.every === 'week') { const back = (now.getUTCDay() + 6) % 7; const t = at(y, m, d - back); return t <= now ? t : at(y, m, d - back - 7); }
  return at(y, m, d);
}

/** Сохранить настройки бэкапа; password: строка — новый пароль, null — оставить прежний. */
export function saveBackupSettings(ctx: Ctx, s: Omit<BackupSettings, 'every' | 'encrypt'> & Partial<Pick<BackupSettings, 'every' | 'encrypt'>>, password: string | null) {
  setSetting(ctx.db, 'backup', s);
  if (password) setSetting(ctx.db, 'backup.password', ctx.seal(password));
}
