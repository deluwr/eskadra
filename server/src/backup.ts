import fs from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { Encrypter } from 'age-encryption';
import type { Ctx } from './ctx.js';
import { config } from './config.js';
import { getSetting } from './db.js';
import { sha256hex } from './lib/crypto.js';
import { tarPack } from './lib/tar.js';
import { audit } from './lib/audit.js';
import type { Bot } from './bot.js';

export interface BackupSettings { recipients: string[]; time: string; enabled: boolean }

/**
 * Бэкап панели (§18): БД, мастер-ключ, nodekit-версия → tar.gz → age на всех получателей.
 * Панель хранит только публичные ключи age и сама свои копии расшифровать не может.
 * Копии отправляются ботом админам-получателям (решение §24.1: на MVP только Telegram).
 */
export class Backups {
  constructor(private readonly ctx: Ctx, private readonly bot: Bot) {}

  settings(): BackupSettings {
    return getSetting<BackupSettings>(this.ctx.db, 'backup', { recipients: [], time: '03:00', enabled: true });
  }

  dir() {
    const d = path.join(config.dataDir, 'backups');
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    return d;
  }

  async run(profile: 'full' | 'manual', actor = 'system'): Promise<{ id: number; file: string; size: number; delivered: number; total: number }> {
    const s = this.settings();
    const db = this.ctx.db;
    if (!s.recipients.length) {
      const id = Number(db.prepare(`INSERT INTO backups (profile, status, detail) VALUES (?, 'failed', ?)`).run(profile, 'нет получателей age').lastInsertRowid);
      throw Object.assign(new Error('не заданы публичные ключи age получателей'), { backupId: id });
    }
    const tmpDb = path.join(this.dir(), `.snap-${Date.now()}.db`);
    db.exec(`VACUUM INTO '${tmpDb.replace(/'/g, "''")}'`);
    const files = [
      { name: 'fleet.db', data: fs.readFileSync(tmpDb) },
      { name: 'master.key', data: fs.readFileSync(path.join(config.dataDir, 'master.key')) },
    ];
    fs.unlinkSync(tmpDb);
    const prev = db.prepare(`SELECT sha256 FROM backups WHERE status IN ('ok','partial') ORDER BY id DESC LIMIT 1`).get() as { sha256: string } | undefined;
    const manifest = {
      format: 1, created: new Date().toISOString(), profile, panel: 'eskadra',
      contents: files.map((f) => ({ file: f.name, sha256: sha256hex(f.data), size: f.data.length })),
      prev_manifest_sha256: prev?.sha256 ?? null,
    };
    const manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2));
    const archive = gzipSync(tarPack([{ name: 'manifest.json', data: manifestBuf }, ...files]));
    const enc = new Encrypter();
    for (const r of s.recipients) enc.addRecipient(r);
    const ct = Buffer.from(await enc.encrypt(archive));
    const stamp = manifest.created.replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    const file = path.join(this.dir(), `eskadra-${profile}-${stamp}.tar.gz.age`);
    fs.writeFileSync(file, ct, { mode: 0o600 });
    this.prune();

    const sent = await this.bot.sendBackup(path.basename(file), ct);
    const status = sent.total === 0 ? 'local' : sent.ok === sent.total ? 'ok' : sent.ok ? 'partial' : 'failed';
    const id = Number(db.prepare('INSERT INTO backups (profile, size, sha256, status, detail) VALUES (?, ?, ?, ?, ?)')
      .run(profile, ct.length, sha256hex(manifestBuf), status, JSON.stringify({ file: path.basename(file), delivered: sent.ok, total: sent.total, errors: sent.errors })).lastInsertRowid);
    audit(db, actor, 'backup.created', String(id), { profile, size: ct.length, delivered: sent.ok, total: sent.total });
    return { id, file: path.basename(file), size: ct.length, delivered: sent.ok, total: sent.total };
  }

  /** Локально храним последние 14 зашифрованных копий; основная копия — у получателей в Telegram. */
  prune() {
    const files = fs.readdirSync(this.dir()).filter((f) => f.endsWith('.age')).sort();
    for (const f of files.slice(0, Math.max(0, files.length - 14))) fs.unlinkSync(path.join(this.dir(), f));
  }

  /** Ежедневная копия в заданное время (UTC). */
  async tick() {
    const s = this.settings();
    if (!s.enabled || !s.recipients.length) return;
    const [hh, mm] = s.time.split(':').map(Number);
    const now = new Date();
    const due = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hh ?? 3, mm ?? 0));
    if (now < due) return;
    const last = this.ctx.db.prepare(`SELECT created_at FROM backups WHERE profile = 'full' ORDER BY id DESC LIMIT 1`).get() as { created_at: string } | undefined;
    if (last && Date.parse(last.created_at.replace(' ', 'T') + 'Z') >= due.getTime()) return;
    await this.run('full').catch(() => undefined);
  }
}
