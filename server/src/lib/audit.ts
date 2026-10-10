import type { Db } from '../db.js';
import { sha256hex } from './crypto.js';

/** Append-only аудит с цепочкой хэшей (§17): подмена или удаление записи ломает цепочку. */
export function audit(db: Db, actor: string, action: string, target?: string, detail?: unknown): void {
  const prev = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').get() as { hash: string } | undefined;
  const ts = new Date().toISOString();
  const detailJson = detail === undefined ? null : JSON.stringify(detail);
  const hash = sha256hex([prev?.hash ?? '', ts, actor, action, target ?? '', detailJson ?? ''].join('\n'));
  db.prepare(
    'INSERT INTO audit_log (ts, actor, action, target, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(ts, actor, action, target ?? null, detailJson, prev?.hash ?? null, hash);
}

export function verifyAuditChain(db: Db): { ok: boolean; brokenAt?: number } {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id').all() as Array<{
    id: number; ts: string; actor: string; action: string; target: string | null;
    detail: string | null; prev_hash: string | null; hash: string;
  }>;
  let prev = '';
  for (const r of rows) {
    const h = sha256hex([prev, r.ts, r.actor, r.action, r.target ?? '', r.detail ?? ''].join('\n'));
    if (h !== r.hash || (r.prev_hash ?? '') !== prev) return { ok: false, brokenAt: r.id };
    prev = r.hash;
  }
  return { ok: true };
}
