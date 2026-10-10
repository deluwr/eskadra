import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** Envelope-шифрование секретов в БД (§4.7): AES-256-GCM, мастер-ключ отдельно от БД. */
export class Sealer {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error('master key must be 32 bytes');
  }

  seal(plain: string | Buffer): string {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([c.update(plain), c.final()]);
    return 'v1:' + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
  }

  open(sealed: string): Buffer {
    if (!sealed.startsWith('v1:')) throw new Error('unknown sealed format');
    const raw = Buffer.from(sealed.slice(3), 'base64');
    const d = createDecipheriv('aes-256-gcm', this.key, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]);
  }
}

export function loadOrCreateMasterKey(dataDir: string): Buffer {
  const file = path.join(dataDir, 'master.key');
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
  const key = randomBytes(32);
  fs.writeFileSync(file, key.toString('base64') + '\n', { mode: 0o600, flag: 'wx' });
  return key;
}

const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [kind, n, r, p, salt, hash] = stored.split('$');
  if (kind !== 'scrypt' || !n || !r || !p || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64');
  const got = scryptSync(password, Buffer.from(salt, 'base64'), expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
    maxmem: SCRYPT.maxmem,
  });
  return timingSafeEqual(expected, got);
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const sha256hex = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
