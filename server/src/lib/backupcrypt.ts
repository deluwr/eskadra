/**
 * Шифрование бэкапа паролем: scrypt (N=2^15) → ключ AES-256-GCM. Формат файла:
 * «ESKADRA-BACKUP-1\n» · соль 16 байт · IV 12 байт · тег 16 байт · шифротекст.
 * Пароль хранится в панели (зашифрован мастер-ключом), чтобы копии делались сами; для восстановления нужен только он.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

const MAGIC = Buffer.from('ESKADRA-BACKUP-1\n');
const keyOf = (password: string, salt: Buffer) => scryptSync(password, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });

export const isPasswordBackup = (data: Buffer) => data.subarray(0, MAGIC.length).equals(MAGIC);

export function encryptWithPassword(plain: Buffer, password: string): Buffer {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', keyOf(password, salt), iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, salt, iv, c.getAuthTag(), ct]);
}

export function decryptWithPassword(data: Buffer, password: string): Buffer {
  if (!isPasswordBackup(data)) throw new Error('файл не является бэкапом Эскадры');
  let o = MAGIC.length;
  const salt = data.subarray(o, (o += 16));
  const iv = data.subarray(o, (o += 12));
  const tag = data.subarray(o, (o += 16));
  const d = createDecipheriv('aes-256-gcm', keyOf(password, salt), iv);
  d.setAuthTag(tag);
  try { return Buffer.concat([d.update(data.subarray(o)), d.final()]); } catch { throw new Error('пароль не подходит к этой копии (или файл повреждён)'); }
}
