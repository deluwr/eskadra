/**
 * Восстановление из бэкапа в консоли (§18.8):  npm run restore -w server -- <файл копии> <файл с паролем> [каталог]
 * Пароль бэкапа (для старых копий .age — приватный ключ age) читается из файла: так он не попадает в историю shell.
 * Проверяет sha256 по манифесту и раскладывает fleet.db и master.key в каталог данных; панель запускается как обычно.
 */
import fs from 'node:fs';
import path from 'node:path';
import { decryptBackup } from './restorelib.js';
import { config } from './config.js';

const [file, secretFile, outDir = config.dataDir] = process.argv.slice(2);
if (!file || !secretFile) {
  console.error('usage: restore <backup.tar.gz.enc|.age> <password-or-age-key-file> [data-dir]');
  process.exit(2);
}
const { manifest, files } = await decryptBackup(fs.readFileSync(file), fs.readFileSync(secretFile, 'utf8').replace(/\r?\n$/, '')).catch((e: Error) => { console.error(e.message); process.exit(1); });
fs.mkdirSync(outDir, { recursive: true });
for (const name of ['fleet.db', 'master.key']) {
  const dest = path.join(outDir, name);
  if (fs.existsSync(dest)) fs.renameSync(dest, `${dest}.before-restore-${Date.now()}`);
  fs.writeFileSync(dest, files.get(name)!, { mode: 0o600 });
}
console.log(`восстановлено из копии ${manifest.created} в ${outDir}. Запустите панель; при смене IP см. §7.10.`);
