/**
 * Восстановление из бэкапа (§18.8):  npm run restore -w server -- <файл.age> <файл-ключа-age> [каталог]
 * Расшифровывает копию приватным ключом age (он хранится офлайн), проверяет sha256 по манифесту
 * и раскладывает fleet.db и master.key в каталог данных. Панель после этого запускается как обычно.
 */
import fs from 'node:fs';
import path from 'node:path';
import { decryptBackup } from './restorelib.js';
import { config } from './config.js';

const [file, keyFile, outDir = config.dataDir] = process.argv.slice(2);
if (!file || !keyFile) {
  console.error('usage: restore <backup.tar.gz.age> <age-identity-file> [data-dir]');
  process.exit(2);
}
const { manifest, files } = await decryptBackup(fs.readFileSync(file), fs.readFileSync(keyFile, 'utf8')).catch((e: Error) => { console.error(e.message); process.exit(1); });
fs.mkdirSync(outDir, { recursive: true });
for (const name of ['fleet.db', 'master.key']) {
  const dest = path.join(outDir, name);
  if (fs.existsSync(dest)) fs.renameSync(dest, `${dest}.before-restore-${Date.now()}`);
  fs.writeFileSync(dest, files.get(name)!, { mode: 0o600 });
}
console.log(`восстановлено из копии ${manifest.created} в ${outDir}. Запустите панель; при смене IP см. §7.10.`);
