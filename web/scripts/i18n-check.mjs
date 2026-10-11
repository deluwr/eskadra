// Проверка полноты перевода: у каждой русской строки интерфейса есть английский вариант в src/i18n-en.ts.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extract } from './i18n-extract.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const dict = fs.readFileSync(path.join(here, '..', 'src', 'i18n-en.ts'), 'utf8');
const have = new Set([...dict.matchAll(/^\s*"((?:[^"\\]|\\.)*)":/gm)].map((m) => JSON.parse(`"${m[1]}"`)));
const missing = extract().filter((k) => !have.has(k));
if (missing.length) {
  console.error(`Нет перевода для ${missing.length} строк (добавьте в web/src/i18n-en.ts):\n` + missing.map((k) => '  ' + JSON.stringify(k)).join('\n'));
  process.exit(1);
}
console.log(`i18n: все ${have.size} строк переведены`);
