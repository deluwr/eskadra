// Собирает русские фрагменты интерфейса (текст JSX, строки, шаблонные строки с {} вместо подстановок).
// Используется тестом полноты перевода и при пополнении словаря: node web/scripts/i18n-extract.mjs [--missing]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(here, '..', 'src');
// строки сервера, которые показывает интерфейс: пункты проверки и предупреждения плана правил
const SERVER_FILES = ['firewall.ts', 'preflight.ts'].map((f) => path.join(here, '..', '..', 'server', 'src', f));
const CYR = /[А-Яа-яЁё]/;

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return files(p);
    return /\.(tsx?|ts)$/.test(e.name) && !/i18n|\.test\./.test(e.name) ? [p] : [];
  });
}

/** Убрать комментарии, не трогая строки (простое состояние «внутри строки»). */
function stripComments(src) {
  let out = '', i = 0, q = null;
  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (q) { out += c; if (c === '\\') { out += n ?? ''; i += 2; continue; } if (c === q) q = null; i++; continue; }
    if (c === '"' || c === "'" || c === '`') { q = c; out += c; i++; continue; }
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') { i = src.indexOf('*/', i + 2); i = i < 0 ? src.length : i + 2; continue; }
    out += c; i++;
  }
  return out;
}

export function extract() {
  const keys = new Set();
  const add = (s) => { s = s.replace(/\s+/g, ' ').trim(); if (CYR.test(s) && !s.includes('$')) keys.add(s); };
  for (const f of [...files(SRC), ...SERVER_FILES]) {
    const src = stripComments(fs.readFileSync(f, 'utf8'));
    // шаблонные строки: ${…} → {}
    for (const m of src.matchAll(/`((?:[^`\\]|\\.)*)`/g)) {
      let depth = 0, t = '', s = m[1];
      for (let i = 0; i < s.length; i++) {
        if (s[i] === '$' && s[i + 1] === '{' && depth === 0) { depth = 1; i++; t += '{}'; continue; }
        if (depth) { if (s[i] === '{') depth++; else if (s[i] === '}') depth--; continue; }
        t += s[i];
      }
      add(t);
    }
    // строки в кавычках
    for (const m of src.matchAll(/'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"/g)) add((m[1] ?? m[2]).replace(/\\(.)/g, '$1'));
    // текст JSX между тегами/выражениями
    // (?<![=\-]) — не «=>»/«->»; текст не должен быть похож на код
    const jsxText = (t) => { if (!/=>|\bconst\b|\?\.|\);|\]\s*;|=\s*[[{'"`]|\breturn\b/.test(t)) add(t); };
    for (const m of src.matchAll(/(?<![=\-])>([^<>{}]*[А-Яа-яЁё][^<>{}]*)(?=[<{])/g)) jsxText(m[1]);
    for (const m of src.matchAll(/\}([^<>{}`'"]*[А-Яа-яЁё][^<>{}`'"]*)(?=[<{])/g)) jsxText(m[1]);
  }
  return [...keys].sort();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const all = extract();
  if (process.argv.includes('--missing')) {
    const { EN } = await import(path.join(SRC, 'i18n-en.ts').replace(/\\/g, '/').replace(/^/, 'file:///'));
    const miss = all.filter((k) => !(k in EN));
    console.log(JSON.stringify(miss, null, 1));
    console.error(`${miss.length} из ${all.length} без перевода`);
  } else {
    console.log(JSON.stringify(all, null, 1));
    console.error(`${all.length} фрагментов`);
  }
}
