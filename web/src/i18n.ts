/**
 * Перевод интерфейса RU → EN. Исходный язык разметки — русский; в английском режиме отрисованный текст и
 * атрибуты (placeholder, title, aria-label) заменяются по словарю i18n-en.ts. Ключ словаря — русская строка,
 * «{}» в ключе — подстановка (число, имя и т. п.). Составные подписи через « · » переводятся по частям.
 * Полноту словаря проверяет тест (web/scripts/i18n-check.mjs): у каждой русской строки интерфейса есть перевод.
 */
import { EN } from './i18n-en';

export type Lang = 'ru' | 'en';
const KEY = 'eskadra.lang';
const CYR = /[А-Яа-яЁё]/;
const ATTRS = ['placeholder', 'title', 'aria-label'];

export function getLang(): Lang {
  try { return localStorage.getItem(KEY) === 'en' ? 'en' : 'ru'; } catch { return 'ru'; }
}

/** Шаблоны с подстановками: «Все · {}» → /^Все · (.+?)$/ */
const patterns: Array<{ re: RegExp; out: string }> = Object.entries(EN)
  .filter(([k]) => k.includes('{}'))
  .map(([k, v]) => ({ re: new RegExp('^' + k.split('{}').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('(.+?)') + '$'), out: v }))
  .sort((a, b) => b.re.source.length - a.re.source.length);

const cache = new Map<string, string | null>();

/** Перевод одной строки (без внешних пробелов); null — перевода нет. */
export function tr(s: string): string | null {
  if (!CYR.test(s)) return null;
  const hit = cache.get(s);
  if (hit !== undefined) return hit;
  let out: string | null = EN[s] ?? null;
  if (out === null) {
    for (const p of patterns) {
      const m = s.match(p.re);
      // подстановка — данные (число, имя) или сама переводимая строка; иначе шаблон «{} из {}» портил бы любую фразу со словом «из»
      if (!m || !m.slice(1).every((g) => !CYR.test(g) || tr(g) !== null)) continue;
      let i = 1;
      out = p.out.replace(/\{\}/g, () => { const g = m[i++] ?? ''; return tr(g) ?? g; });
      break;
    }
  }
  // составные подписи: «de-1 · напрямую», «relay → авто», «12 · активно · ревизия 3»
  for (const sep of [' · ', ' → ']) {
    if (out !== null || !s.includes(sep)) continue;
    const src = s.split(sep);
    const parts = src.map((p) => tr(p) ?? p);
    if (parts.some((p, i) => p !== src[i])) out = parts.join(sep);
  }
  // хвост с двоеточием или точкой: «Сейчас:» и т. п.
  if (out === null) {
    const m = s.match(/^(.*?)([:.!?…]+)$/);
    const base = m?.[1] ? EN[m[1]] : undefined;
    if (base !== undefined) out = base + (m?.[2] ?? '');
  }
  cache.set(s, out);
  return out;
}

function translateText(node: Text) {
  const v = node.nodeValue ?? '';
  if (!CYR.test(v)) return;
  const lead = v.match(/^\s*/)![0], trail = v.match(/\s*$/)![0];
  const core = v.trim().replace(/\s+/g, ' ');
  const out = tr(core);
  // пишем только при изменении: любая запись вызывает событие наблюдателя, а перевод может сохранять кириллицу
  // (имена, «Language / Язык») — без этой проверки наблюдатель и перевод зацикливаются
  if (out !== null && lead + out + trail !== v) node.nodeValue = lead + out + trail;
}

function translateEl(el: Element) {
  for (const a of ATTRS) {
    const v = el.getAttribute(a);
    if (v && CYR.test(v)) { const out = tr(v.trim()); if (out !== null && out !== v) el.setAttribute(a, out); }
  }
}

function walk(root: Node) {
  if (root.nodeType === Node.TEXT_NODE) { translateText(root as Text); return; }
  if (root.nodeType !== Node.ELEMENT_NODE) return;
  const el = root as Element;
  if (el.closest('input, textarea, pre, code, .no-tr')) { translateEl(el); return; }   // данные пользователя и конфиги не трогаем
  translateEl(el);
  for (const c of Array.from(el.childNodes)) walk(c);
}

let observer: MutationObserver | null = null;

/** Включить перевод для языка; на русском — ничего не делает (перезагрузка возвращает исходный текст). */
export function startI18n(lang: Lang) {
  document.documentElement.lang = lang;
  if (lang !== 'en') return;
  const title = tr(document.title);
  if (title && title !== document.title) document.title = title;
  walk(document.body);
  observer = new MutationObserver((list) => {
    for (const m of list) {
      if (m.type === 'characterData') translateText(m.target as Text);
      else if (m.type === 'attributes') translateEl(m.target as Element);
      else m.addedNodes.forEach(walk);
    }
  });
  observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
}

/** Сменить язык: запоминается в браузере; страница перезагружается, чтобы русский текст вернулся без следов. */
export function setLang(lang: Lang) {
  try { localStorage.setItem(KEY, lang); } catch { /* приватный режим */ }
  location.reload();
}

/** Перевод строки в коде (для confirm-текстов, document.title и т. п.). */
export const t = (s: string) => (getLang() === 'en' ? tr(s) ?? s : s);
