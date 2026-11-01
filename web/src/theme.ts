/**
 * Цветовые схемы панели. Цвета каждой схемы — в styles.css (блок [data-palette='…']); здесь — список для выбора и
 * применение. Схема ставится на <html> до первой отрисовки (main.tsx), выбор хранится в браузере.
 */
export type Mode = 'dark' | 'light';
export interface Palette { id: string; name: string; mode: Mode }

export const PALETTES: Palette[] = [
  { id: 'pult', name: 'Пульт', mode: 'dark' },
  { id: 'chart', name: 'Ночная карта', mode: 'dark' },
  { id: 'hacker-blue', name: 'Hacker Blue', mode: 'dark' },
  { id: 'kanagawa-wave', name: 'Kanagawa Wave', mode: 'dark' },
  { id: 'everforest-dark', name: 'Everforest Dark', mode: 'dark' },
  { id: 'night-owl', name: 'Night Owl', mode: 'dark' },
  { id: 'rose-pine', name: 'Rosé Pine', mode: 'dark' },
  { id: 'flexoki-dark', name: 'Flexoki Dark', mode: 'dark' },
  { id: 'homebrew', name: 'Homebrew', mode: 'dark' },
  { id: 'fsociety', name: 'fsociety', mode: 'dark' },
  { id: 'dracula', name: 'Dracula', mode: 'dark' },
  { id: 'monokai', name: 'Monokai', mode: 'dark' },
  { id: 'solarized-dark', name: 'Solarized Dark', mode: 'dark' },
  { id: 'nord', name: 'Nord', mode: 'dark' },
  { id: 'gruvbox-dark', name: 'Gruvbox Dark', mode: 'dark' },
  { id: 'tokyo-night', name: 'Tokyo Night', mode: 'dark' },
  { id: 'catppuccin-mocha', name: 'Catppuccin Mocha', mode: 'dark' },
  { id: 'atom-one-dark', name: 'Atom One Dark', mode: 'dark' },
  { id: 'cyberpunk', name: 'Cyberpunk', mode: 'dark' },
  { id: 'ayu-dark', name: 'Ayu Dark', mode: 'dark' },
  { id: 'pult-light', name: 'Пульт светлый', mode: 'light' },
  { id: 'chart-light', name: 'Морская карта', mode: 'light' },
  { id: 'kanagawa-lotus', name: 'Kanagawa Lotus', mode: 'light' },
  { id: 'everforest-light', name: 'Everforest Light', mode: 'light' },
  { id: 'rose-pine-dawn', name: 'Rosé Pine Dawn', mode: 'light' },
  { id: 'flexoki-light', name: 'Flexoki Light', mode: 'light' },
  { id: 'solarized-light', name: 'Solarized Light', mode: 'light' },
  { id: 'nord-light', name: 'Nord Light', mode: 'light' },
  { id: 'gruvbox-light', name: 'Gruvbox Light', mode: 'light' },
  { id: 'tokyo-day', name: 'Tokyo Day', mode: 'light' },
  { id: 'catppuccin-latte', name: 'Catppuccin Latte', mode: 'light' },
  { id: 'atom-one-light', name: 'Atom One Light', mode: 'light' },
  { id: 'ayu-light', name: 'Ayu Light', mode: 'light' },
  { id: 'man-page', name: 'Man Page', mode: 'light' },
];

/** «Как в системе»: «Пульт», тёмный или светлый — по настройке устройства. */
export const SYSTEM = 'system';
const KEY = 'eskadra.theme';
// до 1.0 хранилось только «dark» / «light»
const LEGACY: Record<string, string> = { dark: 'pult', light: 'pult-light' };

export function readTheme(): string {
  try {
    const v = localStorage.getItem(KEY) ?? SYSTEM;
    const id = LEGACY[v] ?? v;
    return id === SYSTEM || PALETTES.some((p) => p.id === id) ? id : SYSTEM;
  } catch { return SYSTEM; }
}

const systemDark = () => typeof matchMedia !== 'function' || matchMedia('(prefers-color-scheme: dark)').matches;

/** Схема, которую сейчас видно: для «как в системе» — по теме устройства. */
export function resolveTheme(id: string): Palette {
  const want = id === SYSTEM ? (systemDark() ? 'pult' : 'pult-light') : id;
  return PALETTES.find((p) => p.id === want) ?? PALETTES[0]!;
}

/** Применить схему к странице и запомнить выбор. */
export function applyTheme(id: string, save = false) {
  const p = resolveTheme(id);
  const root = document.documentElement;
  root.dataset.palette = p.id;
  root.dataset.theme = p.mode;    // светлые и тёмные мелочи (QR, тени) — по data-theme
  const bg = getComputedStyle(root).getPropertyValue('--bg').trim();
  if (bg) document.querySelector('meta[name="theme-color"]')?.setAttribute('content', bg);
  if (save) try { localStorage.setItem(KEY, id); } catch { /* приватный режим */ }
}

/** Следить за темой устройства, пока выбрано «как в системе»; вернуть отписку. */
export function followSystem(id: string, onChange: () => void): () => void {
  if (id !== SYSTEM || typeof matchMedia !== 'function') return () => undefined;
  const mq = matchMedia('(prefers-color-scheme: dark)');
  mq.addEventListener('change', onChange);
  return () => mq.removeEventListener('change', onChange);
}

/** Моноширинный шрифт интерфейса: подписи, таблицы, код. Все — с кириллицей. */
export const FONTS: Array<{ id: string; name: string }> = [
  { id: 'IBM Plex Mono', name: 'IBM Plex Mono' },
  { id: 'JetBrains Mono', name: 'JetBrains Mono' },
  { id: 'Fira Mono', name: 'Fira Mono' },
  { id: 'Source Code Pro', name: 'Source Code Pro' },
  { id: 'Roboto Mono', name: 'Roboto Mono' },
  { id: 'Ubuntu Mono', name: 'Ubuntu Mono' },
  { id: 'PT Mono', name: 'PT Mono' },
  { id: 'Anonymous Pro', name: 'Anonymous Pro' },
];
const FONT_KEY = 'eskadra.font';

export function readFont(): string {
  try { const v = localStorage.getItem(FONT_KEY) ?? ''; return FONTS.some((f) => f.id === v) ? v : FONTS[0]!.id; } catch { return FONTS[0]!.id; }
}

/** Применить шрифт ко всей панели и запомнить выбор. */
export function applyFont(id: string, save = false) {
  document.documentElement.style.setProperty('--mono', `'${id}', ui-monospace, monospace`);
  if (save) try { localStorage.setItem(FONT_KEY, id); } catch { /* приватный режим */ }
}
