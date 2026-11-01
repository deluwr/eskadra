/**
 * Таблицы не уходят за край экрана: таблица, которая не помещается по ширине, показывается карточками —
 * каждая строка блоком, у каждой ячейки подпись из заголовка столбца. Помещается снова — обычная таблица.
 * Работает для всех таблиц в .table-wrap без правок разметки страниц; матрица связности — списком «сервер → сервер».
 */
const NATURAL = new WeakMap<HTMLElement, number>();

/** Подписи ячеек — текст заголовков столбцов (учитывает colSpan). */
function label(table: HTMLTableElement) {
  // текст заголовка без стрелки сортировки
  const text = (th: HTMLTableCellElement) => ((th.textContent ?? '').replace(th.querySelector('.th-arrow')?.textContent ?? '', '')).trim();
  const heads = [...(table.tHead?.rows[0]?.cells ?? [])].flatMap((th) => Array<string>(th.colSpan || 1).fill(text(th)));
  for (const body of table.tBodies)
    for (const tr of body.rows) {
      let i = 0;
      for (const td of tr.cells) {
        const want = td.colSpan > 1 ? '' : heads[i] ?? '';
        if (td.dataset.label !== want) td.dataset.label = want;
        i += td.colSpan || 1;
      }
    }
}

function fit(wrap: HTMLElement) {
  const table = wrap.querySelector(':scope > table');
  if (!(table instanceof HTMLTableElement)) return;
  label(table);
  const stacked = wrap.classList.contains('stacked');
  if (!stacked) {
    if (table.scrollWidth > wrap.clientWidth + 1) { NATURAL.set(wrap, table.scrollWidth); wrap.classList.add('stacked'); }
  } else if (wrap.clientWidth >= (NATURAL.get(wrap) ?? Infinity)) {
    wrap.classList.remove('stacked');
    // данные могли стать шире, пока таблица была карточками
    if (table.scrollWidth > wrap.clientWidth + 1) { NATURAL.set(wrap, table.scrollWidth); wrap.classList.add('stacked'); }
  }
}

export function startFitTables() {
  let queued = false;
  const all = () => { queued = false; document.querySelectorAll<HTMLElement>('.table-wrap').forEach(fit); };
  const later = () => { if (!queued) { queued = true; requestAnimationFrame(all); } };
  new MutationObserver(later).observe(document.body, { childList: true, subtree: true, characterData: true });
  addEventListener('resize', later);
  later();
}
