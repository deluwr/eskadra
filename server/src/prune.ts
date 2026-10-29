/**
 * Ссылки на удалённые серверы. Строка servers удаляется, а её id остаётся в JSON-полях: серверы и вход
 * конфигурации, порядок «Авто», домены, серверы пользователей, область ролей, прокси бота и управления.
 * Такая «висящая» ссылка ломала сохранение конфигурации («сервер не найден»), хотя сервера уже не видно.
 * Чистим при удалении и при запуске панели (для того, что осталось от прежних версий).
 */
import type { Ctx } from './ctx.js';
import { getSetting, setSetting } from './db.js';

const parse = <T>(s: string | null | undefined, d: T): T => { try { return s ? (JSON.parse(s) as T) : d; } catch { return d; } };

/** Убрать ссылки на серверы, которых нет. Возвращает, что изменилось (для журнала). */
export function pruneServerRefs(ctx: Ctx): string[] {
  const { db } = ctx;
  const alive = new Set(ctx.servers().map((s) => s.id));
  const gone = (id: unknown) => typeof id === 'string' && id.startsWith('srv-') && !alive.has(id);
  const changed: string[] = [];

  // канал «через сервер»: посредник удалён — узел снова управляется напрямую (сменить канал можно в его карточке)
  for (const s of ctx.servers().filter((x) => x.mgmt_mode === 'jump' && gone(x.mgmt_jump))) {
    ctx.updateServer(s.id, { mgmt_mode: 'direct', mgmt_jump: null });
    changed.push(`канал управления ${s.name}`);
  }

  // конфигурации: серверы, вход, порядок «Авто», домены
  for (const t of db.prepare('SELECT id, name, node_ids, entry_id, settings FROM templates').all() as Array<{ id: string; name: string; node_ids: string; entry_id: string | null; settings: string }>) {
    const nodes = parse<string[]>(t.node_ids, []);
    const st = parse<Record<string, unknown>>(t.settings, {});
    const order = Array.isArray(st.exitOrder) ? (st.exitOrder as string[]) : [];
    const domains = st.domains && typeof st.domains === 'object' ? (st.domains as Record<string, string>) : {};
    const dropEntry = gone(t.entry_id);
    if (!nodes.some(gone) && !order.some(gone) && !Object.keys(domains).some(gone) && !dropEntry) continue;
    st.exitOrder = order.filter((x) => !gone(x));
    st.domains = Object.fromEntries(Object.entries(domains).filter(([k]) => !gone(k)));
    db.prepare(`UPDATE templates SET node_ids = ?, settings = ?, entry_id = ?, entry_port = CASE WHEN ? THEN NULL ELSE entry_port END,
      revision = revision + 1, updated_at = datetime('now') WHERE id = ?`)
      .run(JSON.stringify(nodes.filter((x) => !gone(x))), JSON.stringify(st), dropEntry ? null : t.entry_id, dropEntry ? 1 : 0, t.id);
    changed.push(`конфигурация ${t.name}`);
  }
  // пользователи: ограничение по серверам (пустой список остаётся пустым — «ни одного», а не «все»)
  for (const u of db.prepare('SELECT id, name, node_ids FROM users WHERE node_ids IS NOT NULL').all() as Array<{ id: string; name: string; node_ids: string }>) {
    const ids = parse<string[]>(u.node_ids, []);
    if (!ids.some(gone)) continue;
    db.prepare('UPDATE users SET node_ids = ? WHERE id = ?').run(JSON.stringify(ids.filter((x) => !gone(x))), u.id);
    changed.push(`пользователь ${u.name}`);
  }
  // роли: область серверов
  for (const r of db.prepare('SELECT id, name, scope FROM roles').all() as Array<{ id: string; name: string; scope: string }>) {
    const sc = parse<{ servers?: string[] | null }>(r.scope, {});
    if (!sc.servers?.some(gone)) continue;
    sc.servers = sc.servers.filter((x) => !gone(x));
    db.prepare('UPDATE roles SET scope = ? WHERE id = ?').run(JSON.stringify(sc), r.id);
    changed.push(`роль ${r.name}`);
  }
  // прокси бота через удалённый сервер — выключить
  const bot = getSetting<{ enabled: boolean; serverId: string } | null>(db, 'bot.proxy', null);
  if (bot?.serverId && gone(bot.serverId)) { setSetting(db, 'bot.proxy', { ...bot, enabled: false, serverId: '' }); changed.push('прокси бота'); }
  // служебные отметки удалённых серверов
  db.prepare(`DELETE FROM settings WHERE (key LIKE 'applied.srv-%' OR key LIKE 'limits.applied.srv-%') AND substr(key, instr(key, 'srv-')) NOT IN (SELECT id FROM servers)`).run();
  return changed;
}
