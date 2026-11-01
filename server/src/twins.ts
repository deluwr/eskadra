/**
 * Один сервер — две записи в панели (одинаковый ключ хоста). Так получалось, когда панель переезжала на сервер,
 * который уже был во флоте, а потом главный сервер добавляли во флот ещё раз: у записей свои входы, а выкат
 * переписывает конфиг ядер на сервере целиком — выкат одной записи стирал конфигурации другой.
 *
 * Пока записей две, выкат на этот сервер не запускается (Ops.applyServer), а в «Требует внимания» и в карточке
 * сервера — объяснение и кнопка «Объединить»: админ выбирает, какое имя останется. Объединённая запись получает
 * входы, конфигурации, пользователей, роли, учётные данные (пароли и ссылки — те же) и служебные отметки обеих;
 * адрес — IP, если он есть у одной из записей (конфигурации с сертификатом на IP ходят на него, со «своим доменом» —
 * на свой домен); доступ главного сервера (local) переходит к ней же. Конфиг сервера собирается заново из всех входов.
 */
import { isIP } from 'node:net';
import type { Ctx, ServerRow } from './ctx.js';
import { Vpn } from './vpn.js';

const parse = <T>(s: string | null | undefined, d: T): T => { try { return s ? (JSON.parse(s) as T) : d; } catch { return d; } };

/** Другая запись того же сервера (одинаковый ключ хоста). */
export function twinOf(ctx: Ctx, s: Pick<ServerRow, 'id' | 'host_key_fp'>): ServerRow | undefined {
  return s.host_key_fp ? ctx.servers().find((x) => x.id !== s.id && x.host_key_fp === s.host_key_fp) : undefined;
}

export const twinText = (a: Pick<ServerRow, 'name'>, b: Pick<ServerRow, 'name'>) =>
  `«${a.name}» и «${b.name}» — один и тот же сервер: пока это две записи, выкат одной стирает конфигурации другой. Объедините их в карточке сервера`;

/**
 * Какая запись остаётся: с IP-адресом (на него ходят конфигурации с сертификатом на IP), при равенстве — не «главный
 * сервер как узел» (у него своя история и настройки), иначе более ранняя.
 */
function keeperOf(a: ServerRow, b: ServerRow): [ServerRow, ServerRow] {
  const ip = (s: ServerRow) => isIP(s.host) > 0;
  if (ip(a) !== ip(b)) return ip(a) ? [a, b] : [b, a];
  if ((a.mgmt_mode === 'local') !== (b.mgmt_mode === 'local')) return a.mgmt_mode === 'local' ? [b, a] : [a, b];
  return a.created_at <= b.created_at ? [a, b] : [b, a];
}

/** Перенести всё с записи dup на keep и удалить dup. */
export function mergeServer(ctx: Ctx, keep: ServerRow, dup: ServerRow): void {
  const { db } = ctx;
  const swap = (s: string) => s.split(dup.id).join(keep.id);
  db.exec('BEGIN');
  try {
    // входы: если у конфигурации вход уже есть на keep — остаётся он, дубль удаляется; состояние — как было
    for (const ib of db.prepare('SELECT id, template_id, kind FROM inbounds WHERE server_id = ?').all(dup.id) as Array<{ id: string; template_id: string; kind: string }>) {
      const clash = db.prepare('SELECT 1 FROM inbounds WHERE template_id = ? AND server_id = ? AND kind = ?').get(ib.template_id, keep.id, ib.kind);
      if (clash) db.prepare('DELETE FROM inbounds WHERE id = ?').run(ib.id);
      else db.prepare('UPDATE inbounds SET server_id = ? WHERE id = ?').run(keep.id, ib.id);
    }
    // конфигурации: вход, серверы (без повторов), порядок «Авто», домены и прочее в настройках
    for (const t of db.prepare('SELECT id, node_ids, entry_id, settings FROM templates').all() as Array<{ id: string; node_ids: string; entry_id: string | null; settings: string }>) {
      if (!t.node_ids.includes(dup.id) && t.entry_id !== dup.id && !t.settings.includes(dup.id)) continue;
      const nodes = [...new Set(parse<string[]>(t.node_ids, []).map((x) => (x === dup.id ? keep.id : x)))];
      db.prepare('UPDATE templates SET node_ids = ?, entry_id = ?, settings = ? WHERE id = ?')
        .run(JSON.stringify(nodes), t.entry_id === dup.id ? keep.id : t.entry_id, swap(t.settings), t.id);
    }
    // пользователи и роли: серверы, выключенные варианты; учётные данные — те же (ссылки и пароли не меняются)
    for (const u of db.prepare('SELECT id, node_ids, excluded_profiles FROM users').all() as Array<{ id: string; node_ids: string | null; excluded_profiles: string | null }>) {
      if (!u.node_ids?.includes(dup.id) && !u.excluded_profiles?.includes(dup.id)) continue;
      const nodes = u.node_ids ? JSON.stringify([...new Set(parse<string[]>(u.node_ids, []).map((x) => (x === dup.id ? keep.id : x)))]) : null;
      db.prepare('UPDATE users SET node_ids = ?, excluded_profiles = ? WHERE id = ?').run(nodes, u.excluded_profiles ? swap(u.excluded_profiles) : null, u.id);
    }
    for (const r of db.prepare('SELECT id, scope FROM roles').all() as Array<{ id: string; scope: string }>) {
      if (!r.scope.includes(dup.id)) continue;
      const sc = parse<{ servers?: string[] | null }>(r.scope, {});
      if (sc.servers) sc.servers = [...new Set(sc.servers.map((x) => (x === dup.id ? keep.id : x)))];
      db.prepare('UPDATE roles SET scope = ? WHERE id = ?').run(JSON.stringify(sc), r.id);
    }
    db.prepare('UPDATE OR IGNORE user_creds SET key = replace(key, ?, ?) WHERE instr(key, ?) > 0').run(dup.id, keep.id, dup.id);
    db.prepare('UPDATE OR IGNORE service_creds SET key = replace(key, ?, ?) WHERE instr(key, ?) > 0').run(dup.id, keep.id, dup.id);
    // служебные отметки: «выкачено» — заново у обеих; остальное (сертификаты, домены, ручная остановка ядер…) — к keep, если там своего нет
    db.prepare(`DELETE FROM settings WHERE key LIKE 'applied.%' AND (instr(key, ?) > 0 OR instr(key, ?) > 0)`).run(dup.id, keep.id);
    db.prepare('UPDATE OR IGNORE settings SET key = replace(key, ?, ?) WHERE instr(key, ?) > 0').run(dup.id, keep.id, dup.id);
    db.prepare('DELETE FROM settings WHERE instr(key, ?) > 0').run(dup.id);
    for (const s of db.prepare('SELECT key, value FROM settings WHERE instr(value, ?) > 0').all(dup.id) as Array<{ key: string; value: string }>)
      db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(swap(s.value), s.key);
    // главный сервер: остающаяся запись получает его доступ — панель заходит на свой хост через 127.0.0.1 своим ключом
    if (dup.mgmt_mode === 'local')
      db.prepare(`UPDATE servers SET mgmt_mode = 'local', mgmt_jump = NULL, ssh_port = ?, ssh_user = ?, key_pub = ?, key_priv_sealed = ? WHERE id = ?`)
        .run(dup.ssh_port, dup.ssh_user, dup.key_pub, dup.key_priv_sealed, keep.id);
    db.prepare('DELETE FROM servers WHERE id = ?').run(dup.id);
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  // конфиг сервера — из всех входов сразу; входы конфигураций, ведущих на него, — тоже заново
  new Vpn(ctx).markDirty();
}

/**
 * Объединить запись с её близнецом (кнопка в карточке сервера): остаётся одна запись с выбранным именем.
 * Возвращает id оставшейся записи и порты, которые совпали у входов (их нужно развести вручную).
 */
export function mergeTwins(ctx: Ctx, a: ServerRow, b: ServerRow, name: string): { id: string; clash: string[] } {
  if (!a.host_key_fp || a.host_key_fp !== b.host_key_fp || a.id === b.id) throw new Error('это разные серверы');
  const [keep, dup] = keeperOf(a, b);
  mergeServer(ctx, keep, dup);
  ctx.updateServer(keep.id, { name });
  const clash = (ctx.db.prepare('SELECT port, proto, COUNT(*) AS n FROM inbounds WHERE server_id = ? GROUP BY port, proto HAVING n > 1').all(keep.id) as Array<{ port: number; proto: string }>)
    .map((c) => `${c.port}/${c.proto}`);
  return { id: keep.id, clash };
}
