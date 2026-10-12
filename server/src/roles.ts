/**
 * Роли администраторов: набор прав и область — какие конфигурации, серверы, режимы подключения и группы
 * лимитов роль может выдавать пользователям и менять. owner — все права без ограничений; управление
 * администраторами и ролями, бэкапами, токеном бота, обновлением и терминалом на сервере — только у owner.
 *
 * Область работает «слиянием»: то, что у пользователя или конфигурации вне области роли, роль не видит как
 * своё и не может ни выдать, ни снять — при сохранении оно остаётся как было.
 */
import type { Db } from './db.js';
import type { UserRow } from './ctx.js';

export const PERMS = {
  'users.edit': 'Создавать и менять пользователей: подписки, ссылки, лимиты, белый список',
  'users.delete': 'Удалять пользователей',
  'users.limits': 'Менять группы лимитов',
  'configs.edit': 'Создавать и менять конфигурации, подбирать сайт маскировки',
  'configs.rollout': 'Выкатывать конфигурации, проверять выходы «Авто», продлевать сертификаты',
  'configs.delete': 'Удалять конфигурации',
  'servers.manage': 'Подключать, настраивать, перезапускать и удалять серверы',
  'servers.protect': 'Защита серверов: firewall, SSH, аварийный доступ, 3x-ui (с кодом 2FA)',
  'cores.manage': 'Ядра: установка, обновление, включение и выключение',
  'ports.groups': 'Группы портов и связности',
  'backups.run': 'Запускать бэкап',
  'settings.edit': 'Настройки панели: сервис подписок, язык, прокси бота, адреса исполнителя',
} as const;
export type Perm = keyof typeof PERMS;
export const PERM_KEYS = Object.keys(PERMS) as Perm[];

export interface Scope {
  /** null — все; иначе только эти */
  templates: string[] | null;
  servers: string[] | null;
  modes: Array<'direct' | 'via'> | null;
  limitGroups: string[] | null;
}
export const FULL_SCOPE: Scope = { templates: null, servers: null, modes: null, limitGroups: null };

export interface RoleInfo { id: string; name: string; builtin: boolean; owner: boolean; perms: Perm[]; scope: Scope }

interface RoleRow { id: string; name: string; builtin: number; perms: string; scope: string }

const parse = <T>(s: string, d: T): T => { try { return JSON.parse(s) as T; } catch { return d; } };

export function roleOf(db: Db, id: string): RoleInfo {
  if (id === 'owner') return { id, name: 'owner', builtin: true, owner: true, perms: PERM_KEYS, scope: FULL_SCOPE };
  const r = db.prepare('SELECT * FROM roles WHERE id = ?').get(id) as RoleRow | undefined;
  // роль удалили или неизвестна — никаких прав (только просмотр)
  if (!r) return { id, name: id, builtin: false, owner: false, perms: [], scope: FULL_SCOPE };
  return { id: r.id, name: r.name, builtin: !!r.builtin, owner: false, perms: parse<Perm[]>(r.perms, []).filter((p) => p in PERMS), scope: { ...FULL_SCOPE, ...parse<Partial<Scope>>(r.scope, {}) } };
}

export function listRoles(db: Db): RoleInfo[] {
  const rows = db.prepare('SELECT id FROM roles ORDER BY builtin DESC, name').all() as Array<{ id: string }>;
  return [roleOf(db, 'owner'), ...rows.map((r) => roleOf(db, r.id))];
}

export const can = (r: RoleInfo, p: Perm | 'owner') => r.owner || (p !== 'owner' && r.perms.includes(p));
export const inScope = (list: string[] | null, id: string) => !list || list.includes(id);

/** Список «выдано» с учётом области: вне области — как было, в области — как прислали. null — «все». */
export function mergeScoped(all: string[], prev: string[] | null, next: string[] | null, scope: string[] | null): string[] | null {
  if (!scope) return next;
  const prevSet = new Set(prev ?? all);
  const nextSet = new Set(next ?? all);
  const out = all.filter((id) => (scope.includes(id) ? nextSet.has(id) : prevSet.has(id)));
  return out.length === all.length ? null : out;
}

export class ScopeError extends Error {}

/**
 * Пользователь, которого сохраняет роль: конфигурации, серверы и режимы — слиянием с областью роли,
 * группа лимитов — только из области (прежняя, не из области, остаётся допустимой).
 */
export function scopeUserBody<B extends { templateIds: string[] | null; nodeIds: string[] | null; modes: Array<'direct' | 'via'>; limitGroup: string }>(
  db: Db, role: RoleInfo, prev: UserRow | null, b: B,
): B {
  if (role.owner) return b;
  const s = role.scope;
  const allTpl = (db.prepare('SELECT id FROM templates ORDER BY created_at').all() as Array<{ id: string }>).map((r) => r.id);
  const allSrv = (db.prepare('SELECT id FROM servers ORDER BY created_at').all() as Array<{ id: string }>).map((r) => r.id);
  const prevJson = (v: string | null | undefined) => (v ? parse<string[] | null>(v, null) : null);
  // новый пользователь: вне области ничего нет (а не «всё»)
  const prevTpl = prev ? prevJson(prev.template_ids) : s.templates ? [] : null;
  const prevSrv = prev ? prevJson(prev.node_ids) : s.servers ? [] : null;
  const templateIds = mergeScoped(allTpl, prevTpl, b.templateIds, s.templates);
  const nodeIds = mergeScoped(allSrv, prevSrv, b.nodeIds, s.servers);
  let modes = b.modes;
  if (s.modes) {
    const prevModes = prev ? parse<Array<'direct' | 'via'>>(prev.modes, []) : [];
    modes = (['direct', 'via'] as const).filter((m) => (s.modes!.includes(m) ? b.modes.includes(m) : prevModes.includes(m)));
    if (!modes.length) throw new ScopeError(`роль «${role.name}» может выдавать только: ${s.modes.map((m) => (m === 'via' ? 'через вход' : 'напрямую')).join(', ')}`);
  }
  if (s.limitGroups && !s.limitGroups.includes(b.limitGroup) && prev?.limit_group !== b.limitGroup)
    throw new ScopeError(`роль «${role.name}» не может назначать группу лимитов «${b.limitGroup}»`);
  return { ...b, templateIds, nodeIds, modes };
}

/** Серверы конфигурации, которые роль меняет: добавлять и убирать можно только серверы из области. */
export function checkTemplateServers(role: RoleInfo, prev: string[], next: string[]) {
  if (role.owner || !role.scope.servers) return;
  const changed = [...prev.filter((x) => !next.includes(x)), ...next.filter((x) => !prev.includes(x))];
  const bad = changed.filter((x) => !role.scope.servers!.includes(x));
  if (bad.length) throw new ScopeError(`роль «${role.name}» не управляет серверами: ${bad.join(', ')}`);
}

/** Встроенные роли: права по умолчанию повторяют прежние admin и operator. */
export const BUILTIN_ROLES: Array<{ id: string; name: string; perms: Perm[] }> = [
  { id: 'admin', name: 'admin', perms: PERM_KEYS },
  { id: 'operator', name: 'operator', perms: ['users.edit', 'configs.edit', 'configs.rollout'] },
];
