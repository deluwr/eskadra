import { useState } from 'react';
import { api, type Scope, type Server, type Template } from '../api';
import { ErrorBox, Info, Modal, Tag, toast, useAsync, usePoll, ask } from '../ui';

export interface RoleInfo { id: string; name: string; builtin: boolean; owner: boolean; perms: string[]; scope: Scope; admins: number }
export interface RolesData { perms: Record<string, string>; roles: RoleInfo[] }

/** Разделы прав — для группировки в редакторе и матрице. */
const PERM_GROUPS: Array<[string, string[]]> = [
  ['Пользователи', ['users.edit', 'users.delete', 'users.limits']],
  ['Конфигурации', ['configs.edit', 'configs.rollout', 'configs.delete']],
  ['Серверы', ['servers.manage', 'servers.protect', 'cores.manage', 'ports.groups']],
  ['Панель', ['backups.run', 'settings.edit', 'ips.view']],
];
const OWNER_ONLY = ['Администраторы и роли', 'Бэкапы: получатели, пароль, восстановление; перенос панели', 'Токен бота, обновление панели', 'Терминал (shell) и режим SSH на сервере'];
const MODE_LABEL: Record<string, string> = { via: 'через вход', direct: 'напрямую' };

/** Краткая область роли: только то, что ограничено. */
function scopeSummary(s: Scope, names: { t: Map<string, string>; s: Map<string, string> }): string {
  const list = (v: string[], map?: Map<string, string>) => v.map((x) => map?.get(x) ?? x).join(', ') || 'ничего';
  const out: string[] = [];
  if (s.templates) out.push(`конфигурации: ${list(s.templates, names.t)}`);
  if (s.servers) out.push(`серверы: ${list(s.servers, names.s)}`);
  if (s.modes) out.push(`режимы: ${s.modes.map((m) => MODE_LABEL[m]).join(', ')}`);
  if (s.limitGroups) out.push(`группы лимитов: ${list(s.limitGroups)}`);
  if (s.maxUsers != null) out.push(`пользователей: до ${s.maxUsers}`);
  if (s.maxTemplates != null) out.push(`конфигураций: до ${s.maxTemplates}`);
  if (s.maxDevices != null) out.push(`устройств: до ${s.maxDevices}`);
  return out.join(' · ') || 'область: всё';
}

/** Роли: карточки в ряд, редактор поверх страницы, матрица прав из настроек ролей. */
export function RolesCard({ isOwner, onChange }: { isOwner: boolean; onChange: () => void }) {
  const { data, setData } = usePoll(() => api.get<RolesData>('/api/v1/roles'), null);
  const { data: tpls } = usePoll(() => api.get<Template[]>('/api/v1/templates'), null);
  const { data: servers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  const [edit, setEdit] = useState<RoleInfo | 'new' | null>(null);
  if (!data) return null;
  const names = { t: new Map((tpls ?? []).map((t) => [t.id, t.name])), s: new Map((servers ?? []).map((x) => [x.id, x.name])) };
  const has = (r: RoleInfo, k: string) => r.owner || r.perms.includes(k);
  return (
    <section className="card">
      <div className="card-head">
        <h2>Роли <Info>Роль — набор прав и область: какие конфигурации, серверы, режимы подключения и группы лимитов она выдаёт пользователям и меняет. Выданное вне области роль не может ни выдать, ни снять — оно остаётся как было. owner — все права; часть действий только у owner.</Info></h2>
        {isOwner && <button className="btn pri sm" onClick={() => setEdit('new')}>Новая роль</button>}
      </div>
      <div className="role-list">
        {data.roles.map((r) => (
          <button key={r.id} type="button" className="role" disabled={!isOwner || r.owner} onClick={() => setEdit(r)}>
            <span className="flex" style={{ justifyContent: 'space-between', width: '100%' }}><b>{r.name}</b>{r.builtin || r.owner ? <Tag>встроенная</Tag> : <Tag kind="acc">своя</Tag>}</span>
            <span className="k">{r.owner ? 'все права' : `прав: ${r.perms.length} из ${Object.keys(data.perms).length}`} · администраторов: {r.admins}</span>
            {!r.owner && <span className="k role-scope">{scopeSummary(r.scope, names)}</span>}
          </button>
        ))}
      </div>
      <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
        <table className="perm-mx" aria-label="Матрица прав">
          <thead><tr><th>Право</th>{data.roles.map((r) => <th key={r.id} style={{ textAlign: 'center' }}>{r.name}</th>)}</tr></thead>
          <tbody>
            {PERM_GROUPS.flatMap(([g, keys]) => [
              <tr key={g} className="grp"><td colSpan={data.roles.length + 1}>{g}</td></tr>,
              ...keys.map((k) => <tr key={k}><td className="small">{data.perms[k]}</td>{data.roles.map((r) => <td key={r.id} className={`c ${has(r, k) ? 'yes' : ''}`}>{has(r, k) ? '✓' : '—'}</td>)}</tr>),
            ])}
            <tr className="grp"><td colSpan={data.roles.length + 1}>Только owner</td></tr>
            {OWNER_ONLY.map((x) => <tr key={x}><td className="small">{x}</td>{data.roles.map((r) => <td key={r.id} className={`c ${r.owner ? 'yes' : ''}`}>{r.owner ? '✓' : '—'}</td>)}</tr>)}
          </tbody>
        </table>
      </div>
      {edit && <RoleEditor role={edit === 'new' ? null : edit} perms={data.perms} templates={tpls ?? []} servers={servers ?? []}
        onClose={() => setEdit(null)} onSaved={(d) => { setData(d); setEdit(null); onChange(); }} />}
    </section>
  );
}

/** «Все» или выбранные — для области роли. */
function ScopePick({ label, hint, all, value, onChange }: { label: string; hint: string; all: Array<[string, string]>; value: string[] | null; onChange: (v: string[] | null) => void }) {
  const toggle = (id: string) => { const cur = value ?? []; onChange(cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]); };
  return (
    <div className="ublock stack">
      <span className="flex" style={{ justifyContent: 'space-between' }}>
        <h3>{label} <Info>{hint}</Info></h3>
        <span className="flex" style={{ gap: 6 }}>
          <button type="button" className={`btn sm ${value === null ? 'pri' : 'ghost'}`} aria-pressed={value === null} onClick={() => onChange(null)}>Все</button>
          <button type="button" className={`btn sm ${value !== null ? 'pri' : 'ghost'}`} aria-pressed={value !== null} onClick={() => onChange(value ?? [])}>Выбранные</button>
        </span>
      </span>
      {value === null ? <span className="k">Без ограничения — в том числе те, что появятся позже.</span> : (
        <span className="chips">
          {all.map(([id, name]) => <label key={id} className="cb"><input type="checkbox" checked={value.includes(id)} onChange={() => toggle(id)} />{name}</label>)}
          {!all.length && <span className="k">Пока нечего выбрать.</span>}
        </span>
      )}
    </div>
  );
}

function RoleEditor({ role, perms, templates, servers, onClose, onSaved }: {
  role: RoleInfo | null; perms: Record<string, string>; templates: Template[]; servers: Server[]; onClose: () => void; onSaved: (d: RolesData) => void;
}) {
  const [name, setName] = useState(role?.name ?? '');
  const [p, setP] = useState<string[]>(role?.perms ?? ['users.edit']);
  const [sc, setSc] = useState<Scope>({ maxUsers: null, maxTemplates: null, maxDevices: null, ...(role?.scope ?? { templates: null, servers: null, modes: null, limitGroups: null }) });
  // поле лимита: пусто — без лимита
  const limitField = (key: 'maxUsers' | 'maxTemplates' | 'maxDevices', label: string, hint: string) => (
    <label className="fld"><span>{label} <Info>{hint}</Info></span>
      <input className="inp mono" inputMode="numeric" value={sc[key] ?? ''} placeholder="без лимита" aria-label={label}
        onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); setSc({ ...sc, [key]: v === '' ? null : Number(v) }); }} />
    </label>
  );
  const { data: groups } = usePoll(() => api.get<Array<{ name: string }>>('/api/v1/limit-groups'), null);
  const { busy, error, run } = useAsync();
  const togglePerm = (k: string) => setP(p.includes(k) ? p.filter((x) => x !== k) : [...p, k]);
  const save = () => run(async () => {
    if (sc.modes && !sc.modes.length) throw new Error('выберите хотя бы один режим подключения или «Все»');
    const body = { name: name.trim(), perms: p, scope: sc };
    onSaved(role ? await api.put<RolesData>(`/api/v1/roles/${role.id}`, body) : await api.post<RolesData>('/api/v1/roles', body));
    toast(role ? `Роль ${body.name} сохранена` : `Роль ${body.name} создана`);
  });
  const del = () => run(async () => {
    if (!role || !(await ask(`Удалить роль ${role.name}?`))) return;
    onSaved(await api.del<RolesData>(`/api/v1/roles/${role.id}`));
    toast(`Роль ${role.name} удалена`);
  });
  return (
    <Modal size="xl" title={role ? `Роль ${role.name}` : 'Новая роль'} onClose={onClose}>
      <label className="fld" style={{ maxWidth: 380 }}>Название
        <input className="inp" value={name} disabled={!!role?.builtin} onChange={(e) => setName(e.target.value)} placeholder="например, реселлер или поддержка" maxLength={32} />
        {role?.builtin && <span className="k">Встроенную роль не переименовать — права и область меняются.</span>}
      </label>
      <div className="ucard">
        <div className="ucol">
          {PERM_GROUPS.map(([g, keys]) => (
            <section key={g} className="ublock stack">
              <h3>{g}</h3>
              {keys.map((k) => <label key={k} className="cb"><input type="checkbox" checked={p.includes(k)} onChange={() => togglePerm(k)} />{perms[k]}</label>)}
            </section>
          ))}
          <span className="k">Администраторы, роли, бэкапы, токен бота, обновление панели и терминал на сервере — только у owner.</span>
        </div>
        <div className="ucol">
          <ScopePick label="Конфигурации" hint="Какие конфигурации роль выдаёт пользователям, меняет и выкатывает. С ограничением роль не создаёт новые конфигурации." all={templates.map((t) => [t.id, t.name])} value={sc.templates} onChange={(v) => setSc({ ...sc, templates: v })} />
          <ScopePick label="Серверы" hint="На какие серверы роль выдаёт доступ пользователям и какими управляет в рамках своих прав. С ограничением роль не подключает новые серверы." all={servers.map((x) => [x.id, x.name])} value={sc.servers} onChange={(v) => setSc({ ...sc, servers: v })} />
          <ScopePick label="Режимы подключения" hint="Что роль может выдать пользователю: через вход (relay) или напрямую к серверу." all={[['via', 'через вход'], ['direct', 'напрямую']]} value={sc.modes} onChange={(v) => setSc({ ...sc, modes: v as Scope['modes'] })} />
          <ScopePick label="Группы лимитов" hint="Какие группы лимитов роль назначает пользователям." all={(groups ?? []).map((g) => [g.name, g.name])} value={sc.limitGroups} onChange={(v) => setSc({ ...sc, limitGroups: v })} />
          <section className="ublock stack">
            <h3>Лимиты на администратора <Info>Считаются для каждого администратора с этой ролью отдельно. Пусто — без лимита. Удалённые пользователи и конфигурации освобождают место. Пользователи и конфигурации, созданные до появления лимита, не считаются.</Info></h3>
            <div className="grid g3">
              {limitField('maxUsers', 'Пользователей', 'Сколько пользователей может создать каждый администратор роли — в панели и в боте.')}
              {limitField('maxTemplates', 'Конфигураций', 'Сколько конфигураций может создать каждый администратор роли. Служебная Hysteria2 у eskadra не считается.')}
              {limitField('maxDevices', 'Устройств у пользователя', 'Лимит устройств пользователя, которого администратор роли создаёт или меняет, — не больше этого числа. Без лимита устройств сохранить нельзя: свой лимит пользователя или лимит его группы. Группы лимитов с бо́льшим числом устройств роль тоже не сохранит.')}
            </div>
          </section>
        </div>
      </div>
      <ErrorBox error={error} />
      <div className="savebar">
        <button className="btn pri" disabled={busy || name.trim().length < 2} onClick={() => void save()}>{role ? 'Сохранить' : 'Создать роль'}</button>
        <span className="spacer" />
        {role && !role.builtin && <button className="btn ghost sm" style={{ color: 'var(--fail)' }} disabled={busy || role.admins > 0} title={role.admins ? 'сначала смените роль администраторам' : undefined} onClick={() => void del()}>Удалить роль</button>}
      </div>
    </Modal>
  );
}
