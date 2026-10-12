import { useEffect, useState } from 'react';
import { ago, api, can, fmtBytes, fmtTime, inScope, type Server, type User } from '../api';
import { CopyButton, ErrorBox, Modal, Seg, Tag, TgBind, toast, useAsync, usePoll, ask, Info, QrButton, Addr } from '../ui';

interface Form {
  name: string; note: string; tgId: string; limitGroup: string; trafficLimitGb: string; expireAt: string; deviceLimit: string;
  overAction: string; modes: string[]; nodeIds: string[] | null; templateIds: string[] | null; wlMode: 'exact' | 'prefix' | 'asn'; status: 'active' | 'disabled';
  excludedProfiles: string[];
}
const emptyForm: Form = { name: '', note: '', tgId: '', limitGroup: 'default', trafficLimitGb: '', expireAt: '', deviceLimit: '', overAction: 'disable', modes: ['direct', 'via'], nodeIds: null, templateIds: null, wlMode: 'exact', status: 'active', excludedProfiles: [] };
const toForm = (u: User): Form => ({
  name: u.name, note: u.note, tgId: u.tg_id ?? '', limitGroup: u.limit_group, trafficLimitGb: u.traffic_limit_gb?.toString() ?? '', expireAt: u.expire_at?.slice(0, 10) ?? '',
  deviceLimit: u.device_limit?.toString() ?? '', overAction: u.over_action, modes: u.modes, nodeIds: u.node_ids, templateIds: u.template_ids, wlMode: u.wl_mode, status: u.status,
  excludedProfiles: [...u.excluded_profiles].sort(),
});
const num = (s: string) => (s.trim() === '' ? null : Number(s));

export function UsersPage() {
  const { data: users, reload, setData: setUsers } = usePoll(() => api.get<User[]>('/api/v1/users'), 30_000);
  const { data: st } = usePoll(() => api.get<{ whitelistOn: boolean }>('/api/v1/settings'), null);
  const wlOn = !!st?.whitelistOn;
  const { data: servers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  const [sel, setSel] = useState<string | 'new' | null>(null);
  const [filter, setFilter] = useState<'all' | 'online' | 'active' | 'expiring' | 'disabled'>('all');
  const [groups, setGroups] = useState(false);

  const soon = (u: User) => !!u.effective.expireAt && Date.parse(u.effective.expireAt) - Date.now() < 7 * 86400_000;
  const list = (users ?? []).filter((u) => filter === 'all' || (filter === 'online' ? u.online : filter === 'disabled' ? u.status === 'disabled' : filter === 'active' ? u.status === 'active' : soon(u)));
  const onlineN = (users ?? []).filter((u) => u.online).length;
  const [sort, setSort] = useState<Sort>(readSort);
  const sorted = sortUsers(list, sort);
  const th = (key: SortKey, label: string) => <SortTh key={key} k={key} label={label} sort={sort} onSort={(s) => { setSort(s); saveSort(s); }} />;
  const user = users?.find((u) => u.id === sel) ?? null;

  return (
    <>
      <div className="page-head">
        <div><h1>Пользователи</h1><p>Лимиты, режимы подключения, подписки и ссылки</p></div>
        <div className="flex">{can('users.limits') && <button className="btn" onClick={() => setGroups(true)}>Группы лимитов</button>}{can('users.edit') && <button className="btn pri" onClick={() => setSel('new')}>Новый пользователь</button>}</div>
      </div>
      <SubServiceCard />
      <section className="card">
        <div className="card-head"><Seg value={filter} onChange={setFilter} label="Статус" options={[['all', `Все · ${users?.length ?? 0}`], ['online', `Онлайн · ${onlineN}`], ['active', 'Активные'], ['expiring', 'Истекают'], ['disabled', 'Отключены']]} /></div>
        <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
          <table>
            <thead><tr>{th('name', 'Пользователь')}{th('traffic', 'Трафик за месяц')}{th('expire', 'Срок')}<th>Режимы</th>{th('devices', 'Устройства')}{th('profiles', 'Профилей')}{wlOn && <th>Белый список</th>}</tr></thead>
            <tbody>
              {sorted.map((u) => {
                const used = u.traffic.up + u.traffic.down;
                const pct = u.effective.trafficGb ? Math.min(100, (used / (u.effective.trafficGb * 1024 ** 3)) * 100) : 0;
                return (
                  <tr key={u.id} className={`clickable ${sel === u.id ? 'sel' : ''}`} onClick={() => setSel(u.id)}>
                    <td><span className="flex" style={{ gap: 8, flexWrap: 'nowrap' }}><OnlineDot u={u} /><b>{u.name}</b></span>{u.note && <div className="k note-line" title={u.note}>{u.note}</div>}<div className="k">{u.limit_group}{u.status === 'disabled' && ` · отключён${u.disabled_reason ? `: ${u.disabled_reason}` : ''}`}</div></td>
                    <td><div className="stack" style={{ gap: 4 }}><span className="mono small">{fmtBytes(used)} / {u.effective.trafficGb ? `${u.effective.trafficGb} ГБ` : '∞'}</span>{u.effective.trafficGb ? <div className={`bar ${pct > 80 ? 'hot' : ''}`}><span style={{ width: `${pct}%` }} /></div> : null}</div></td>
                    <td>{u.effective.expireAt ? <span className={soon(u) ? 'tag warn' : 'k'}>до {u.effective.expireAt.slice(0, 10)}</span> : <span className="k">бессрочно</span>}</td>
                    <td><span className="flex" style={{ gap: 4 }}>{u.modes.map((m) => <Tag key={m}>{m === 'via' ? 'вход' : 'напрямую'}</Tag>)}</span></td>
                    <td>{(() => { const on = u.devices.filter((d) => !d.blocked).length; const over = u.devices.length - on;
                    return <span className="flex" style={{ gap: 4 }}><span className="mono small">{on}{u.effective.devices ? ` / ${u.effective.devices}` : ''}</span>{over > 0 && <Tag kind="fail">+{over} заблок.</Tag>}</span>; })()}</td>
                  <td className="mono small">{u.profiles}</td>
                    {wlOn && <td><Tag>{u.wl_mode === 'exact' ? '/32' : u.wl_mode === 'prefix' ? '/24' : 'ASN'}</Tag></td>}
                  </tr>
                );
              })}
              {users && !list.length && <tr><td colSpan={wlOn ? 7 : 6} className="empty">Пользователей нет</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      {/* карточка — поверх страницы: таблица не сдвигается и не растёт вниз */}
      {servers && (sel === 'new' ? <UserCard key="new" user={null} servers={servers} wlOn={wlOn} onSaved={(u) => { void reload(); setSel(u.id); }} onDeleted={() => { setSel(null); void reload(); }} onClose={() => setSel(null)} />
        : user && <UserCard key={user.id} user={user} servers={servers} wlOn={wlOn} onSaved={(u) => setUsers((list) => list?.map((x) => (x.id === u.id ? u : x)) ?? list)} onDeleted={() => { setSel(null); void reload(); }} onClose={() => setSel(null)} />)}
      {groups && <LimitGroups onClose={() => setGroups(false)} />}
    </>
  );
}

function SubServiceCard() {
  const { data, reload } = usePoll(() => api.get<{ sub: { host: string; port: number; scheme: string } }>('/api/v1/settings'), null);
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const { busy, error, run } = useAsync();
  useEffect(() => { if (data) { setHost(data.sub.host); setPort(String(data.sub.port || '')); } }, [data]);
  const save = (randomPort = false) => run(async () => { await api.put('/api/v1/settings/sub', { host, port: num(port), scheme: data?.sub.scheme ?? 'http', randomPort }); void reload(); });
  return (
    <section className="card pad flex" style={{ alignItems: 'flex-end', gap: 16 }} aria-label="Сервис подписок">
      <div className="row-text" style={{ flex: '1 1 260px' }}><h2>Сервис подписок</h2><span className="k">Порт выбран случайно при установке, а не известный по умолчанию — так сервис сложнее найти сканером. Адрес — тот, по которому клиенты достают главный сервер.</span></div>
      <label className="fld" style={{ flex: '0 1 240px' }}>Адрес (домен или IP)<input className="inp mono" value={host} onChange={(e) => setHost(e.target.value)} placeholder="sub.example.com" /></label>
      <label className="fld" style={{ flex: '0 1 120px' }}>Порт<input className="inp mono" value={port} onChange={(e) => setPort(e.target.value)} /></label>
      <button className="btn" disabled={busy} onClick={() => void save(true)}>Случайный порт</button>
      <button className="btn pri" disabled={busy} onClick={() => void save()}>Сохранить</button>
      <ErrorBox error={error} />
    </section>
  );
}

/** Импорт подписки в популярные клиенты по их схемам ссылок. */
function importLinks(url: string, name: string): Array<[string, string]> {
  const u = encodeURIComponent(url);
  const n = encodeURIComponent(`Эскадра · ${name}`);
  return [
    ['Hiddify', `hiddify://import/${url}#${n}`],
    ['v2rayNG', `v2rayng://install-sub?url=${u}&name=${n}`],
    ['Happ', `happ://add/${url}`],
    ['Streisand', `streisand://import/${url}#${n}`],
    ['sing-box', `sing-box://import-remote-profile?url=${u}#${n}`],
  ];
}

const bodyOf = (f: Form) => ({ name: f.name, note: f.note, tgId: f.tgId || null, limitGroup: f.limitGroup, trafficLimitGb: num(f.trafficLimitGb), expireAt: f.expireAt ? new Date(f.expireAt + 'T23:59:59Z').toISOString() : null,
  deviceLimit: num(f.deviceLimit), overAction: f.overAction, modes: f.modes, nodeIds: f.nodeIds, templateIds: f.templateIds, wlMode: f.wlMode, status: f.status, excludedProfiles: f.excludedProfiles });

function UserCard({ user, servers, onSaved, onDeleted, onClose, wlOn }: { user: User | null; servers: Server[]; onSaved: (u: User) => void; onDeleted: () => void; onClose: () => void; wlOn: boolean }) {
  const [f, setF] = useState<Form>(user ? toForm(user) : emptyForm);
  const { data: groups } = usePoll(() => api.get<Array<{ name: string; traffic_gb: number | null; days: number | null; devices: number | null }>>('/api/v1/limit-groups'), null);
  const [mode, setMode] = useState<'sub' | 'links'>('sub');
  const [links, setLinks] = useState<Array<{ key: string; name: string; uri: string }> | null>(null);
  const [ip, setIp] = useState('');
  const { busy, error, run } = useAsync();
  const toggleMode = (m: string) => setF({ ...f, modes: f.modes.includes(m) ? f.modes.filter((x) => x !== m) : [...f.modes, m] });
  // конфигурации, профили которых попадут в подписку (у существующего пользователя — с примером профилей)
  const { data: tpls } = usePoll(() => api.get<Array<{ id: string; name: string }>>('/api/v1/templates'), null);
  const configs = user?.configs ?? tpls?.map((t) => ({ id: t.id, name: t.name, allowed: true, profiles: [] as User['configs'][number]['profiles'] })) ?? [];
  const toggleProfile = (key: string) => setF({ ...f, excludedProfiles: (f.excludedProfiles.includes(key) ? f.excludedProfiles.filter((k) => k !== key) : [...f.excludedProfiles, key]).sort() });
  const toggleTpl = (id: string) => {
    const all = configs.map((c) => c.id);
    const cur = f.templateIds ?? all;
    const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    setF({ ...f, templateIds: all.every((x) => next.includes(x)) ? null : next });
  };
  const save = () => run(async () => {
    // Telegram существующего пользователя меняется привязкой (кнопка «Привязать») — здесь берём сохранённый
    const body = { ...bodyOf(f), tgId: user ? user.tg_id : f.tgId || null };
    const saved = user ? await api.put<User>(`/api/v1/users/${user.id}`, body) : await api.post<User>('/api/v1/users', body);
    // форма — ровно то, что сохранил сервер (он, например, обрезает пробелы у комментария), иначе «несохранённые изменения» остаются
    setF(toForm(saved));
    onSaved(saved);
    toast(user ? 'Изменения сохранены' : `Пользователь ${f.name} создан`);
  });
  const dirty = !user || JSON.stringify({ ...f, tgId: '', note: f.note.trim() }) !== JSON.stringify({ ...toForm(user), tgId: '' });
  const loadLinks = () => run(async () => user && setLinks(await api.get(`/api/v1/users/${user.id}/links`)));
  useEffect(() => { if (mode === 'links' && user) void loadLinks(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [mode, user?.id]);
  const rotate = (what: string) => run(async () => { if (!user) return; onSaved(await api.post<User>(`/api/v1/users/${user.id}/rotate`, { what })); if (what === 'links') void loadLinks(); });
  const g = groups?.find((x) => x.name === f.limitGroup);
  // закрыть окно: несохранённые правки не теряем молча
  const close = async () => { if (!dirty || await ask('Закрыть без сохранения? Изменения пропадут.')) onClose(); };

  return (
    <Modal size="xl" title={user ? user.name : 'Новый пользователь'} onClose={close} head={user && (
      <span className="flex" style={{ gap: 8 }}>
        <span className="k">группа «{user.limit_group}» · {user.tg_id ? 'Telegram привязан' : 'Telegram не привязан'}</span>
        <Tag kind={user.status === 'active' ? 'ok' : 'fail'} dot>{user.status === 'active' ? 'активен' : 'отключён'}</Tag>
      </span>
    )}>
      <div className="ucard">
        <div className="ucol">
          <section className="ublock stack">
            <h3>Профиль</h3>
            <div className="grid g2">
              <label className="fld">Имя<input className="inp" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
              {user ? (
                <div className="fld"><span>Telegram <Info>В боте пользователь получает подписку, ссылки на профили и сведения о своём трафике.</Info></span>
                  <span className="flex" style={{ minHeight: 40 }}><TgBind tgId={user.tg_id} linkUrl={`/api/v1/users/${user.id}/tg-link`} onChanged={() => void api.get<User>(`/api/v1/users/${user.id}`).then(onSaved)}
                    onSaveId={(v) => api.put(`/api/v1/users/${user.id}`, { ...bodyOf(toForm(user)), tgId: v })} /></span></div>
              ) : <label className="fld">Telegram ID (необязательно)<input className="inp mono" inputMode="numeric" value={f.tgId} onChange={(e) => setF({ ...f, tgId: e.target.value.replace(/\D/g, '') })} placeholder="привязать можно и после создания" /></label>}
            </div>
            <label className="fld">Комментарий <span className="k">видят только администраторы</span>
              <textarea className="inp" rows={2} maxLength={500} value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} placeholder="кто это: друг Саши, рабочий ноутбук, оплатил до мая…" /></label>
          </section>
          <section className="ublock stack">
            <h3>Ограничения</h3>
            <div className="grid g3">
              <label className="fld">Группа лимитов<select className="inp" value={f.limitGroup} onChange={(e) => setF({ ...f, limitGroup: e.target.value })}>{groups?.filter((x) => inScope('limitGroups', x.name) || x.name === user?.limit_group).map((x) => <option key={x.name}>{x.name}</option>)}</select></label>
              <label className="fld">Трафик в месяц, ГБ<input className="inp mono" value={f.trafficLimitGb} onChange={(e) => setF({ ...f, trafficLimitGb: e.target.value })} placeholder={g?.traffic_gb ? `из группы: ${g.traffic_gb}` : '∞'} /></label>
              <label className="fld">Действует до<input className="inp mono" type="date" value={f.expireAt} onChange={(e) => setF({ ...f, expireAt: e.target.value })} /></label>
              <label className="fld">Устройств одновременно<input className="inp mono" value={f.deviceLimit} onChange={(e) => setF({ ...f, deviceLimit: e.target.value })} placeholder={g?.devices ? `из группы: ${g.devices}` : '∞'} /></label>
              <label className="fld">При превышении<select className="inp" value={f.overAction} onChange={(e) => setF({ ...f, overAction: e.target.value })}><option value="disable">отключить</option><option value="notify">только уведомить</option></select></label>
              <label className="fld">Статус<select className="inp" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value as Form['status'] })}><option value="active">активен</option><option value="disabled">отключён</option></select></label>
            </div>
            <span className="k">Пустое поле — значение из группы. Трафик считается по Xray. Устройство — адрес, с которого пользователь сейчас подключён; лишние блокируются только для этого пользователя.</span>
          </section>
          {user && <Devices user={user} />}
          {wlOn && <section className="ublock stack">
            <div className="flex" style={{ justifyContent: 'space-between' }}><h3>Белый список IP <Info>Включён скрытностью группы (раздел «Порты и связность»): к серверам группы пускаются только адреса из списка. Адрес добавляется по персональной ссылке пользователя или вручную.</Info></h3></div>
            <Seg value={f.wlMode} label="Гранулярность" onChange={(v) => setF({ ...f, wlMode: v })} options={[['exact', 'Точный IP'], ['prefix', 'Префикс /24'], ['asn', 'Сеть оператора']]} />
            <span className="k">{f.wlMode === 'exact' ? 'Для домашних: меньше всего чужих адресов проходит фильтр.' : f.wlMode === 'prefix' ? 'Для мобильных, у которых IP меняется внутри пула оператора.' : 'Самый широкий режим (/16): пропускает и чужие адреса той же сети.'}</span>
            {user?.allowedIps.map((a) => (
              <div key={a.id} className="flex" style={{ justifyContent: 'space-between', borderTop: '1px solid var(--line)', paddingTop: 8 }}>
                <span><span className="small"><Addr value={a.cidr} /></span> <span className="k">· {a.source} · до {fmtTime(a.expires_at)}</span></span>
                <button className="btn ghost sm" disabled={busy} onClick={() => void run(async () => onSaved(await api.del<User>(`/api/v1/users/${user.id}/allowed-ips/${a.id}`)))}>Отозвать</button>
              </div>
            ))}
            {user && <form className="flex" onSubmit={(e) => { e.preventDefault(); void run(async () => { onSaved(await api.post<User>(`/api/v1/users/${user.id}/allowed-ips`, { cidr: ip })); setIp(''); }); }}>
              <input className="inp mono" style={{ flex: 1 }} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="добавить вручную: 198.51.100.7" aria-label="IP" /><button className="btn sm" disabled={!ip || busy}>Добавить</button></form>}
          </section>}
        </div>
        <div className="ucol">
          <section className="ublock stack">
            <h3>Что попадёт в подписку</h3>
            <div className="flex" style={{ gap: 18 }}>
              <label className="cb"><input type="checkbox" checked={f.modes.includes('via')} disabled={!inScope('modes', 'via')} onChange={() => toggleMode('via')} />Через Relay (вход)</label>
              <label className="cb"><input type="checkbox" checked={f.modes.includes('direct')} disabled={!inScope('modes', 'direct')} onChange={() => toggleMode('direct')} />Напрямую к серверу</label>
              {(!inScope('modes', 'via') || !inScope('modes', 'direct')) && <span className="k">режим вне вашей роли не меняется</span>}
            </div>
            <span className="k">Конфигурации и варианты <Info>Отмеченные конфигурации дают пользователю свои варианты подключения; у снятой — ни одного. Отдельный вариант можно снять галочкой: он пропадёт из подписки, а его ссылка перестанет работать на сервере. Новые варианты (например, новый выход в конфигурации) появляются включёнными. Варианты зависят ещё и от режимов выше.</Info></span>
            {configs.length ? (
              <ul className="cfg-pick">
                {configs.map((c) => {
                  const mine = inScope('templates', c.id);
                  // вне области роли: у существующего пользователя — как было, новому не выдаётся
                  const on = (!f.templateIds || f.templateIds.includes(c.id)) && (mine || !!user);
                  return (
                    <li key={c.id} className={on ? '' : 'off'}>
                      <label className="cb"><input type="checkbox" checked={on} disabled={!mine} onChange={() => toggleTpl(c.id)} /><b>{c.name}</b>{!mine && <span className="k"> · вне вашей роли</span>}</label>
                      {user && (c.profiles.length
                        ? <span className="cfg-profiles">{c.profiles.map((p) => {
                          const pOn = !f.excludedProfiles.includes(p.key);
                          return (
                            <label key={p.key} className={`chip-cb ${pOn && on ? 'on' : ''}`} title={on ? (pOn ? 'вариант в подписке — снимите, чтобы убрать' : 'вариант выключен — ссылка не работает') : 'конфигурация не выдана'}>
                              <input type="checkbox" checked={pOn} disabled={!on || !mine} onChange={() => toggleProfile(p.key)} />{p.name}
                            </label>
                          );
                        })}</span>
                        : <span className="k">профилей нет: проверьте режимы и выкат конфигурации</span>)}
                    </li>
                  );
                })}
              </ul>
            ) : <span className="k">Конфигураций пока нет — создайте их в разделе «Конфигурации».</span>}
            {!user && <span className="k">Профили каждой конфигурации появятся здесь после создания пользователя.</span>}
            {f.nodeIds && <div className="alert warn small flex" style={{ justifyContent: 'space-between' }}>
              <span>{`Задано и ограничение по серверам: ${f.nodeIds.map((id) => servers.find((s) => s.id === id)?.name ?? id).join(', ') || 'ни одного'}`}</span>
              <button type="button" className="btn ghost sm" onClick={() => setF({ ...f, nodeIds: null })}>Снять</button>
            </div>}
          </section>
          {user && (
            <section className="ublock stack">
              <div className="flex" style={{ justifyContent: 'space-between' }}><h3>Подписка и ссылки</h3><Seg value={mode} onChange={setMode} label="Что выдавать" options={[['sub', 'Подписка'], ['links', 'Отдельные ссылки']]} /></div>
              {mode === 'sub' ? (
                user.subUrl ? (
                  <>
                    {user.profiles === 0 && <div className="alert warn">В подписке нет ни одного профиля — клиент (v2rayN и др.) ничего не добавит. Выкатите конфигурацию на серверы, доступные пользователю, и проверьте режимы подключения выше.</div>}
                    <div className="flex"><input className="inp mono" style={{ flex: 1 }} value={user.subUrl} readOnly aria-label="Ссылка подписки" /><CopyButton text={user.subUrl} /><QrButton text={user.subUrl} title={`Подписка · ${user.name}`} /></div>
                    <div className="flex" style={{ gap: 6 }}>
                      <span className="k">Открыть в приложении <Info>Кнопки работают на устройстве, где установлено приложение. В v2rayN (Windows) — «Подписки → Добавить», вставьте ссылку; или отсканируйте QR с экрана.</Info></span>
                      {importLinks(user.subUrl, user.name).map(([n, href]) => <a key={n} className="btn ghost sm" href={href}>{n}</a>)}
                    </div>
                    <div className="flex"><button className="btn sm" onClick={() => void rotate('sub')}>Сменить токен</button>{user.knockUrl && <CopyButton text={user.knockUrl} label="Knock-ссылка" />}</div>
                    <span className="k">Одна ссылка, обновляется сама. Профилей внутри: {user.profiles}.</span>
                  </>
                ) : <span className="k">Задайте адрес сервиса подписок выше.</span>
              ) : (
                <>
                  <span className="k">Ссылка на каждый профиль — для клиентов без подписок или чтобы дать один сервер. Сама не обновляется.</span>
                  {links?.map((l) => (
                    <div key={l.key} className="flex" style={{ justifyContent: 'space-between', borderTop: '1px solid var(--line)', paddingTop: 8 }}>
                      <span className="row-text" style={{ minWidth: 0, flex: 1 }}><b className="small">{l.name}</b><span className="k mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{l.uri}</span></span>
                      <span className="flex" style={{ gap: 6 }}><QrButton text={l.uri} title={l.name} /><CopyButton text={l.uri} /></span>
                    </div>
                  ))}
                  {links && !links.length && <span className="k">Нет активных профилей: выкатите конфигурацию на доступные узлы.</span>}
                  {links && links.length > 0 && <div className="flex"><CopyButton text={links.map((l) => l.uri).join('\n')} label="Скопировать все" /><button className="btn sm" onClick={async () => { if (await ask('Перевыпустить ссылки? Старые перестанут работать.')) void rotate('links'); }}>Перевыпустить ссылки</button></div>}
                </>
              )}
            </section>
          )}
        </div>
      </div>
      <ErrorBox error={error} />
      <div className="savebar">
        <button className="btn pri" disabled={busy || !f.name || !f.modes.length || !dirty} onClick={() => void save()}>{user ? 'Сохранить' : 'Создать пользователя'}</button>
        {user && dirty && <><span className="dirty"><span className="dot" />Есть несохранённые изменения</span><button className="btn ghost sm" onClick={() => setF(toForm(user))}>Отменить</button></>}
        <span className="spacer" />
        {user && can('users.delete') && <button className="btn ghost sm" style={{ color: 'var(--fail)' }} disabled={busy} onClick={async () => { if (await ask(`Удалить ${user.name}? Его ссылки и подписка перестанут работать.`)) void run(async () => { await api.del(`/api/v1/users/${user.id}`); toast(`${user.name} удалён`); onDeleted(); }); }}>Удалить</button>}
      </div>
    </Modal>
  );
}

// ───── сортировка таблицы: клик по заголовку, повторный — обратный порядок; выбор помнит браузер ─────

type SortKey = 'name' | 'traffic' | 'expire' | 'devices' | 'profiles';
interface Sort { key: SortKey; dir: 1 | -1 }
const SORT_LS = 'users.sort';
const readSort = (): Sort => { try { const v = JSON.parse(localStorage.getItem(SORT_LS) ?? '') as Sort; if (v && v.key && (v.dir === 1 || v.dir === -1)) return v; } catch { /* нет — по имени */ } return { key: 'name', dir: 1 }; };
const saveSort = (v: Sort) => { try { localStorage.setItem(SORT_LS, JSON.stringify(v)); } catch { /* приватный режим — не запоминаем */ } };

/** Порядок: выбранная колонка; при равенстве — онлайн выше, затем по имени. Бессрочные — в конце по сроку. */
function sortUsers(list: User[], s: Sort): User[] {
  const val = (u: User): number | string => {
    switch (s.key) {
      case 'name': return u.name.toLocaleLowerCase();
      case 'traffic': return u.traffic.up + u.traffic.down;
      case 'expire': return u.effective.expireAt ? Date.parse(u.effective.expireAt) : Number.MAX_SAFE_INTEGER;
      case 'devices': return u.devices.filter((d) => !d.blocked).length;
      case 'profiles': return u.profiles;
    }
  };
  return [...list].sort((a, b) => {
    const x = val(a), y = val(b);
    const c = typeof x === 'string' ? x.localeCompare(y as string, 'ru') : x - (y as number);
    return c * s.dir || Number(b.online) - Number(a.online) || a.name.localeCompare(b.name, 'ru');
  });
}

function SortTh({ k, label, sort, onSort }: { k: SortKey; label: string; sort: Sort; onSort: (s: Sort) => void }) {
  const on = sort.key === k;
  return (
    <th aria-sort={on ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className={`th-sort ${on ? 'on' : ''}`} onClick={() => onSort({ key: k, dir: on ? (sort.dir === 1 ? -1 : 1) : k === 'name' ? 1 : -1 })}>
        {label}<span aria-hidden="true" className="th-arrow">{on ? (sort.dir === 1 ? '▲' : '▼') : '↕'}</span>
      </button>
    </th>
  );
}

/** Онлайн-индикатор: зелёный — подключения видели в последнюю минуту; серый — «был …» по подсказке. */
function OnlineDot({ u }: { u: User }) {
  const title = u.online ? `в сети: устройств ${u.devices.filter((d) => !d.blocked).length}` : u.lastSeen ? `был в сети ${ago(u.lastSeen)}` : 'ещё не подключался';
  return <span className={`odot ${u.online ? 'on' : ''}`} title={title} role="img" aria-label={title} />;
}

/** Устройства пользователя сейчас: по ним работает лимит «Устройств одновременно». */
function Devices({ user }: { user: User }) {
  const limit = user.effective.devices;
  const active = user.devices.filter((d) => !d.blocked).length;
  return (
    <section className="ublock stack">
      <span className="flex" style={{ justifyContent: 'space-between' }}>
        <h3>Устройства сейчас <Info>Устройство — IP, с которого у пользователя открыты подключения (через вход или напрямую — считается один раз). Первые по времени подключения пропускаются, лишние блокируются — только для этого пользователя: другие с той же конфигурации и того же адреса не затрагиваются. Отключившееся устройство освобождает место через 2 минуты. Обновляется раз в 30 секунд; Hysteria2 и узлы с 3x-ui пока не учитываются.</Info></h3>
        <span className="k">{active}{limit ? ` из ${limit}` : ' · без лимита'}</span>
      </span>
      {user.devices.length ? (
        <div className="dev-list">
          {user.devices.map((d) => (
            <span key={d.ip} className={`dev ${d.blocked ? 'off' : ''}`}>
              <span className="small"><Addr value={d.ip} /></span>
              <span className="k">с {fmtTime(d.first_seen)}</span>
              {d.blocked ? <Tag kind="fail">сверх лимита — заблокировано</Tag> : <Tag kind="ok">подключено</Tag>}
            </span>
          ))}
        </div>
      ) : <span className="k">Сейчас не подключён.</span>}
    </section>
  );
}

function LimitGroups({ onClose }: { onClose: () => void }) {
  const { data, setData } = usePoll(() => api.get<Array<{ name: string; traffic_gb: number | null; days: number | null; devices: number | null }>>('/api/v1/limit-groups'), null);
  const [f, setF] = useState({ name: '', trafficGb: '', days: '', devices: '' });
  const { busy, error, run } = useAsync();
  return (
    <Modal size="md" title="Группы лимитов" onClose={onClose}>
      <table><thead><tr><th>Группа</th><th>Трафик</th><th>Дней</th><th>Устройств</th></tr></thead>
        <tbody>{data?.map((g) => <tr key={g.name} className="clickable" onClick={() => setF({ name: g.name, trafficGb: g.traffic_gb?.toString() ?? '', days: g.days?.toString() ?? '', devices: g.devices?.toString() ?? '' })}><td>{g.name}</td><td>{g.traffic_gb ?? '∞'}</td><td>{g.days ?? '∞'}</td><td>{g.devices ?? '∞'}</td></tr>)}</tbody></table>
      <div className="grid g2">
        <label className="fld">Имя<input className="inp" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label className="fld">Трафик, ГБ<input className="inp mono" value={f.trafficGb} onChange={(e) => setF({ ...f, trafficGb: e.target.value })} /></label>
        <label className="fld">Дней<input className="inp mono" value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })} /></label>
        <label className="fld">Устройств<input className="inp mono" value={f.devices} onChange={(e) => setF({ ...f, devices: e.target.value })} /></label>
      </div>
      <ErrorBox error={error} />
      <div className="flex"><button className="btn pri" disabled={busy || !f.name} onClick={() => void run(async () => setData(await api.put('/api/v1/limit-groups', { name: f.name, trafficGb: num(f.trafficGb), days: num(f.days), devices: num(f.devices) })))}>Сохранить группу</button><button className="btn ghost" onClick={onClose}>Закрыть</button></div>
    </Modal>
  );
}
