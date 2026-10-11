import { useEffect, useState } from 'react';
import { api, fmtBytes, fmtTime, type Server, type User } from '../api';
import { CopyButton, ErrorBox, Modal, Seg, Tag, useAsync, usePoll, ask, Info, QrButton } from '../ui';

interface Form {
  name: string; tgId: string; limitGroup: string; trafficLimitGb: string; expireAt: string; deviceLimit: string;
  overAction: string; modes: string[]; nodeIds: string[] | null; wlMode: 'exact' | 'prefix' | 'asn'; status: 'active' | 'disabled';
}
const emptyForm: Form = { name: '', tgId: '', limitGroup: 'default', trafficLimitGb: '', expireAt: '', deviceLimit: '', overAction: 'disable', modes: ['direct', 'via'], nodeIds: null, wlMode: 'exact', status: 'active' };
const toForm = (u: User): Form => ({
  name: u.name, tgId: u.tg_id ?? '', limitGroup: u.limit_group, trafficLimitGb: u.traffic_limit_gb?.toString() ?? '', expireAt: u.expire_at?.slice(0, 10) ?? '',
  deviceLimit: u.device_limit?.toString() ?? '', overAction: u.over_action, modes: u.modes, nodeIds: u.node_ids, wlMode: u.wl_mode, status: u.status,
});
const num = (s: string) => (s.trim() === '' ? null : Number(s));

export function UsersPage() {
  const { data: users, reload } = usePoll(() => api.get<User[]>('/api/v1/users'), 30_000);
  const { data: st } = usePoll(() => api.get<{ whitelistOn: boolean }>('/api/v1/settings'), null);
  const wlOn = !!st?.whitelistOn;
  const { data: servers } = usePoll(() => api.get<Server[]>('/api/v1/servers'), null);
  const [sel, setSel] = useState<string | 'new' | null>(null);
  const [filter, setFilter] = useState<'all' | 'active' | 'expiring' | 'disabled'>('all');
  const [groups, setGroups] = useState(false);
  useEffect(() => { if (!sel && users?.length) setSel(users[0]!.id); }, [users, sel]);

  const soon = (u: User) => !!u.effective.expireAt && Date.parse(u.effective.expireAt) - Date.now() < 7 * 86400_000;
  const list = (users ?? []).filter((u) => filter === 'all' || (filter === 'disabled' ? u.status === 'disabled' : filter === 'active' ? u.status === 'active' : soon(u)));
  const user = users?.find((u) => u.id === sel) ?? null;

  return (
    <>
      <div className="page-head">
        <div><h1>Пользователи</h1><p>Лимиты, режимы подключения, подписки и ссылки</p></div>
        <div className="flex"><button className="btn" onClick={() => setGroups(true)}>Группы лимитов</button><button className="btn pri" onClick={() => setSel('new')}>Новый пользователь</button></div>
      </div>
      <SubServiceCard />
      <div className="split">
        <section className="card wide">
          <div className="card-head"><Seg value={filter} onChange={setFilter} label="Статус" options={[['all', `Все · ${users?.length ?? 0}`], ['active', 'Активные'], ['expiring', 'Истекают'], ['disabled', 'Отключены']]} /></div>
          <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
            <table>
              <thead><tr><th>Пользователь</th><th>Трафик за месяц</th><th>Срок</th><th>Режимы</th><th>Профилей</th>{wlOn && <th>Белый список</th>}</tr></thead>
              <tbody>
                {list.map((u) => {
                  const used = u.traffic.up + u.traffic.down;
                  const pct = u.effective.trafficGb ? Math.min(100, (used / (u.effective.trafficGb * 1024 ** 3)) * 100) : 0;
                  return (
                    <tr key={u.id} className={`clickable ${sel === u.id ? 'sel' : ''}`} onClick={() => setSel(u.id)}>
                      <td><b>{u.name}</b><div className="k">{u.limit_group}{u.status === 'disabled' && ` · отключён${u.disabled_reason ? `: ${u.disabled_reason}` : ''}`}</div></td>
                      <td><div className="stack" style={{ gap: 4 }}><span className="mono small">{fmtBytes(used)} / {u.effective.trafficGb ? `${u.effective.trafficGb} ГБ` : '∞'}</span>{u.effective.trafficGb ? <div className={`bar ${pct > 80 ? 'hot' : ''}`}><span style={{ width: `${pct}%` }} /></div> : null}</div></td>
                      <td>{u.effective.expireAt ? <span className={soon(u) ? 'tag warn' : 'k'}>до {u.effective.expireAt.slice(0, 10)}</span> : <span className="k">бессрочно</span>}</td>
                      <td><span className="flex" style={{ gap: 4 }}>{u.modes.map((m) => <Tag key={m}>{m === 'via' ? 'вход' : 'напрямую'}</Tag>)}</span></td>
                      <td className="mono small">{u.profiles}</td>
                      {wlOn && <td><Tag>{u.wl_mode === 'exact' ? '/32' : u.wl_mode === 'prefix' ? '/24' : 'ASN'}</Tag></td>}
                    </tr>
                  );
                })}
                {users && !list.length && <tr><td colSpan={wlOn ? 6 : 5} className="empty">Пользователей нет</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
        {servers && (sel === 'new' ? <UserCard key="new" user={null} servers={servers} wlOn={wlOn} onSaved={(u) => { void reload(); setSel(u.id); }} onDeleted={() => { setSel(null); void reload(); }} />
          : user && <UserCard key={user.id} user={user} servers={servers} wlOn={wlOn} onSaved={() => void reload()} onDeleted={() => { setSel(null); void reload(); }} />)}
      </div>
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

function UserCard({ user, servers, onSaved, onDeleted, wlOn }: { user: User | null; servers: Server[]; onSaved: (u: User) => void; onDeleted: () => void; wlOn: boolean }) {
  const [f, setF] = useState<Form>(user ? toForm(user) : emptyForm);
  const { data: groups } = usePoll(() => api.get<Array<{ name: string; traffic_gb: number | null; days: number | null; devices: number | null }>>('/api/v1/limit-groups'), null);
  const [mode, setMode] = useState<'sub' | 'links'>('sub');
  const [links, setLinks] = useState<Array<{ key: string; name: string; uri: string }> | null>(null);
  const [ip, setIp] = useState('');
  const { busy, error, run } = useAsync();
  const nodes = servers.filter((s) => s.role !== 'control');
  const toggleMode = (m: string) => setF({ ...f, modes: f.modes.includes(m) ? f.modes.filter((x) => x !== m) : [...f.modes, m] });
  const toggleNode = (id: string) => {
    const cur = f.nodeIds ?? nodes.map((n) => n.id);
    const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    setF({ ...f, nodeIds: next.length === nodes.length ? null : next });
  };
  const save = () => run(async () => {
    const body = { name: f.name, tgId: f.tgId || null, limitGroup: f.limitGroup, trafficLimitGb: num(f.trafficLimitGb), expireAt: f.expireAt ? new Date(f.expireAt + 'T23:59:59Z').toISOString() : null,
      deviceLimit: num(f.deviceLimit), overAction: f.overAction, modes: f.modes, nodeIds: f.nodeIds, wlMode: f.wlMode, status: f.status };
    onSaved(user ? await api.put<User>(`/api/v1/users/${user.id}`, body) : await api.post<User>('/api/v1/users', body));
  });
  const loadLinks = () => run(async () => user && setLinks(await api.get(`/api/v1/users/${user.id}/links`)));
  useEffect(() => { if (mode === 'links' && user) void loadLinks(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [mode, user?.id]);
  const rotate = (what: string) => run(async () => { if (!user) return; onSaved(await api.post<User>(`/api/v1/users/${user.id}/rotate`, { what })); if (what === 'links') void loadLinks(); });
  const g = groups?.find((x) => x.name === f.limitGroup);

  return (
    <section className="card narrow" aria-label="Карточка пользователя">
      <div className="card-head" style={{ alignItems: 'flex-start' }}>
        <div className="row-text"><h2 style={{ fontSize: 18 }}>{user ? user.name : 'Новый пользователь'}</h2>{user && <span className="k">группа «{user.limit_group}» · {user.tg_id ? 'Telegram привязан' : 'Telegram не привязан'}</span>}</div>
        {user && <Tag kind={user.status === 'active' ? 'ok' : 'fail'} dot>{user.status === 'active' ? 'активен' : 'отключён'}</Tag>}
      </div>
      <div className="row" style={{ display: 'block' }}>
        <div className="grid g2">
          <label className="fld">Имя<input className="inp" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="fld">Telegram ID<input className="inp mono" value={f.tgId} onChange={(e) => setF({ ...f, tgId: e.target.value })} placeholder="для /sub /links /access в боте" /></label>
        </div>
      </div>
      <div className="row stack" style={{ alignItems: 'stretch' }}>
        <h3>Ограничения</h3>
        <div className="grid g2">
          <label className="fld">Группа лимитов<select className="inp" value={f.limitGroup} onChange={(e) => setF({ ...f, limitGroup: e.target.value })}>{groups?.map((x) => <option key={x.name}>{x.name}</option>)}</select></label>
          <label className="fld">Трафик в месяц, ГБ<input className="inp mono" value={f.trafficLimitGb} onChange={(e) => setF({ ...f, trafficLimitGb: e.target.value })} placeholder={g?.traffic_gb ? `из группы: ${g.traffic_gb}` : '∞'} /></label>
          <label className="fld">Действует до<input className="inp mono" type="date" value={f.expireAt} onChange={(e) => setF({ ...f, expireAt: e.target.value })} /></label>
          <label className="fld">Устройств одновременно<input className="inp mono" value={f.deviceLimit} onChange={(e) => setF({ ...f, deviceLimit: e.target.value })} placeholder={g?.devices ? `из группы: ${g.devices}` : '∞'} /></label>
          <label className="fld">При превышении<select className="inp" value={f.overAction} onChange={(e) => setF({ ...f, overAction: e.target.value })}><option value="disable">отключить</option><option value="notify">только уведомить</option></select></label>
          <label className="fld">Статус<select className="inp" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value as Form['status'] })}><option value="active">активен</option><option value="disabled">отключён</option></select></label>
        </div>
        <span className="k">Пустое поле — значение из группы. Трафик считается по Xray; лимит устройств пока только отображается.</span>
      </div>
      <div className="row stack" style={{ alignItems: 'stretch' }}>
        <h3>Режимы подключения</h3>
        <label className="cb"><input type="checkbox" checked={f.modes.includes('via')} onChange={() => toggleMode('via')} />Через универсальный вход</label>
        <label className="cb"><input type="checkbox" checked={f.modes.includes('direct')} onChange={() => toggleMode('direct')} />Напрямую к серверу</label>
        <span className="k">Доступные узлы</span>
        <div className="flex">{nodes.map((n) => <label key={n.id} className="cb tag" style={{ minHeight: 36, padding: '0 12px' }}><input type="checkbox" checked={!f.nodeIds || f.nodeIds.includes(n.id)} onChange={() => toggleNode(n.id)} />{n.name}</label>)}</div>
      </div>
      {wlOn && <div className="row stack" style={{ alignItems: 'stretch' }}>
        <div className="flex" style={{ justifyContent: 'space-between' }}><h3>Белый список IP <Info>Включён скрытностью группы (раздел «Порты и связность»): к серверам группы пускаются только адреса из списка. Адрес добавляется по персональной ссылке пользователя или вручную.</Info></h3></div>
        <Seg value={f.wlMode} label="Гранулярность" onChange={(v) => setF({ ...f, wlMode: v })} options={[['exact', 'Точный IP'], ['prefix', 'Префикс /24'], ['asn', 'Сеть оператора']]} />
        <span className="k">{f.wlMode === 'exact' ? 'Для домашних: меньше всего чужих адресов проходит фильтр.' : f.wlMode === 'prefix' ? 'Для мобильных, у которых IP меняется внутри пула оператора.' : 'Самый широкий режим (/16): пропускает и чужие адреса той же сети.'}</span>
        {user?.allowedIps.map((a) => (
          <div key={a.id} className="flex" style={{ justifyContent: 'space-between', borderTop: '1px solid var(--line)', paddingTop: 8 }}>
            <span><span className="mono small">{a.cidr}</span> <span className="k">· {a.source} · до {fmtTime(a.expires_at)}</span></span>
            <button className="btn ghost sm" disabled={busy} onClick={() => void run(async () => onSaved(await api.del<User>(`/api/v1/users/${user.id}/allowed-ips/${a.id}`)))}>Отозвать</button>
          </div>
        ))}
        {user && <form className="flex" onSubmit={(e) => { e.preventDefault(); void run(async () => { onSaved(await api.post<User>(`/api/v1/users/${user.id}/allowed-ips`, { cidr: ip })); setIp(''); }); }}>
          <input className="inp mono" style={{ flex: 1 }} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="добавить вручную: 198.51.100.7" aria-label="IP" /><button className="btn sm" disabled={!ip || busy}>Добавить</button></form>}
      </div>}
      {user && (
        <div className="row stack" style={{ alignItems: 'stretch' }}>
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
                  <span className="row-text" style={{ minWidth: 0 }}><b className="small">{l.name}</b><span className="k mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 260 }}>{l.uri}</span></span>
                  <span className="flex" style={{ gap: 6 }}><QrButton text={l.uri} title={l.name} /><CopyButton text={l.uri} /></span>
                </div>
              ))}
              {links && !links.length && <span className="k">Нет активных профилей: выкатите конфигурацию на доступные узлы.</span>}
              {links && links.length > 0 && <div className="flex"><CopyButton text={links.map((l) => l.uri).join('\n')} label="Скопировать все" /><button className="btn sm" onClick={async () => { if (await ask('Перевыпустить ссылки? Старые перестанут работать.')) void rotate('links'); }}>Перевыпустить ссылки</button></div>}
            </>
          )}
        </div>
      )}
      <div className="row">
        <div className="flex"><button className="btn pri" disabled={busy || !f.name || !f.modes.length} onClick={() => void save()}>Сохранить</button>
          {user && <button className="btn ghost" style={{ color: 'var(--fail)' }} disabled={busy} onClick={async () => { if (await ask(`Удалить ${user.name}?`)) void run(async () => { await api.del(`/api/v1/users/${user.id}`); onDeleted(); }); }}>Удалить</button>}</div>
        <ErrorBox error={error} />
      </div>
    </section>
  );
}

function LimitGroups({ onClose }: { onClose: () => void }) {
  const { data, setData } = usePoll(() => api.get<Array<{ name: string; traffic_gb: number | null; days: number | null; devices: number | null }>>('/api/v1/limit-groups'), null);
  const [f, setF] = useState({ name: '', trafficGb: '', days: '', devices: '' });
  const { busy, error, run } = useAsync();
  return (
    <Modal title="Группы лимитов" onClose={onClose}>
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
