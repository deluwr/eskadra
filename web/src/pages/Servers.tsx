import { useState, type FormEvent } from 'react';
import { api, ago, type Server } from '../api';
import { ErrorBox, Info, Seg, useAsync, usePoll } from '../ui';
import { ServerTable } from '../ServerTable';
import { ViaPicker, viaBody, viaReady, type Via } from '../ViaPicker';

export function ServersPage() {
  const { data: servers, error, reload } = usePoll(() => api.get<Server[]>('/api/v1/servers'), 30_000);
  const [adding, setAdding] = useState(false);
  const [filter, setFilter] = useState<'all' | 'entry' | 'exit' | 'attn'>('all');
  const self = servers?.find((s) => s.mgmt_mode === 'local');
  const list = (servers ?? []).filter((s) =>
    filter === 'all' ? true : filter === 'attn' ? !!s.fail_since || s.stage < 2 : filter === 'exit' ? s.role === 'exit' : s.role !== 'exit');

  return (
    <>
      <div className="page-head">
        <div><h1>Серверы</h1><p>Узлы флота и их состояние</p></div>
        <div className="flex">
          <button className="btn pri" onClick={() => setAdding((v) => !v)}>{adding ? 'Скрыть форму' : 'Добавить сервер'}</button>
        </div>
      </div>
      <ErrorBox error={error} />
      {servers && !self && <SelfNodeCard onDone={(id) => { void reload(); location.hash = `#/server/${id}`; }} />}
      {adding && <AddServerForm onCreated={(id) => { void reload(); location.hash = `#/server/${id}`; }} onCancel={() => setAdding(false)} />}
      <Seg value={filter} onChange={setFilter} label="Фильтр" options={[
        ['all', `Все · ${servers?.length ?? 0}`], ['entry', 'Relay'], ['exit', 'Выходы'], ['attn', 'Требуют внимания'],
      ]} />
      <section className="card">
        {servers && <ServerTable servers={list} onChanged={() => void reload()}
          empty={servers.length ? 'Нет серверов в этом фильтре.' : 'Серверов пока нет. Начните с «Добавить сервер» — порядок действий описан в «Справке».'} />}
      </section>
    </>
  );
}

/** Главный сервер (где работает панель) становится входом для пользователей — одной кнопкой. */
function SelfNodeCard({ onDone }: { onDone: (id: string) => void }) {
  const { busy, error, run } = useAsync();
  return (
    <section className="card pad flex" style={{ justifyContent: 'space-between', borderColor: 'var(--accent)' }}>
      <div className="row-text" style={{ maxWidth: 640 }}>
        <b>Главный сервер может быть входом</b>
        <span className="small">Сервер, на котором работает панель, пока не принимает пользователей. Если сделать его входом, пользователи будут подключаться к нему, а он — пересылать трафик на выходы. Удобно, когда главный сервер в РФ: к нему проще подключиться.</span>
      </div>
      <div className="stack" style={{ alignItems: 'flex-end' }}>
        <button className="btn pri" disabled={busy} onClick={() => void run(async () => {
          const r = await api.post<{ server: Server }>('/api/v1/servers/self');
          onDone(r.server.id);
        })}>{busy ? 'Подключаю…' : 'Сделать главный сервер входом'}</button>
        <ErrorBox error={error} />
      </div>
    </section>
  );
}

function AddServerForm({ onCreated, onCancel }: { onCreated: (id: string) => void; onCancel: () => void }) {
  const [f, setF] = useState({ name: '', host: '', sshPort: '22', role: 'exit', group: 'default', mgmtMode: 'direct', user: 'root', method: 'password', password: '', privateKey: '', passphrase: '' });
  const { busy, error, run } = useAsync();
  const { data: groups } = usePoll(() => api.get<Array<{ name: string }>>('/api/v1/groups'), null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const [via, setVia] = useState<Via>({ kind: 'direct' });
  const create = (manual: boolean) => run(async () => {
    const auth = manual ? undefined : {
      ...(f.method === 'password' ? { user: f.user, password: f.password } : { user: f.user, privateKey: f.privateKey, ...(f.passphrase ? { passphrase: f.passphrase } : {}) }),
      ...viaBody(via),
    };
    const r = await api.post<{ server: Server }>('/api/v1/servers', {
      name: f.name, host: f.host, sshPort: Number(f.sshPort), role: f.role, group: f.group, mgmtMode: f.mgmtMode, ...(auth ? { auth } : {}),
    });
    onCreated(r.server.id);
  });
  const submit = (e: FormEvent) => { e.preventDefault(); void create(false); };
  const hasSecret = f.method === 'password' ? !!f.password : !!f.privateKey.trim();
  return (
    <form className="card pad stack" onSubmit={submit} autoComplete="off">
      <h2>Новый сервер</h2>
      <div className="grid g4">
        <label className="fld">Имя<input className="inp" value={f.name} onChange={set('name')} placeholder="de-1" required /></label>
        <label className="fld">IP или домен<input className="inp mono" value={f.host} onChange={set('host')} placeholder="203.0.113.10" required /></label>
        <label className="fld">Порт SSH<input className="inp mono" value={f.sshPort} onChange={set('sshPort')} inputMode="numeric" required /></label>
        <label className="fld"><span>Роль <Info>Выход — сервер, через который трафик уходит в интернет. Вход — сервер, к которому подключаются пользователи; он может пересылать их на выходы. Подробнее — в «Справке».</Info></span>
          <select className="inp" value={f.role} onChange={set('role')}><option value="exit">Выход</option><option value="entry">Relay</option></select>
        </label>
        <label className="fld"><span>Группа <Info>Группа задаёт политику портов и связности. Создать новую — в «Портах и связности».</Info></span>
          <select className="inp" value={f.group} onChange={set('group')}>{(groups ?? [{ name: 'default' }]).map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}</select>
        </label>
      </div>

      <div className="grid g4">
        <label className="fld"><span>Логин <Info>Обычно root. Подойдёт и пользователь с sudo — тогда пароль используется и для sudo.</Info></span>
          <input className="inp mono" value={f.user} onChange={set('user')} autoComplete="off" required />
        </label>
        <label className="fld">Вход по
          <select className="inp" value={f.method} onChange={set('method')}><option value="password">паролю</option><option value="key">SSH-ключу</option></select>
        </label>
        {f.method === 'password'
          ? <label className="fld" style={{ gridColumn: 'span 2' }}><span>Пароль <Info>Нужен один раз для первичной настройки. Не сохраняется: после настройки панель входит своим ключом.</Info></span>
              <input className="inp" type="password" value={f.password} onChange={set('password')} autoComplete="new-password" />
            </label>
          : <label className="fld" style={{ gridColumn: 'span 2' }}>Пароль ключа (если есть)<input className="inp" type="password" value={f.passphrase} onChange={set('passphrase')} autoComplete="new-password" /></label>}
      </div>
      {f.method === 'key' && (
        <label className="fld"><span>Приватный ключ <Info>Ключ, которым вы уже входите на этот сервер. Используется один раз и не сохраняется.</Info></span>
          <textarea className="inp mono" rows={4} value={f.privateKey} onChange={set('privateKey')} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellCheck={false} />
        </label>
      )}

      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="k" style={{ marginBottom: 6 }}>Канал управления <Info>Как панель будет ходить на сервер после настройки. Если главный сервер в РФ — выбирайте туннель: прямой SSH через границу может резаться.</Info></legend>
        <div className="choice">
          <label>
            <input type="radio" name="mgmt" value="direct" checked={f.mgmtMode === 'direct'} onChange={set('mgmtMode')} />
            <span><b>Напрямую по SSH</b></span>
          </label>
          <label>
            <input type="radio" name="mgmt" value="tunnel" checked={f.mgmtMode === 'tunnel'} onChange={set('mgmtMode')} />
            <span><b>Через туннель</b></span>
          </label>
        </div>
      </fieldset>

      {/* через прокси — значит SSH напрямую режется: и дальше управлять сервером лучше через туннель */}
      <ViaPicker value={via} onChange={(v) => { setVia(v); if (v.kind !== 'direct') setF((x) => ({ ...x, mgmtMode: 'tunnel' })); }} mgmtMode={f.mgmtMode} />

      <ErrorBox error={error} />
      <div className="flex">
        <button className="btn pri" disabled={busy || !hasSecret || !viaReady(via)}>{busy ? 'Добавляю…' : 'Добавить и настроить'}</button>
        <button type="button" className="btn ghost" onClick={onCancel}>Отмена</button>
        <span style={{ flex: 1 }} />
        <button type="button" className="link" disabled={busy || !f.name || !f.host} onClick={() => void create(true)}>Без пароля: выполню команду на сервере сам</button>
      </div>
    </form>
  );
}
