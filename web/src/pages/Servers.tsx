import { useState, type FormEvent } from 'react';
import { api, ago, type Server } from '../api';
import { ErrorBox, Seg, StagePip, Tag, useAsync, usePoll } from '../ui';

const ROLE_HINT: Record<string, string> = {
  entry: 'вход для пользователей', relay: 'промежуточный', exit: 'выход, скрыт', control: 'главный сервер',
};

export function ServersPage() {
  const { data: servers, error, reload } = usePoll(() => api.get<Server[]>('/api/v1/servers'), 30_000);
  const [adding, setAdding] = useState(false);
  const [filter, setFilter] = useState<'all' | 'entry' | 'exit' | 'control' | 'attn'>('all');
  const list = (servers ?? []).filter((s) =>
    filter === 'all' ? true : filter === 'attn' ? !!s.fail_since || !!s.ufw_active || s.stage < 3 : s.role === filter);

  return (
    <>
      <div className="page-head">
        <div><h1>Серверы</h1><p>Главный сервер и ноды: подключение, роль, уровень защиты, прямой доступ</p></div>
        <button className="btn pri" onClick={() => setAdding((v) => !v)}>{adding ? 'Скрыть форму' : 'Добавить сервер'}</button>
      </div>
      <ErrorBox error={error} />
      {adding && <AddServerForm onCreated={(id) => { void reload(); location.hash = `#/server/${id}`; }} onCancel={() => setAdding(false)} />}
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <Seg value={filter} onChange={setFilter} label="Фильтр" options={[
          ['all', `Все · ${servers?.length ?? 0}`], ['entry', 'entry'], ['exit', 'exit'], ['control', 'главный'], ['attn', 'Требуют внимания'],
        ]} />
        <span className="k">Этапы: подключён · настроен · проверен · защищён</span>
      </div>
      <section className="card table-wrap">
        <table>
          <thead><tr><th>Сервер</th><th>Роль</th><th>Этап</th><th>Защита хоста</th><th>Firewall</th><th>Прямой доступ</th><th>Связь</th></tr></thead>
          <tbody>
            {list.map((s) => (
              <tr key={s.id} className="clickable" onClick={() => (location.hash = `#/server/${s.id}`)}>
                <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a><div className="k mono">{s.host}:{s.ssh_port}</div></td>
                <td>{s.role}<div className="k">{s.group_name}</div></td>
                <td><StagePip stage={s.stage} /></td>
                <td className="mono small">{s.protection_current}{s.protection_current !== s.protection_target && <span className="k"> → цель {s.protection_target}</span>}</td>
                <td><Tag kind={s.fw_mode === 'enforced' ? 'ok' : s.fw_mode === 'pending' ? 'warn' : undefined}>{s.fw_mode}</Tag></td>
                <td>{s.direct_access ? <Tag kind="ok">включён</Tag> : <Tag>выключен</Tag>}</td>
                <td>{s.fail_since ? <Tag kind="fail" dot>нет связи</Tag> : <Tag kind={s.last_seen_at ? 'ok' : undefined} dot>{ago(s.last_seen_at)}</Tag>}</td>
              </tr>
            ))}
            {servers && !list.length && <tr><td colSpan={7} className="empty">Нет серверов в этом фильтре. Добавьте первый: панель выдаст ключ и bootstrap-сниппет.</td></tr>}
          </tbody>
        </table>
      </section>
      <div className="grid g3">
        <div className="card pad stack"><span className="k">Главный сервер</span><b>P1 «как есть» по умолчанию</b><span className="k">Защита опциональна: P2 закрывает лишние порты, P3 — ещё whitelist и вход только по ключам.</span></div>
        <div className="card pad stack"><span className="k">Ноды</span><b>Цель P3 сразу</b><span className="k">Блокировки включаются только после ручного чек-листа и под таймером отката на самом узле.</span></div>
        <div className="card pad stack"><span className="k">Разные серверы</span><b>Свой ключ на каждый</b><span className="k">Порт SSH, роль и группа задаются при добавлении; связь между нодами настраивается сама.</span></div>
      </div>
    </>
  );
}

function AddServerForm({ onCreated, onCancel }: { onCreated: (id: string) => void; onCancel: () => void }) {
  const [f, setF] = useState({ name: '', host: '', sshPort: '22', role: 'entry', group: 'default', mgmtMode: 'direct' });
  const { busy, error, run } = useAsync();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api.post<{ server: Server }>('/api/v1/servers', { ...f, sshPort: Number(f.sshPort) });
      onCreated(r.server.id);
    });
  };
  return (
    <form className="card pad stack" onSubmit={submit}>
      <h2>Новый сервер</h2>
      <div className="grid g4">
        <label className="fld">Имя<input className="inp" value={f.name} onChange={set('name')} placeholder="de-1" required /></label>
        <label className="fld">IP или FQDN<input className="inp mono" value={f.host} onChange={set('host')} placeholder="203.0.113.10" required /></label>
        <label className="fld">Порт SSH<input className="inp mono" value={f.sshPort} onChange={set('sshPort')} inputMode="numeric" required /></label>
        <label className="fld">Роль
          <select className="inp" value={f.role} onChange={set('role')}>
            {Object.entries(ROLE_HINT).map(([v, l]) => <option key={v} value={v}>{v} — {l}</option>)}
          </select>
        </label>
        <label className="fld">Группа<input className="inp" value={f.group} onChange={set('group')} placeholder="default" /></label>
      </div>
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="k" style={{ marginBottom: 6 }}>Канал управления</legend>
        <div className="choice">
          <label>
            <input type="radio" name="mgmt" value="direct" checked={f.mgmtMode === 'direct'} onChange={set('mgmtMode')} />
            <span><b>Напрямую по SSH</b><span className="k">Главный сервер вне РФ или SSH до узла проходит стабильно.</span></span>
          </label>
          <label>
            <input type="radio" name="mgmt" value="tunnel" checked={f.mgmtMode === 'tunnel'} onChange={set('mgmtMode')} />
            <span><b>Через служебный туннель</b><span className="k">Главный сервер в РФ: SSH идёт внутри VLESS-REALITY, ТСПУ видит обычный HTTPS. Сниппет поставит на узле служебный Xray.</span></span>
          </label>
        </div>
      </fieldset>
      <ErrorBox error={error} />
      <div className="flex">
        <button className="btn pri" disabled={busy}>Создать ключ и сниппет</button>
        <button type="button" className="btn ghost" onClick={onCancel}>Отмена</button>
        <span className="k">Панель выдаст отдельный ключ ed25519 и сниппет, который только добавляет доступ.</span>
      </div>
    </form>
  );
}
