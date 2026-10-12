import { useState } from 'react';
import { api, ago } from '../api';
import { ErrorBox, Info, Tag, roleLabel, useAsync, usePoll, toast } from '../ui';

interface Conn {
  servers: Array<{ id: string; name: string; group: string; role: string; ufw: boolean; sshPorts: number[]; fwMode: string }>;
  inbounds: Array<{ server_id: string; port: number; proto: string; state: string; template: string }>;
  checks: Array<{ from_id: string; to_id: string; result: string; checked_at: string; fail_since: string | null }>;
  groups: Array<{ name: string; stealth: string; peer_scope: string; port_range: string }>;
}

const STEALTH: Record<string, string> = { S0: 'открыто всем (по умолчанию)', S1: '+ ограничение частоты', S2: '+ фильтр по стране/оператору', S3: 'только белый список IP', S4: 'S4 · скрытые exit' };

export function PortsPage() {
  const { data: d, reload } = usePoll(() => api.get<Conn>('/api/v1/connectivity'), 30_000);
  if (!d) return <p className="muted">Загрузка…</p>;
  const check = (a: string, b: string) => d.checks.find((c) => c.from_id === a && c.to_id === b);
  const last = d.checks.reduce((m, c) => (c.checked_at > m ? c.checked_at : m), '');
  return (
    <>
      <div className="page-head"><div><h1>Порты и связность</h1><p>Открытые порты и связь между серверами</p></div></div>
      <section className="card">
        <div className="card-head"><h2>Политика групп <Info>Группа задаёт скрытность портов, связь между нодами и разрешённый диапазон портов. Новая нода попадает в наборы соседей сама. Нажмите на группу, чтобы изменить её политику.</Info></h2><NewGroup onSaved={reload} /></div>
        <div className="grp-list">
          {d.groups.map((g) => <GroupRow key={g.name} g={g} servers={d.servers.filter((s) => s.group === g.name)} onSaved={reload} />)}
        </div>
      </section>
      <section className="card pad stack">
        <div className="flex" style={{ justifyContent: 'space-between' }}><h2>Связность нод <Info>Строка — откуда, столбец — куда. Проверяется каждые 10 минут. Долгий сбой связи сбрасывает чек-лист защиты обеих нод.</Info></h2><span className="k">{last ? ago(last) : 'ещё не проверялось'}</span></div>
        {d.servers.length < 2 ? <p className="k">Нужно минимум два узла с nodekit.</p> : (
          <div className="table-wrap">
            <table className="mx" aria-label="Матрица связности">
              <thead><tr><th />{d.servers.map((s) => <th key={s.id}>{s.name}</th>)}</tr></thead>
              <tbody>{d.servers.map((a) => (
                <tr key={a.id}><th className="r" scope="row">{a.name}</th>
                  {d.servers.map((b) => {
                    if (a.id === b.id) return <td key={b.id} className="c-self">—</td>;
                    const c = check(a.id, b.id);
                    return <td key={b.id} className={!c ? 'c-none' : c.result === 'ok' ? 'c-ok' : 'c-fail'} title={c ? `проверено ${ago(c.checked_at)}${c.fail_since ? `, сбой с ${c.fail_since}` : ''}` : 'не проверялось'}>{!c ? '?' : c.result === 'ok' ? '✓' : 'нет'}</td>;
                  })}
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
      <section className="card">
        <div className="card-head"><h2>Порты узлов <Info>Порт конфигурации открывается сам при выкате: проверка (не SSH, не занят, в диапазоне группы) → проверка конфига на узле → открытие порта → внешняя проба, при ошибке — откат. Защищённые порты (SSH, служебные) не трогаются никогда. Если у хостера свой firewall, диапазон портов группы откройте в нём заранее.</Info></h2></div>
        <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
          <table>
            <thead><tr><th>Узел</th><th>Сервисные TCP</th><th>Сервисные UDP</th><th>Защищённые</th><th>Firewall</th><th>ufw/firewalld</th></tr></thead>
            <tbody>{d.servers.map((s) => {
              const ib = d.inbounds.filter((i) => i.server_id === s.id);
              const show = (proto: string) => ib.filter((i) => i.proto === proto).map((i) => <Tag key={`${i.port}${i.template}`} kind={i.state === 'active' ? 'ok' : i.state === 'error' ? 'fail' : 'warn'}>{i.port} · {i.template}</Tag>);
              return (
                <tr key={s.id}>
                  <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a><div className="k">{s.group} · {roleLabel(s)}</div></td>
                  <td><span className="flex" style={{ gap: 4 }}>{show('tcp').length ? show('tcp') : <span className="k">—</span>}</span></td>
                  <td><span className="flex" style={{ gap: 4 }}>{show('udp').length ? show('udp') : <span className="k">—</span>}</span></td>
                  <td><span className="flex" style={{ gap: 4 }}>{s.sshPorts.map((p) => <Tag key={p} kind="acc">{p}</Tag>)}<Tag kind="acc">10085 lo</Tag></span></td>
                  <td><Tag kind={s.fwMode === 'enforced' ? 'ok' : undefined}>{s.fwMode}</Tag></td>
                  <td>{s.ufw ? <Tag kind="warn">включён</Tag> : <Tag>выключен</Tag>}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </section>
    </>
  );
}

/** Новая группа со своей политикой; серверы переносятся в неё в карточке сервера (вкладка «Доступ»). */
function NewGroup({ onSaved }: { onSaved: () => void }) {
  const [name, setName] = useState('');
  const { busy, error, run } = useAsync();
  return (
    <form className="flex" style={{ gap: 8 }} onSubmit={(e) => { e.preventDefault(); void run(async () => { await api.put('/api/v1/groups', { name: name.trim(), stealth: 'S0', peerScope: 'services', portRange: '443,1024-65535' }); toast(`Группа ${name.trim()} создана`); setName(''); onSaved(); }); }}>
      <input className="inp" style={{ width: 200 }} value={name} onChange={(e) => setName(e.target.value)} placeholder="имя новой группы" maxLength={32} aria-label="Имя новой группы" />
      <button className="btn sm" disabled={busy || !name.trim()}>Создать группу</button>
      <Info>После создания раскройте группу, настройте политику и перенесите серверы в группу в их карточках (вкладка «Доступ»).</Info>
      <ErrorBox error={error} />
    </form>
  );
}

const PEER: Record<string, string> = { services: 'сервисные порты', chain: 'только цепочка', all: 'все порты', none: 'нет' };

/** Группа — строка-сводка; раскрывается в горизонтальную форму политики. */
function GroupRow({ g, servers, onSaved }: { g: Conn['groups'][number]; servers: Conn['servers']; onSaved: () => void }) {
  const [v, setV] = useState({ stealth: g.stealth, peerScope: g.peer_scope, portRange: g.port_range });
  const { busy, error, run } = useAsync();
  const dirty = v.stealth !== g.stealth || v.peerScope !== g.peer_scope || v.portRange !== g.port_range;
  return (
    <details className="grp" open={dirty || undefined}>
      <summary className="grp-sum">
        <b className="grp-name">{g.name}</b>
        <span className="grp-cell"><span className="k">Скрытность</span><span className="small">{STEALTH[g.stealth] ?? g.stealth}</span></span>
        <span className="grp-cell"><span className="k">Связность нод</span><span className="small">{PEER[g.peer_scope] ?? g.peer_scope}</span></span>
        <span className="grp-cell"><span className="k">Порты</span><span className="small mono">{g.port_range}</span></span>
        <span className="grp-cell grp-servers">{servers.length ? servers.map((x) => <a key={x.id} className="tag" href={`#/server/${x.id}`} onClick={(e) => e.stopPropagation()}>{x.name}</a>) : <span className="k">нет серверов</span>}</span>
        {dirty && <Tag kind="warn">не сохранено</Tag>}
        <span className="grp-chev" aria-hidden="true">▾</span>
      </summary>
      <div className="grp-body">
        <label className="fld">Скрытность<select className="inp" value={v.stealth} onChange={(e) => setV({ ...v, stealth: e.target.value })}>{Object.entries(STEALTH).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        <label className="fld">Связность нод<select className="inp" value={v.peerScope} onChange={(e) => setV({ ...v, peerScope: e.target.value })}>{Object.entries(PEER).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        <label className="fld grp-range">Разрешённый диапазон портов<input className="inp mono" value={v.portRange} onChange={(e) => setV({ ...v, portRange: e.target.value })} /></label>
        <span className="flex grp-acts">
          <button className="btn sm pri" disabled={busy || !dirty} onClick={() => void run(async () => { await api.put('/api/v1/groups', { name: g.name, ...v }); toast(`Политика группы ${g.name} сохранена`); onSaved(); })}>Сохранить</button>
          {dirty && <button type="button" className="btn ghost sm" onClick={() => setV({ stealth: g.stealth, peerScope: g.peer_scope, portRange: g.port_range })}>Отменить</button>}
          {!servers.length && g.name !== 'default' && <button type="button" className="btn ghost sm" style={{ color: 'var(--fail)' }} disabled={busy} onClick={() => void run(async () => { await api.del(`/api/v1/groups/${encodeURIComponent(g.name)}`); toast(`Группа ${g.name} удалена`); onSaved(); })}>Удалить группу</button>}
        </span>
        <ErrorBox error={error} />
      </div>
    </details>
  );
}
