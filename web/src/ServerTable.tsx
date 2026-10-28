import { useState } from 'react';
import { api, ago, can, paidLeftText, type Server } from './api';
import { Addr, Icon, Info, Level, RoleTag, StageHelp, StagePip, Tag, ask, toast } from './ui';
import { HostStatsPanel } from './HostStats';

/**
 * Таблица серверов (раздел «Серверы» и обзор): клик по строке — карточка сервера; справа — быстрые действия
 * (перезапуск ядер, перезагрузка) и стрелка, раскрывающая живую статистику под строкой.
 */
export function ServerTable({ servers, empty, onChanged }: { servers: Server[]; empty?: string; onChanged?: () => void }) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const toggle = (id: string) => setOpen((o) => { const n = new Set(o); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const act = async (s: Server, what: 'cores' | 'host') => {
    const main = s.mgmt_mode === 'local';
    const q = what === 'cores'
      ? `Перезапустить работающие ядра на ${s.name}? Подключения пользователей этого сервера оборвутся на пару секунд и восстановятся сами.`
      : main
        ? `Перезагрузить главный сервер ${s.name}? На нём работает панель: она будет недоступна 1–3 минуты, пользователи этого сервера потеряют связь до окончания загрузки.`
        : `Перезагрузить сервер ${s.name}? Он будет недоступен 1–3 минуты, его пользователи потеряют связь до окончания загрузки.`;
    if (!(await ask(q))) return;
    setBusy(`${s.id}:${what}`);
    try {
      const r = await api.post<{ output: string }>(`/api/v1/servers/${s.id}/restart`, { what });
      toast(what === 'host' ? `${s.name} перезагружается — вернётся через 1–3 минуты` : `${s.name}: ${r.output}`);
      onChanged?.();
    } catch (e) { toast(`${s.name}: ${(e as Error).message}`, 'fail'); }
    setBusy(null);
  };
  return (
    <div className="table-wrap">
      <table className="srv-table">
        <thead><tr><th>Сервер</th><th>Роль</th><th>Этап <Info label="Что значат этапы"><StageHelp /></Info></th><th>Защита</th><th>Связь</th><th aria-label="Действия" /></tr></thead>
        <tbody>
          {servers.map((s) => {
            const managed = s.sudo_mode === 'restricted';
            const isOpen = open.has(s.id);
            return [
              <tr key={s.id} className={`clickable ${isOpen ? 'open' : ''}`} onClick={() => (location.hash = `#/server/${s.id}`)}>
                <td><a href={`#/server/${s.id}`} style={{ color: 'var(--text)', fontWeight: 600 }}>{s.name}</a>{s.paidDaysLeft !== null && s.paidDaysLeft <= s.paid_warn_days && <> <Tag kind={s.paidDaysLeft <= 1 ? 'fail' : 'warn'}>{`оплата: ${paidLeftText(s.paidDaysLeft)}`}</Tag></>}<div className="k"><Addr value={s.host} /></div></td>
                <td><RoleTag s={s} /></td>
                <td><StagePip stage={s.stage} /></td>
                <td><Level value={s.protection_current} /></td>
                <td>{s.fail_since ? <Tag kind="fail" dot>нет связи</Tag> : <Tag kind={s.last_seen_at ? 'ok' : undefined} dot>{ago(s.last_seen_at)}</Tag>}</td>
                <td className="srv-acts" onClick={(e) => e.stopPropagation()}>
                  {managed && can('servers.manage') && <>
                    <button type="button" className="btn ghost icon sm-icon" title="Перезапустить ядра" aria-label={`Перезапустить ядра ${s.name}`} disabled={!!busy} onClick={() => void act(s, 'cores')}>{busy === `${s.id}:cores` ? <span className="spin" /> : Icon.restart}</button>
                    <button type="button" className="btn ghost icon sm-icon" title="Перезагрузить сервер" aria-label={`Перезагрузить ${s.name}`} disabled={!!busy} onClick={() => void act(s, 'host')}>{busy === `${s.id}:host` ? <span className="spin" /> : Icon.power}</button>
                  </>}
                  <button type="button" className="xbtn" aria-expanded={isOpen} aria-label={`Статистика ${s.name}`} title="Нагрузка вживую" disabled={!managed} onClick={() => toggle(s.id)}>{Icon.down}</button>
                </td>
              </tr>,
              isOpen && <tr key={`${s.id}-x`} className="srv-x"><td colSpan={6}><HostStatsPanel url={`/api/v1/servers/${s.id}/stats`} pollMs={s.mgmt_mode === 'local' ? 3000 : 5000} /></td></tr>,
            ];
          })}
          {!servers.length && <tr><td colSpan={6} className="empty">{empty ?? 'Серверов пока нет'}</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
