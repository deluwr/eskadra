import { useEffect, useState } from 'react';
import { api } from './api';
import { Info, Seg } from './ui';

/** Как панель заходит на SSH нового сервера при первичной настройке. */
export type Via = { kind: 'direct' } | { kind: 'fleet'; serverId: string; templateId: string } | { kind: 'link'; link: string };
interface Opt { serverId: string; serverName: string; templateId: string; templateName: string; protocol: string }

/** Для запроса: «напрямую» не передаётся вовсе. */
export const viaBody = (v: Via) => (v.kind === 'direct' ? {} : { via: v });
export const viaReady = (v: Via) => v.kind === 'direct' || (v.kind === 'fleet' ? !!v.serverId : v.link.trim().length > 10);

/**
 * Первичный доступ: напрямую или через прокси — конфигурацию, уже работающую во флоте, либо свою ссылку.
 * Нужен, когда главный сервер в РФ и SSH до сервера за границей режется.
 */
export function ViaPicker({ value, onChange, exclude, mgmtMode }: { value: Via; onChange: (v: Via) => void; exclude?: string; mgmtMode: string }) {
  const [opts, setOpts] = useState<Opt[] | null>(null);
  useEffect(() => { api.get<Opt[]>('/api/v1/servers/proxy-options').then(setOpts).catch(() => setOpts([])); }, []);
  const list = (opts ?? []).filter((o) => o.serverId !== exclude);
  const key = value.kind === 'fleet' ? `${value.serverId}|${value.templateId}` : '';
  return (
    <div className="stack" style={{ gap: 8 }}>
      <span className="k">Первичный доступ <Info>Как панель один раз зайдёт на сервер, чтобы его настроить. Если главный сервер в РФ и SSH до сервера за границей режется — выберите конфигурацию панели (например, выход за границей) или свою ссылку: панель зайдёт на SSH сервера через этот VLESS-прокси, а дальше будет работать по своему туннелю.</Info></span>
      <Seg value={value.kind} label="Первичный доступ" onChange={(k) => onChange(k === 'direct' ? { kind: 'direct' } : k === 'fleet' ? { kind: 'fleet', serverId: list[0]?.serverId ?? '', templateId: list[0]?.templateId ?? '' } : { kind: 'link', link: '' })}
        options={[['direct', 'напрямую'], ['fleet', 'через конфигурацию панели'], ['link', 'через свою ссылку']]} />
      {value.kind === 'fleet' && (list.length ? (
        <select className="inp" value={key} onChange={(e) => { const [serverId, templateId] = e.target.value.split('|'); onChange({ kind: 'fleet', serverId: serverId!, templateId: templateId! }); }} aria-label="Конфигурация для доступа">
          {list.map((o) => <option key={`${o.serverId}|${o.templateId}`} value={`${o.serverId}|${o.templateId}`}>{o.serverName} · {o.templateName} ({o.protocol})</option>)}
        </select>
      ) : <span className="small muted">Во флоте пока нет выкаченных конфигураций Xray на других серверах — вставьте свою ссылку.</span>)}
      {value.kind === 'link' && (
        <textarea className="inp mono" rows={3} value={value.link} onChange={(e) => onChange({ kind: 'link', link: e.target.value })} spellCheck={false}
          placeholder="vless://uuid@203.0.113.5:443?type=tcp&security=reality&pbk=…&sni=…#имя  (также trojan://, vmess://, ss:// или JSON outbound)" aria-label="Ссылка прокси" />
      )}
      {value.kind !== 'direct' && <span className="small muted">Прокси должен быть за пределами РФ. Ссылка используется только на время подключения и не сохраняется.{mgmtMode !== 'tunnel' ? ' Канал «напрямую по SSH» после настройки тоже должен проходить — иначе выберите канал «через туннель».' : ''}</span>}
    </div>
  );
}
