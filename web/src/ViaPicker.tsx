import { useEffect, useState } from 'react';
import { api } from './api';
import { Info, Seg } from './ui';

/** Как панель доходит до сервера: напрямую или через прокси (конфигурация флота или своя ссылка). */
export type Via = ({ kind: 'direct' } | { kind: 'fleet'; serverId: string; templateId: string } | { kind: 'link'; link: string }) & { keep?: boolean };
interface Opt { serverId: string; serverName: string; templateId: string; templateName: string; protocol: string }

/** Прокси без служебных полей — для API. */
export const viaOnly = (v: Via) => (v.kind === 'fleet' ? { kind: v.kind, serverId: v.serverId, templateId: v.templateId } : v.kind === 'link' ? { kind: v.kind, link: v.link } : null);
/** Для запроса подключения: «напрямую» не передаётся вовсе; keep — и дальше вести туннель через этот прокси. */
export const viaBody = (v: Via) => (v.kind === 'direct' ? {} : { via: viaOnly(v), ...(v.keep ? { keepVia: true } : {}) });
export const viaReady = (v: Via) => v.kind === 'direct' || (v.kind === 'fleet' ? !!v.serverId : v.link.trim().length > 10);

/**
 * Прокси до сервера. mode='boot' — первичный доступ (с галочкой «и дальше управлять через этот прокси»);
 * mode='tunnel' — постоянный прокси туннеля управления («напрямую» = без прокси).
 */
export function ViaPicker({ value, onChange, exclude, mgmtMode, mode = 'boot' }: { value: Via; onChange: (v: Via) => void; exclude?: string; mgmtMode: string; mode?: 'boot' | 'tunnel' }) {
  const [opts, setOpts] = useState<Opt[] | null>(null);
  useEffect(() => { api.get<Opt[]>('/api/v1/servers/proxy-options').then(setOpts).catch(() => setOpts([])); }, []);
  const list = (opts ?? []).filter((o) => o.serverId !== exclude);
  const key = value.kind === 'fleet' ? `${value.serverId}|${value.templateId}` : '';
  const keep = value.keep ?? true;
  return (
    <div className="stack" style={{ gap: 8 }}>
      {mode === 'boot'
        ? <span className="k">Первичный доступ <Info>Как панель один раз зайдёт на сервер, чтобы его настроить. Если главный сервер в РФ и SSH до сервера за границей режется — выберите конфигурацию панели (например, выход за границей) или свою ссылку: панель зайдёт на SSH сервера через этот VLESS-прокси.</Info></span>
        : <span className="k">Туннель управления <Info>Если сервер недоступен из РФ целиком (не только по SSH), туннель панели до него идёт цепочкой через прокси за границей: панель → прокси → туннель сервера.</Info></span>}
      <Seg value={value.kind} label={mode === 'boot' ? 'Первичный доступ' : 'Туннель управления'} onChange={(k) => onChange(k === 'direct' ? { kind: 'direct' } : k === 'fleet' ? { kind: 'fleet', serverId: list[0]?.serverId ?? '', templateId: list[0]?.templateId ?? '', keep } : { kind: 'link', link: '', keep })}
        options={[['direct', mode === 'boot' ? 'напрямую' : 'без прокси'], ['fleet', 'через конфигурацию панели'], ['link', 'через свою ссылку']]} />
      {value.kind === 'fleet' && (list.length ? (
        <select className="inp" value={key} onChange={(e) => { const [serverId, templateId] = e.target.value.split('|'); onChange({ kind: 'fleet', serverId: serverId!, templateId: templateId!, keep }); }} aria-label="Конфигурация для доступа">
          {list.map((o) => <option key={`${o.serverId}|${o.templateId}`} value={`${o.serverId}|${o.templateId}`}>{o.serverName} · {o.templateName} ({o.protocol})</option>)}
        </select>
      ) : <span className="small muted">Во флоте пока нет выкаченных конфигураций Xray на других серверах — вставьте свою ссылку.</span>)}
      {value.kind === 'link' && (
        <textarea className="inp mono" rows={3} value={value.link} onChange={(e) => onChange({ kind: 'link', link: e.target.value, keep })} spellCheck={false}
          placeholder="vless://uuid@203.0.113.5:443?type=tcp&security=reality&pbk=…&sni=…#имя  (также trojan://, vmess://, ss:// или JSON outbound)" aria-label="Ссылка прокси" />
      )}
      {value.kind !== 'direct' && mode === 'boot' && mgmtMode === 'tunnel' && (
        <label className="cb small"><input type="checkbox" checked={keep} onChange={(e) => onChange({ ...value, keep: e.target.checked })} />и дальше вести туннель управления через этот прокси — если сервер недоступен из РФ целиком</label>
      )}
      {value.kind !== 'direct' && <span className="small muted">{mode === 'boot' ? 'Прокси должен быть за пределами РФ. Ссылка хранится зашифрованной, только если выбрано «и дальше вести туннель», иначе используется лишь на время подключения.' : 'Прокси должен быть за пределами РФ. Ссылка хранится зашифрованной.'}{mode === 'boot' && mgmtMode !== 'tunnel' ? ' Канал «напрямую по SSH» после настройки тоже должен проходить — иначе выберите канал «через туннель».' : ''}</span>}
    </div>
  );
}
