import type { ReactNode } from 'react';
import { Icon } from './ui';

/**
 * Схема маршрута: вход слева, выходы справа, линия к каждому выходу. Одна и та же схема — на обзоре (только
 * показывает) и в редакторе конфигурации (выходы включаются кликом, порядок — стрелками).
 */
export type ExitState = 'lead' | 'ok' | 'fail' | 'idle' | 'off';

export interface MapExit {
  id: string;
  name: string;
  state: ExitState;
  /** короткая подпись справа: «ведёт трафик», «в резерве», «4 ч без связи» */
  note?: string;
  /** замер: «48 мс · 212 Мбит/с» */
  metric?: string;
  href?: string;
}

const ROW = 48;
const GAP = 8;

export function RouteMap({ entry, entryOff, exits, ordered, onToggle, onMove, empty }: {
  entry: ReactNode;
  /** входа нет — пользователи подключаются напрямую: рамка пунктиром */
  entryOff?: boolean;
  exits: MapExit[];
  /** показывать номера и стрелки порядка у включённых выходов */
  ordered?: boolean;
  onToggle?: (id: string) => void;
  onMove?: (id: string, dir: -1 | 1) => void;
  empty?: ReactNode;
}) {
  const on = exits.filter((x) => x.state !== 'off');
  const h = Math.max(1, exits.length) * ROW + Math.max(0, exits.length - 1) * GAP;
  const mid = h / 2;
  const y = (i: number) => i * (ROW + GAP) + ROW / 2;
  return (
    <div className="rmap-wrap"><div className="rmap" style={{ ['--rm-h' as string]: `${h}px` }}>
      <div className={`rm-entry ${entryOff ? 'none' : ''}`}>{entry}</div>
      <svg className="rm-lines" viewBox={`0 0 100 ${h}`} preserveAspectRatio="none" aria-hidden="true">
        {exits.map((x, i) => x.state === 'off' ? null : (
          <path key={x.id} className={`rm-line ${x.state}`} vectorEffect="non-scaling-stroke"
            d={`M0 ${mid} C 55 ${mid}, 45 ${y(i)}, 100 ${y(i)}`} />
        ))}
      </svg>
      <ol className="rm-exits" aria-label="Выходы">
        {exits.map((x) => {
          const n = on.indexOf(x);
          const body = (
            <>
              {ordered && x.state !== 'off' ? <span className="rm-n">{n + 1}</span> : null}
              <span className="rm-name">{x.name}</span>
              {x.metric && <span className="rm-metric">{x.metric}</span>}
              {x.note && <span className="rm-note">{x.note}</span>}
            </>
          );
          return (
            <li key={x.id} className={`rm-exit ${x.state}`}>
              {onToggle ? (
                <label className="rm-pick">
                  <input type="checkbox" checked={x.state !== 'off'} onChange={() => onToggle(x.id)} />
                  {body}
                </label>
              ) : x.href ? <a className="rm-pick" href={x.href}>{body}</a> : <span className="rm-pick">{body}</span>}
              {ordered && onMove && x.state !== 'off' && (
                <span className="rm-ord">
                  <button type="button" className="btn ghost icon" disabled={n === 0} onClick={() => onMove(x.id, -1)} aria-label={`${x.name} выше`}>{Icon.up}</button>
                  <button type="button" className="btn ghost icon" disabled={n === on.length - 1} onClick={() => onMove(x.id, 1)} aria-label={`${x.name} ниже`}>{Icon.down}</button>
                </span>
              )}
            </li>
          );
        })}
        {!exits.length && <li className="rm-empty">{empty}</li>}
      </ol>
    </div></div>
  );
}

/** Подписи выхода по замерам «Авто»: что сейчас с ним и цифры. */
export function exitView(h: { rtt_ms: number | null; mbps: number | null; ok: number; error: string | null } | null | undefined, opts: { lead: boolean; failSince?: string | null; mode?: string; ago?: (iso: string) => string }): Pick<MapExit, 'state' | 'note' | 'metric'> {
  const metric = h && (h.rtt_ms !== null || h.mbps !== null) ? `${h.rtt_ms ?? '—'} мс · ${h.mbps ?? '—'} Мбит/с` : undefined;
  if (opts.failSince) return { state: 'fail', note: opts.ago ? `нет связи · ${opts.ago(opts.failSince)}` : 'нет связи', metric };
  if (h && !h.ok) return { state: 'fail', note: h.error ?? 'ниже порога', metric };
  if (opts.lead) return { state: 'lead', note: 'ведёт трафик', metric };
  return { state: 'ok', note: opts.mode === 'random' ? 'в пуле' : 'в резерве', metric };
}
