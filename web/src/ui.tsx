import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import qrcode from 'qrcode-generator';
import { api, can } from './api';

export function useAsync() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

/** Перезагрузка данных с периодическим опросом (для задач и статусов). */
export function usePoll<T>(load: () => Promise<T>, ms: number | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef(load);
  ref.current = load;
  const reload = useCallback(async () => {
    try { setData(await ref.current()); setError(null); } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => {
    void reload();
    if (!ms) return;
    const t = setInterval(() => void reload(), ms);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, ms, ...deps]);
  return { data, error, reload, setData };
}

/**
 * Подтверждение внутри панели вместо window.confirm: встроенные браузеры (например, в приложении Claude)
 * системные окна не показывают, и confirm() молча возвращает «нет».
 */
let confirmProvider: ((text: string) => Promise<boolean>) | null = null;
export const setConfirmProvider = (p: (text: string) => Promise<boolean>) => { confirmProvider = p; };
export const ask = (text: string): Promise<boolean> => (confirmProvider ? confirmProvider(text) : Promise.resolve(window.confirm(text)));

export function ErrorBox({ error }: { error: string | null | undefined }) {
  return error ? <div className="alert fail" role="alert">{error}</div> : null;
}

export function Tag({ kind, dot, children }: { kind?: 'ok' | 'warn' | 'fail' | 'info' | 'acc'; dot?: boolean; children: ReactNode }) {
  return <span className={`tag ${kind ?? ''}`}>{dot && <span className="dot" />}{children}</span>;
}

export function Switch({ on, onChange, label, disabled }: { on: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return <button type="button" className={on ? 'sw on' : 'sw'} aria-pressed={on} aria-label={label} disabled={disabled} onClick={() => onChange(!on)} />;
}

export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: Array<[T, string]>; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([v, l]) => <button type="button" key={v} className={v === value ? 'on' : ''} aria-pressed={v === value} onClick={() => onChange(v)}>{l}</button>)}
    </div>
  );
}

/**
 * Скопировать текст: буфер обмена браузера, а если он недоступен (панель открыта по http, браузер отказал) —
 * через скрытое поле. false — не получилось ни так, ни так.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    // запрос к буферу может зависнуть в ожидании разрешения — больше секунды не ждём
    if (navigator.clipboard && window.isSecureContext) {
      const ok = await Promise.race([navigator.clipboard.writeText(text).then(() => true), new Promise<false>((r) => setTimeout(() => r(false), 1000))]);
      if (ok) return true;
    }
  } catch { /* ниже — запасной способ */ }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.select();
  try { return document.execCommand('copy'); } catch { return false; } finally { ta.remove(); }
}

/** Кнопка копирования: type="button" — внутри формы она не отправляет форму. */
function useCopy(text: string) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    if (await copyText(text)) { setCopied(true); setTimeout(() => setCopied(false), 1500); }
    else toast('Не удалось скопировать — выделите текст и нажмите Ctrl+C', 'fail');
  };
  return { copied, copy };
}

export function CopyBlock({ text }: { text: string }) {
  const { copied, copy } = useCopy(text);
  return (
    <div className="copy">
      <button type="button" className="btn sm" onClick={() => void copy()}>{copied ? 'Скопировано' : 'Копировать'}</button>
      <pre className="code">{text}</pre>
    </div>
  );
}

export function CopyButton({ text, label = 'Копировать' }: { text: string; label?: string }) {
  const { copied, copy } = useCopy(text);
  return <button type="button" className="btn sm" onClick={() => void copy()}>{copied ? 'Скопировано' : label}</button>;
}

const P = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };

export const Icon = {
  logo: (s = 24) => (
    <svg width={s} height={s} viewBox="0 0 24 24" {...P} strokeWidth={1.7} aria-hidden="true"><path d="M3.5 16.5h17l-2.4 4.2H5.9z" /><path d="M12 2.8v13.7" /><path d="M12 4.6l6.8 9.4H12" /><path d="M12 6.9L6.4 14H12" /><path d="M12 2.8l3 1.3-3 1.3" /></svg>
  ),
  overview: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></svg>,
  servers: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></svg>,
  configs: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /></svg>,
  users: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5" /><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18.5 14.8c1.6.8 2.6 2.5 3 5.2" /></svg>,
  ports: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M12 3l8 3v6c0 4.6-3.3 8.2-8 9-4.7-.8-8-4.4-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" /></svg>,
  access: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M16 7l3 3M14 9l2 2" /></svg>,
  backups: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><rect x="3" y="4" width="18" height="5" rx="1.5" /><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9M10 13h4" /></svg>,
  audit: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" /></svg>,
  settings: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>,
  sun: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>,
  cores: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" /></svg>,
  help: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01" /></svg>,
  eye: <svg width="14" height="14" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>,
  eyeOff: <svg width="14" height="14" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M3 3l18 18M10.6 5.1A10.4 10.4 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7c1.8 0 3.4-.5 4.8-1.3M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>,
  restart: <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" /></svg>,
  power: <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0" /></svg>,
  up: <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M6 15l6-6 6 6" /></svg>,
  down: <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M6 9l6 6 6-6" /></svg>,
  moon: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" /></svg>,
};

export const STAGES = ['не подключён', 'подключён', 'настроен', 'проверен', 'защищён'];
/** Что значат четыре полоски этапа: зелёная — пройден, оранжевая — следующий шаг, серая — ещё впереди. */
const STAGE_STEPS: Array<[string, string]> = [
  ['подключён', 'панель входит на сервер своим ключом'],
  ['настроен', 'служебные скрипты и ядра установлены'],
  ['проверен', 'чек-лист защиты пройден'],
  ['защищён', 'блокировки firewall включены'],
];
/** Что значат четыре полоски этапа — для подсказки (i). */
export function StageHelp() {
  return (
    <span className="stage-help">
      {STAGE_STEPS.map(([name, text], i) => (
        <span key={name} className="sh-row"><StagePipBar stage={i + 1} /><b>{name}</b><span>{text}</span></span>
      ))}
      <span className="sh-legend"><i className="d" /> пройден <i className="c" /> следующий шаг <i /> впереди</span>
      <span className="k">Для обычной защиты достаточно этапа «настроен».</span>
    </span>
  );
}
function StagePipBar({ stage }: { stage: number }) {
  return <span className="pip" aria-hidden="true">{[1, 2, 3, 4].map((i) => <i key={i} className={i <= stage ? 'd' : i === stage + 1 ? 'c' : ''} />)}</span>;
}

/** Подсказка (i): текст по наведению, фокусу или нажатию — вместо абзацев пояснений в интерфейсе. */
/**
 * Подсказка (i): окно поверх страницы (портал, position: fixed), поэтому таблицы и карточки с прокруткой
 * его не обрезают и не растягиваются. Открывается наведением или нажатием, закрывается уходом, Esc, прокруткой.
 */
export function Info({ children, label = 'Подсказка' }: { children: ReactNode; label?: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ x: number; y: number; up: boolean } | null>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const pop = useRef<HTMLSpanElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const show = () => {
    if (timer.current) clearTimeout(timer.current);
    const r = btn.current?.getBoundingClientRect();
    if (!r) return;
    const up = innerHeight - r.bottom < 260 && r.top > innerHeight - r.bottom;
    setPos({ x: r.left + r.width / 2, y: up ? r.top - 8 : r.bottom + 8, up });
    setOpen(true);
  };
  const hide = (delay = 120) => { if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(() => setOpen(false), delay); };
  // не выходить за края окна
  useLayoutEffect(() => {
    const el = pop.current;
    if (!open || !el || !pos) return;
    const w = el.offsetWidth;
    el.style.left = `${Math.min(Math.max(pos.x - w / 2, 12), innerWidth - w - 12)}px`;
  }, [open, pos]);
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    const key = (e: KeyboardEvent) => e.key === 'Escape' && close();
    addEventListener('scroll', close, true); addEventListener('resize', close); addEventListener('keydown', key);
    return () => { removeEventListener('scroll', close, true); removeEventListener('resize', close); removeEventListener('keydown', key); };
  }, [open]);
  return (
    <span className="info" onMouseEnter={show} onMouseLeave={() => hide()}>
      <button ref={btn} type="button" className="info-i" aria-label={label} aria-expanded={open}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); if (open) setOpen(false); else show(); }} onBlur={() => hide(200)}>i</button>
      {open && pos && createPortal(
        <span ref={pop} className="info-float" role="tooltip" style={{ top: pos.y, ...(pos.up ? { transform: 'translateY(-100%)' } : {}) }}
          onMouseEnter={() => { if (timer.current) clearTimeout(timer.current); }} onMouseLeave={() => hide()} onClick={(e) => e.stopPropagation()}>{children}</span>,
        document.body,
      )}
    </span>
  );
}

/** Роли узлов по-человечески. relay/control — старые значения, показываются как вход/главный. */
export const ROLE_LABEL: Record<string, string> = { entry: 'Relay', relay: 'Relay', exit: 'Выход', control: 'Исполнитель (главный)' };
/** Роль сервера одним названием: главный сервер (панель на нём же) — «Исполнитель (главный)», вход — Relay, выход — «Выход». */
export const roleLabel = (s: { role: string; mgmt_mode?: string }) => (s.mgmt_mode === 'local' ? ROLE_LABEL.control! : ROLE_LABEL[s.role] ?? s.role);
/** Роль и, отдельно, канал управления через туннель. */
export function RoleTag({ s }: { s: { role: string; mgmt_mode?: string } }) {
  return <span className="flex" style={{ gap: 6 }}>{roleLabel(s)}{s.mgmt_mode === 'tunnel' && <span className="tag info" title="Панель управляет сервером через служебный туннель VLESS-REALITY">туннель</span>}</span>;
}

/** Уровни защиты хоста одним словом. */
export const LEVEL_LABEL: Record<string, string> = { P1: 'обычная', P2: 'средняя', P3: 'высокая' };
export function Level({ value }: { value: string }) {
  return <Tag kind={value === 'P3' ? 'ok' : value === 'P2' ? 'info' : undefined}>{LEVEL_LABEL[value] ?? value}</Tag>;
}

export function StagePip({ stage }: { stage: number }) {
  return (
    <div>
      <div className="pip" role="img" aria-label={`этап ${stage} из 4`}>
        {[1, 2, 3, 4].map((i) => <i key={i} className={i <= stage ? 'd' : i === stage + 1 ? 'c' : ''} />)}
      </div>
      <div className="k">{STAGES[stage]}</div>
    </div>
  );
}

/** QR-код как SVG (масштабируется без размытия). */
export function Qr({ text, size = 260 }: { text: string; size?: number }) {
  const qr = qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  const svg = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
  return <div className="qr" style={{ width: size, height: size }} role="img" aria-label="QR-код" dangerouslySetInnerHTML={{ __html: svg }} />;
}

/** Кнопка «QR»: окно с кодом для сканирования телефоном и копированием. */
export function QrButton({ text, title, label = 'QR' }: { text: string; title: string; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="btn sm" onClick={() => setOpen(true)}>{label}</button>
      {open && (
        <Modal title={title} onClose={() => setOpen(false)}>
          <div className="stack" style={{ alignItems: 'center' }}>
            <Qr text={text} />
            <span className="k mono" style={{ wordBreak: 'break-all', maxWidth: 360 }}>{text.length > 140 ? text.slice(0, 140) + '…' : text}</span>
            <div className="flex"><CopyButton text={text} /><button className="btn ghost sm" onClick={() => setOpen(false)}>Закрыть</button></div>
          </div>
        </Modal>
      )}
    </>
  );
}

/**
 * Окно поверх страницы. size: sm — подтверждения, md — формы, lg/xl — карточки (пользователь, подбор SNI).
 * Высота ограничена экраном: шапка остаётся на месте, содержимое прокручивается внутри и не обрезается.
 */
export function Modal({ title, children, onClose, size = 'sm', head }: { title: string; children: ReactNode; onClose: () => void; size?: 'sm' | 'md' | 'lg' | 'xl'; head?: ReactNode }) {
  const bg = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // Escape закрывает только верхнее окно (например, подтверждение поверх карточки пользователя)
    const onKey = (e: KeyboardEvent) => {
      const all = document.querySelectorAll('.modal-bg');
      if (e.key === 'Escape' && all[all.length - 1] === bg.current) onClose();
    };
    addEventListener('keydown', onKey);
    return () => removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div ref={bg} className="modal-bg" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`card modal modal-${size}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head"><h2>{title}</h2>{head}<button type="button" className="btn ghost sm modal-x" aria-label="Закрыть" onClick={onClose}>✕</button></div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

// ───── уведомления о результате действия («Сохранено») ─────

type ToastKind = 'ok' | 'fail' | 'info';
let toastSink: ((text: string, kind: ToastKind) => void) | null = null;
/** Короткое уведомление внизу экрана: подтверждает, что действие выполнено (сохранено, привязано, удалено). */
export const toast = (text: string, kind: ToastKind = 'ok') => toastSink?.(text, kind);

export function Toasts() {
  const [items, setItems] = useState<Array<{ id: number; text: string; kind: ToastKind }>>([]);
  useEffect(() => {
    let n = 0;
    toastSink = (text, kind) => {
      const id = ++n;
      setItems((xs) => [...xs.slice(-2), { id, text, kind }]);
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), kind === 'fail' ? 6000 : 3000);
    };
    return () => { toastSink = null; };
  }, []);
  return (
    <div className="toasts" role="status" aria-live="polite">
      {items.map((t) => <div key={t.id} className={`toast ${t.kind}`}><span className="dot" />{t.text}</div>)}
    </div>
  );
}

// ───── привязка Telegram ─────

/**
 * Telegram администратора или пользователя: привязка одноразовой ссылкой на бота (человек нажимает «Старт» —
 * панель видит это сразу) или вводом ID вручную. Сохранение — явной кнопкой, результат — уведомлением.
 */
export function TgBind({ tgId, linkUrl, onSaveId, onChanged, canEdit = true }: {
  tgId: string | null; linkUrl: string; onSaveId: (id: string | null) => Promise<unknown>; onChanged: () => void; canEdit?: boolean;
}) {
  const [open, setOpen] = useState(false);
  if (!canEdit) return tgId ? <Tag kind="ok">привязан</Tag> : <span className="k">не привязан</span>;
  return (
    <>
      {tgId ? (
        <span className="flex" style={{ gap: 6, flexWrap: 'nowrap' }}>
          <Tag kind="ok" dot>привязан</Tag>
          <button className="btn ghost sm" onClick={() => setOpen(true)}>Изменить</button>
        </span>
      ) : <button className="btn sm" onClick={() => setOpen(true)}>Привязать</button>}
      {open && <TgBindModal tgId={tgId} linkUrl={linkUrl} onSaveId={onSaveId} onClose={() => setOpen(false)} onChanged={onChanged} />}
    </>
  );
}

function TgBindModal({ tgId, linkUrl, onSaveId, onClose, onChanged }: { tgId: string | null; linkUrl: string; onSaveId: (id: string | null) => Promise<unknown>; onClose: () => void; onChanged: () => void }) {
  const [link, setLink] = useState<{ code: string; url: string } | null>(null);
  const [manual, setManual] = useState(tgId ?? '');
  const { busy, error, run } = useAsync();
  const done = (msg: string) => { toast(msg); onChanged(); onClose(); };
  // ждём, пока человек откроет ссылку и нажмёт «Старт»
  useEffect(() => {
    if (!link) return;
    const t = setInterval(() => {
      void api.get<{ state: string }>(`/api/v1/tg-link/${link.code}`).then((r) => {
        if (r.state === 'bound') done('Telegram привязан');
        else if (r.state === 'expired') setLink(null);
      }).catch(() => undefined);
    }, 2000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link?.code]);
  return (
    <Modal title="Telegram" onClose={onClose}>
      {!link ? (
        <div className="stack">
          <p className="small">Ссылка откроет бота. После нажатия «Старт» Telegram привяжется сам — панель увидит это сразу.</p>
          <div><button className="btn pri" disabled={busy} onClick={() => void run(async () => { setLink(await api.post(linkUrl)); })}>Получить ссылку</button></div>
        </div>
      ) : (
        <div className="stack" style={{ alignItems: 'center' }}>
          <Qr text={link.url} size={200} />
          <div className="flex"><a className="btn pri" href={link.url} target="_blank" rel="noreferrer">Открыть в Telegram</a><CopyButton text={link.url} label="Копировать ссылку" /></div>
          <span className="k flex" style={{ gap: 8 }}><span className="spin" aria-hidden="true" />Ждём нажатия «Старт» в боте · ссылка действует 15 минут</span>
        </div>
      )}
      <details className="more" open={!!error || undefined}>
        <summary>Ввести Telegram ID вручную</summary>
        <form className="flex" style={{ marginTop: 10 }} onSubmit={(e) => { e.preventDefault(); void run(async () => { await onSaveId(manual.trim() || null); done(manual.trim() ? 'Telegram ID сохранён' : 'Telegram отвязан'); }); }}>
          <input className="inp mono" style={{ flex: 1, minWidth: 140 }} inputMode="numeric" value={manual} onChange={(e) => setManual(e.target.value.replace(/\D/g, ''))} placeholder="ID — бот присылает его на /start" aria-label="Telegram ID" />
          <button className="btn" disabled={busy || manual === (tgId ?? '')}>Сохранить</button>
        </form>
      </details>
      <ErrorBox error={error} />
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        {tgId ? <button className="btn ghost sm" style={{ color: 'var(--fail)' }} disabled={busy} onClick={() => void run(async () => { await onSaveId(null); done('Telegram отвязан'); })}>Отвязать</button> : <span />}
        <button className="btn ghost" onClick={onClose}>Закрыть</button>
      </div>
    </Modal>
  );
}

// ───── адреса серверов размыты, пока их не открыть (скриншоты, демонстрация экрана) ─────

/** IP или домен: по умолчанию размыт; кнопка-глаз рядом показывает и снова прячет. */
export function Addr({ value, empty = '—', mono = true }: { value: string | null | undefined; empty?: string; mono?: boolean }) {
  const [shown, setShown] = useState(false);
  if (!value) return <span className="k">{empty}</span>;
  // без права «видеть IP» адреса людей сервер не отдаёт вовсе, адреса серверов интерфейс не показывает
  if (!can('ips.view') || value === 'скрыт') return <span className="k" title="Адрес скрыт: у роли нет права видеть IP-адреса">скрыт</span>;
  return (
    <span className="addr">
      <span className={`${mono ? 'mono ' : ''}addr-v ${shown ? '' : 'blur'}`} aria-hidden={!shown}>{value}</span>
      <button type="button" className="addr-eye" aria-label={shown ? 'Скрыть адрес' : 'Показать адрес'} aria-pressed={shown}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setShown((v) => !v); }}>{shown ? Icon.eyeOff : Icon.eye}</button>
    </span>
  );
}
