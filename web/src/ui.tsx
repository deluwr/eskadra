import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';

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

export function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="copy">
      <button className="btn sm" onClick={() => void navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}>
        {copied ? 'Скопировано' : 'Копировать'}
      </button>
      <pre className="code">{text}</pre>
    </div>
  );
}

export function CopyButton({ text, label = 'Копировать' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return <button className="btn sm" onClick={() => void navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}>{copied ? 'Скопировано' : label}</button>;
}

const P = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };

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
  help: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01" /></svg>,
  moon: <svg width="18" height="18" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" /></svg>,
};

export const STAGES = ['не подключён', 'подключён', 'настроен', 'проверен', 'защищён'];

/** Подсказка (i): текст по наведению, фокусу или нажатию — вместо абзацев пояснений в интерфейсе. */
export function Info({ children, label = 'Подсказка' }: { children: ReactNode; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <span className={`info ${open ? 'open' : ''}`} onMouseLeave={() => setOpen(false)}>
      <button type="button" className="info-i" aria-label={label} aria-expanded={open} onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen((v) => !v); }} onBlur={() => setOpen(false)}>i</button>
      <span className="info-pop" role="tooltip">{children}</span>
    </span>
  );
}

/** Роли узлов по-человечески. relay/control — старые значения, показываются как вход/главный. */
export const ROLE_LABEL: Record<string, string> = { entry: 'вход', relay: 'вход', exit: 'выход', control: 'главный' };
export const roleLabel = (s: { role: string; mgmt_mode?: string }) => (s.mgmt_mode === 'local' ? 'главный · вход' : ROLE_LABEL[s.role] ?? s.role);

/** Уровни защиты хоста одним словом. */
export const LEVEL_LABEL: Record<string, string> = { P1: 'обычная', P2: 'средняя', P3: 'высокая' };
export function Level({ value }: { value: string }) {
  return <Tag kind={value === 'P3' ? 'ok' : value === 'P2' ? 'info' : undefined}>{LEVEL_LABEL[value] ?? value}</Tag>;
}

export function StagePip({ stage }: { stage: number }) {
  return (
    <div>
      <div className="pip" aria-label={`этап ${stage} из 4`}>
        {[1, 2, 3, 4].map((i) => <i key={i} className={i <= stage ? 'd' : i === stage + 1 ? 'c' : ''} />)}
      </div>
      <div className="k">{STAGES[stage]}</div>
    </div>
  );
}

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    addEventListener('keydown', onKey);
    return () => removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-bg" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card modal" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}
