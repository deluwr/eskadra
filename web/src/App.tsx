import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError, setOtpProvider } from './api';
import { CopyButton, ErrorBox, Icon, Info, Modal, setConfirmProvider, Toasts, useAsync } from './ui';
import { OverviewPage } from './pages/Overview';
import { ServersPage } from './pages/Servers';
import { ServerDetailPage } from './pages/ServerDetail';
import { ConfigsPage } from './pages/Configs';
import { UsersPage } from './pages/Users';
import { PortsPage } from './pages/Ports';
import { AccessPage } from './pages/Access';
import { SettingsPage } from './pages/Settings';
import { BackupsPage } from './pages/Backups';
import { AuditPage } from './pages/Audit';
import { HelpPage } from './pages/Help';
import { CoresPage } from './pages/Cores';
import { getLang, setLang } from './i18n';

type Route = { page: string; id?: string };
const parseHash = (): Route => {
  const [page = 'overview', id] = location.hash.replace(/^#\/?/, '').split('/');
  return { page: page || 'overview', id };
};

type Theme = 'dark' | 'light';
const readTheme = (): Theme => { try { return localStorage.getItem('eskadra.theme') === 'light' ? 'light' : 'dark'; } catch { return 'dark'; } };

export interface AuthState { setupNeeded: boolean; loggedIn: boolean; username: string | null; role: string | null; totp: boolean }

export function App() {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [route, setRoute] = useState<Route>(parseHash);
  const [theme, setTheme] = useState<Theme>(readTheme);
  const [otpAsk, setOtpAsk] = useState<((code: string | null) => void) | null>(null);
  const [confirmAsk, setConfirmAsk] = useState<{ text: string; done: (ok: boolean) => void } | null>(null);

  useEffect(() => {
    // смена темы мгновенно: без этого все переходы цвета и фона срабатывают разом и страница «размазывается»
    const off = document.createElement('style');
    off.textContent = '*,*::before,*::after{transition:none !important}';
    document.head.appendChild(off);
    document.documentElement.dataset.theme = theme;
    void getComputedStyle(document.body).opacity;   // принудительный перерасчёт стилей
    requestAnimationFrame(() => off.remove());
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#0B1019' : '#F3F5F8');
    try { localStorage.setItem('eskadra.theme', theme); } catch { /* приватный режим */ }
  }, [theme]);

  useEffect(() => {
    setOtpProvider(() => new Promise<string | null>((resolve) => setOtpAsk(() => resolve)));
    setConfirmProvider((text) => new Promise<boolean>((resolve) => setConfirmAsk({ text, done: resolve })));
  }, []);

  const refreshAuth = useCallback(() => api.get<AuthState>('/api/v1/auth/state').then(setAuth), []);
  useEffect(() => {
    void refreshAuth();
    const onHash = () => setRoute(parseHash());
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  }, [refreshAuth]);

  if (!auth) return <div className="center muted">Загрузка…</div>;
  if (!auth.loggedIn) return <LoginPage setup={auth.setupNeeded} onDone={refreshAuth} />;

  const logout = async () => { await api.post('/api/v1/auth/logout'); void refreshAuth(); };
  const nav: Array<[string, string, ReactNode]> = [
    ['overview', 'Обзор', Icon.overview], ['servers', 'Серверы', Icon.servers], ['configs', 'Конфигурации', Icon.configs], ['cores', 'Ядра', Icon.cores],
    ['users', 'Пользователи', Icon.users], ['ports', 'Порты и связность', Icon.ports], ['access', 'Права и роли', Icon.access],
  ];
  const nav2: Array<[string, string, ReactNode]> = [['backups', 'Бэкапы', Icon.backups], ['audit', 'Аудит', Icon.audit], ['settings', 'Настройки', Icon.settings], ['help', 'Справка', Icon.help]];
  const active = route.page === 'server' ? 'servers' : route.page;

  return (
    <div className="shell">
      <aside className="side">
        <a className="brand" href="#/overview">
          <span className="brand-mark">{Icon.logo()}</span>
          <span className="brand-text"><span className="brand-name">Эскадра</span><span className="k">управление узлами</span></span>
        </a>
        {nav.map(([id, label, icon]) => <a key={id} className={`nav ${active === id ? 'on' : ''}`} href={`#/${id}`} aria-current={active === id ? 'page' : undefined}>{icon}{label}</a>)}
        <div className="side-sep" />
        {nav2.map(([id, label, icon]) => <a key={id} className={`nav ${active === id ? 'on' : ''}`} href={`#/${id}`} aria-current={active === id ? 'page' : undefined}>{icon}{label}</a>)}
        <ExecutorFoot />
      </aside>
      <div className="main">
        <header className="topbar">
          <span style={{ flex: 1 }} />
          {!auth.totp && <a className="tag warn" href="#/access">2FA не включена</a>}
          <button className="btn ghost sm static no-tr" onClick={() => {
            const next = getLang() === 'en' ? 'ru' : 'en';
            // язык панели: названия профилей в подписках тоже на нём (нужна роль admin; иначе меняется только интерфейс)
            void api.put('/api/v1/settings/lang', { lang: next }).catch(() => undefined).finally(() => setLang(next));
          }} aria-label="Language / Язык" title="Language / Язык">{getLang() === 'en' ? 'RU' : 'EN'}</button>
          <button className="btn ghost icon" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Переключить тему">{theme === 'dark' ? Icon.sun : Icon.moon}</button>
          <span className="flex who"><span className="tag">{auth.role}</span><span>{auth.username}</span></span>
          <button className="btn ghost" onClick={logout}>Выйти</button>
        </header>
        <main className="content">
          {route.page === 'overview' && <OverviewPage />}
          {route.page === 'servers' && <ServersPage />}
          {route.page === 'server' && route.id && <ServerDetailPage id={route.id} />}
          {route.page === 'configs' && <ConfigsPage />}
          {route.page === 'users' && <UsersPage />}
          {route.page === 'ports' && <PortsPage />}
          {route.page === 'access' && <AccessPage auth={auth} onChange={refreshAuth} />}
          {route.page === 'settings' && <SettingsPage />}
          {route.page === 'backups' && <BackupsPage />}
          {route.page === 'audit' && <AuditPage />}
          {route.page === 'help' && <HelpPage />}
          {route.page === 'cores' && <CoresPage />}
        </main>
      </div>
      <Toasts />
      {otpAsk && <OtpModal onDone={(code) => { otpAsk(code); setOtpAsk(null); }} />}
      {confirmAsk && (
        <Modal title="Подтверждение" onClose={() => { confirmAsk.done(false); setConfirmAsk(null); }}>
          <p>{confirmAsk.text}</p>
          <div className="flex">
            <button className="btn pri" autoFocus onClick={() => { confirmAsk.done(true); setConfirmAsk(null); }}>Да</button>
            <button className="btn ghost" onClick={() => { confirmAsk.done(false); setConfirmAsk(null); }}>Отмена</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function ExecutorFoot() {
  const [ips, setIps] = useState<string[] | null>(null);
  const [ver, setVer] = useState<{ version: string; latest: string | null; updateAvailable: boolean } | null>(null);
  useEffect(() => {
    api.get<{ executorIps: string[] }>('/api/v1/settings').then((s) => setIps(s.executorIps)).catch(() => undefined);
    // наличие обновления проверяется при открытии панели
    api.get<{ version: string; latest: string | null; updateAvailable: boolean }>('/api/v1/version').then(setVer).catch(() => undefined);
  }, []);
  return (
    <div className="side-foot">
      <span className="k">Исполнитель</span>
      <span className="mono small">{ips?.length ? ips.join(', ') : 'не задан'}</span>
      {ver && (
        <span className="flex" style={{ gap: 6, marginTop: 6 }}>
          <span className="k">Эскадра <span className="mono">{ver.version}</span></span>
          {ver.updateAvailable && (
            <span className="flex" style={{ gap: 2 }}>
              <span className="tag ok">есть {ver.latest}</span>
              <Info label="Как обновить">Обновление ставится на главном сервере под root: <code>eskadra update</code> (или пункт «Обновить» в меню <code>eskadra</code>). Данные и настройки сохраняются.<br /><CopyButton text="eskadra update" label="Скопировать команду" /></Info>
            </span>
          )}
        </span>
      )}
    </div>
  );
}

function OtpModal({ onDone }: { onDone: (code: string | null) => void }) {
  const [code, setCode] = useState('');
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => ref.current?.focus(), []);
  return (
    <Modal title="Код 2FA" onClose={() => onDone(null)}>
      <p className="muted small">Операция чувствительная. Введите 6 цифр из приложения-аутентификатора.</p>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); onDone(code.trim()); }}>
        <input ref={ref} className="inp mono" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} aria-label="Код 2FA" />
        <div className="flex"><button className="btn pri" disabled={code.length !== 6}>Подтвердить</button><button type="button" className="btn ghost" onClick={() => onDone(null)}>Отмена</button></div>
      </form>
    </Modal>
  );
}

function LoginPage({ setup, onDone }: { setup: boolean; onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [needOtp, setNeedOtp] = useState(false);
  const { busy, error, run } = useAsync();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        const token = new URLSearchParams(location.hash.split('?')[1] ?? '').get('token') ?? undefined;
        await api.post(setup ? '/api/v1/auth/setup' : '/api/v1/auth/login', { username, password, ...(needOtp ? { otp } : {}), ...(setup && token ? { token } : {}) });
        if (setup) location.hash = '#/overview';
        onDone();
      } catch (err) {
        if (err instanceof ApiError && err.status === 428) { setNeedOtp(true); return; }
        throw err;
      }
    });
  };
  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <div className="flex"><span className="brand-mark">{Icon.logo()}</span><span className="brand-name">Эскадра</span></div>
        <h2>{setup ? 'Создание владельца' : 'Вход'}</h2>
        {setup && <p className="muted small">Первый запуск. Owner создаётся по ссылке первичной настройки (команда <code>eskadra url</code> на сервере) или с localhost. Пароль — от 12 символов.</p>}
        <label className="fld">Логин<input className="inp" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
        <label className="fld">Пароль<input className="inp" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={setup ? 'new-password' : 'current-password'} required minLength={setup ? 12 : 1} /></label>
        {needOtp && <label className="fld">Код 2FA<input className="inp mono" inputMode="numeric" autoComplete="one-time-code" value={otp} onChange={(e) => setOtp(e.target.value)} autoFocus /></label>}
        <ErrorBox error={error} />
        <button className="btn pri" disabled={busy}>{setup ? 'Создать и войти' : 'Войти'}</button>
      </form>
    </div>
  );
}
