import { useEffect, useState } from 'react';
import { api } from '../api';
import { ErrorBox, Info, Switch, useAsync, usePoll } from '../ui';

interface S {
  executorIps: string[];
  sub: { host: string; port: number; scheme: string };
  knockTtlHours: number;
  failThresholdMin: number;
  bot: { configured: boolean };
  backup: { recipients: string[]; time: string; enabled: boolean };
}

export function SettingsPage() {
  const { data, reload } = usePoll(() => api.get<S>('/api/v1/settings'), null);
  if (!data) return <p className="muted">Загрузка…</p>;
  return (
    <>
      <div className="page-head"><div><h1>Настройки</h1><p>Адрес исполнителя, проверка связи, Telegram-бот и бэкапы</p></div></div>
      <Executor s={data} onSaved={reload} />
      <General s={data} />
      <BotCard s={data} onSaved={reload} />
      <BackupCard s={data} />
    </>
  );
}

function Executor({ s, onSaved }: { s: S; onSaved: () => void }) {
  const [ips, setIps] = useState(s.executorIps.join('\n'));
  const [detected, setDetected] = useState<string | null>(null);
  const { busy, error, run } = useAsync();
  return (
    <section className="card pad stack">
      <h2>Адреса исполнителя (executor.ips)</h2>
      <p className="small muted">С этих адресов панель ходит на узлы по SSH. Они попадают в <code>from=</code> ключа панели и в защищённый набор firewall. Меняйте по схеме «добавить → проверить → убрать старый» (§7.10).</p>
      <textarea className="inp mono" rows={3} value={ips} onChange={(e) => setIps(e.target.value)} placeholder="по одному IP в строке" />
      <div className="flex">
        <button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/executor', { ips: ips.split(/[\s,]+/).filter(Boolean) }); onSaved(); })}>Сохранить</button>
        <button className="btn" disabled={busy} onClick={() => void run(async () => setDetected((await api.post<{ ip: string }>('/api/v1/settings/executor/detect')).ip))}>Определить мой внешний IP</button>
        {detected && <span className="small">Внешний IP: <code>{detected}</code> {!ips.includes(detected) && <button className="link" onClick={() => setIps((v) => (v ? v + '\n' : '') + detected)}>добавить</button>}</span>}
      </div>
      <ErrorBox error={error} />
    </section>
  );
}

function General({ s }: { s: S }) {
  const [v, setV] = useState({ failThresholdMin: s.failThresholdMin, knockTtlHours: s.knockTtlHours });
  const [saved, setSaved] = useState(false);
  const { busy, error, run } = useAsync();
  return (
    <section className="card pad stack">
      <h2>Проверки и доступ</h2>
      <div className="grid g2">
        <label className="fld">Порог сбоя связи
          <select className="inp" value={v.failThresholdMin} onChange={(e) => setV({ ...v, failThresholdMin: Number(e.target.value) })}><option value={30}>30 мин</option><option value={60}>1 ч</option><option value={120}>2 ч</option></select>
          <span className="k">Нет связи с узлом или между узлами дольше — чек-лист узла нужно пройти заново.</span></label>
        <label className="fld">Сколько живёт IP после knock
          <select className="inp" value={v.knockTtlHours} onChange={(e) => setV({ ...v, knockTtlHours: Number(e.target.value) })}>{[6, 12, 24, 48].map((h) => <option key={h} value={h}>{h} ч</option>)}</select></label>
      </div>
      <div className="flex"><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/general', v); setSaved(true); })}>Сохранить</button>{saved && <span className="k">Сохранено</span>}</div>
      <ErrorBox error={error} />
    </section>
  );
}

function BotCard({ s, onSaved }: { s: S; onSaved: () => void }) {
  const [token, setToken] = useState('');
  const [info, setInfo] = useState<string | null>(null);
  const { busy, error, run } = useAsync();
  return (
    <section className="card pad stack">
      <h2>Telegram-бот</h2>
      <p className="small muted">Бот работает через long polling — входящий порт не нужен. Он присылает бэкапы получателям, уведомляет админов и отвечает пользователям на /sub, /links, /access. Telegram ID админов и получателей задаются в «Права и роли».</p>
      <div className="flex">
        <input className="inp mono" style={{ flex: 1, minWidth: 260 }} type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder={s.bot.configured ? 'токен задан — введите новый, чтобы заменить' : '123456:ABC… от @BotFather'} aria-label="Токен бота" autoComplete="off" />
        <button className="btn pri" disabled={busy || !token} onClick={() => void run(async () => { const r = await api.put<{ username: string | null }>('/api/v1/settings/bot', { token }); setInfo(r.username ? `Бот @${r.username} подключён` : 'Сохранено'); setToken(''); onSaved(); })}>Сохранить</button>
        {s.bot.configured && <button className="btn ghost" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/bot', { token: null }); setInfo('Бот отключён'); onSaved(); })}>Отключить</button>}
      </div>
      {info && <div className="alert ok">{info}</div>}
      <ErrorBox error={error} />
      <BotProxy />
    </section>
  );
}

interface BotProxyState {
  enabled: boolean; serverId: string; templateId: string;
  options: Array<{ serverId: string; serverName: string; templateId: string; templateName: string; protocol: string }>;
}

/** Прокси бота: если api.telegram.org с главного сервера заблокирован, бот ходит через одну из конфигураций флота. */
function BotProxy() {
  const { data, reload } = usePoll(() => api.get<BotProxyState>('/api/v1/settings/bot-proxy'), null);
  const [probe, setProbe] = useState<{ direct: string; proxy: string | null } | null>(null);
  const { busy, error, run } = useAsync();
  if (!data) return null;
  const sel = data.serverId && data.templateId ? `${data.serverId}|${data.templateId}` : '';
  const save = (enabled: boolean, value = sel) => run(async () => {
    const [serverId = '', templateId = ''] = value.split('|');
    const r = await api.put<{ probe: { direct: string; proxy: string | null } }>('/api/v1/settings/bot-proxy', { enabled, serverId, templateId });
    setProbe(r.probe);
    void reload();
  });
  return (
    <div className="stack" style={{ borderTop: '1px solid var(--line)', paddingTop: 14 }}>
      <div className="flex" style={{ justifyContent: 'space-between' }}>
        <span><b>Через прокси</b> <Info>Если с главного сервера Telegram недоступен (например, сервер в РФ), бот будет ходить через выбранную конфигурацию на одном из ваших серверов. Панель сама добавит в неё служебный клиент для бота.</Info></span>
        <Switch label="Бот через прокси" on={data.enabled} disabled={busy || (!data.enabled && !sel && !data.options.length)}
          onChange={(v) => void save(v, sel || (data.options[0] ? `${data.options[0].serverId}|${data.options[0].templateId}` : ''))} />
      </div>
      {data.options.length ? (
        <label className="fld">Конфигурация для бота
          <select className="inp" value={sel} disabled={busy} onChange={(e) => void save(data.enabled, e.target.value)}>
            {!sel && <option value="">выберите…</option>}
            {data.options.map((o) => <option key={`${o.serverId}|${o.templateId}`} value={`${o.serverId}|${o.templateId}`}>{o.serverName} · {o.templateName} ({o.protocol})</option>)}
          </select>
        </label>
      ) : <span className="k">Нет подходящих конфигураций: нужна выкаченная конфигурация на протоколе Xray (VLESS, VMess, Trojan, Shadowsocks) на сервере флота.</span>}
      <div className="flex">
        <button className="btn sm" disabled={busy} onClick={() => void run(async () => setProbe(await api.post('/api/v1/settings/bot-proxy/test')))}>{busy ? 'Проверяю…' : 'Проверить доступ к Telegram'}</button>
      </div>
      {probe && (
        <div className="stack" style={{ gap: 4 }}>
          <span className="small">Напрямую: {probe.direct}</span>
          {probe.proxy !== null && <span className="small">Через прокси: {probe.proxy}</span>}
        </div>
      )}
      <ErrorBox error={error} />
    </div>
  );
}

function BackupCard({ s }: { s: S }) {
  const [v, setV] = useState({ recipients: s.backup.recipients.join('\n'), time: s.backup.time, enabled: s.backup.enabled });
  const [saved, setSaved] = useState(false);
  const { busy, error, run } = useAsync();
  useEffect(() => setSaved(false), [v]);
  return (
    <section className="card pad stack">
      <h2>Бэкапы</h2>
      <p className="small muted">Копия (база и мастер-ключ) шифруется age на публичные ключи ниже и уходит ботом двум админам-получателям. Приватный ключ age храните офлайн: без него копию не расшифровать. Восстановление: <code>npm run restore -w server -- файл.age ключ.txt</code>.</p>
      <label className="fld">Публичные ключи age получателей (age1…, по одному в строке)<textarea className="inp mono" rows={3} value={v.recipients} onChange={(e) => setV({ ...v, recipients: e.target.value })} /></label>
      <div className="flex">
        <label className="fld">Ежедневно в (UTC)<input className="inp mono" style={{ width: 120 }} value={v.time} onChange={(e) => setV({ ...v, time: e.target.value })} /></label>
        <span className="flex small" style={{ marginTop: 22 }}><Switch label="Включено" on={v.enabled} onChange={(x) => setV({ ...v, enabled: x })} />по расписанию</span>
      </div>
      <div className="flex"><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/backup', { recipients: v.recipients.split(/\s+/).filter(Boolean), time: v.time, enabled: v.enabled }); setSaved(true); })}>Сохранить</button>{saved && <span className="k">Сохранено</span>}<a href="#/backups">История бэкапов</a></div>
      <ErrorBox error={error} />
    </section>
  );
}
