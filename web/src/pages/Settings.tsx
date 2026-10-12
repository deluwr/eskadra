import { useEffect, useState } from 'react';
import { api, can, fmtTime } from '../api';
import { UpdateModal, type Ver } from '../App';
import { ErrorBox, Icon, Info, Switch, Tag, useAsync, usePoll, toast, Addr } from '../ui';

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
      <div className="page-head"><div><h1>Настройки</h1><p>Адрес исполнителя, проверка связи, блокировки, Telegram-бот и бэкапы</p></div></div>
      <PanelVersion />
      <Executor s={data} onSaved={reload} />
      <General s={data} />
      <BlocksCard />
      <BotCard s={data} onSaved={reload} />
      <BackupCard s={data} />
    </>
  );
}

function Executor({ s, onSaved }: { s: S; onSaved: () => void }) {
  const [ips, setIps] = useState(s.executorIps.join('\n'));
  const [detected, setDetected] = useState<string | null>(null);
  const [shown, setShown] = useState(false);
  const { busy, error, run } = useAsync();
  return (
    <section className="card pad stack">
      <h2>Адреса исполнителя (executor.ips)</h2>
      <p className="small muted">С этих адресов панель ходит на узлы по SSH. Они попадают в <code>from=</code> ключа панели и в защищённый набор firewall. Меняйте по схеме «добавить → проверить → убрать старый» (§7.10).</p>
      <div className="addr" style={{ alignItems: 'flex-start' }}>
        <textarea className={`inp mono addr-v ${shown ? '' : 'blur'}`} rows={3} value={ips} onFocus={() => setShown(true)} onChange={(e) => setIps(e.target.value)} placeholder="по одному IP в строке" />
        <button type="button" className="addr-eye" aria-label={shown ? 'Скрыть адреса' : 'Показать адреса'} aria-pressed={shown} onClick={() => setShown((v) => !v)}>{shown ? Icon.eyeOff : Icon.eye}</button>
      </div>
      <div className="flex">
        <button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/executor', { ips: ips.split(/[\s,]+/).filter(Boolean) }); toast('Адреса исполнителя сохранены'); onSaved(); })}>Сохранить</button>
        <button className="btn" disabled={busy} onClick={() => void run(async () => setDetected((await api.post<{ ip: string }>('/api/v1/settings/executor/detect')).ip))}>Определить мой внешний IP</button>
        {detected && <span className="small">Внешний IP: <Addr value={detected} /> {!ips.includes(detected) && <button className="link" onClick={() => setIps((v) => (v ? v + '\n' : '') + detected)}>добавить</button>}</span>}
      </div>
      <ErrorBox error={error} />
    </section>
  );
}

function General({ s }: { s: S }) {
  const [v, setV] = useState({ failThresholdMin: s.failThresholdMin, knockTtlHours: s.knockTtlHours });
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
      <div className="flex"><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/general', v); toast('Настройки сохранены'); })}>Сохранить</button></div>
      <ErrorBox error={error} />
    </section>
  );
}

interface Versions { current: string; minWithData: string; error: string | null; versions: Array<{ version: string; published: string; prerelease: boolean; snapshotAt: string | null; withData: boolean }> }

/** Версия панели и откат на прошлую — только owner. Данные возвращаются из копии, снятой при обновлении с той версии. */
function PanelVersion() {
  const { data: ver } = usePoll(() => api.get<Ver>('/api/v1/version'), null);
  const { data } = usePoll(() => (can('owner') ? api.get<Versions>('/api/v1/update/versions') : Promise.resolve(null)), null);
  const [pick, setPick] = useState('');
  const [withData, setWithData] = useState(true);
  const [open, setOpen] = useState<'update' | 'rollback' | null>(null);
  if (!ver) return null;
  const v = data?.versions.find((x) => x.version === pick) ?? data?.versions[0];
  return (
    <section className="card pad stack">
      <span className="flex" style={{ justifyContent: 'space-between' }}>
        <h2>Версия панели <Info>Перед каждым обновлением и откатом панель сохраняет копию своих данных (последние 8). При откате на версию её данные можно вернуть — на момент, когда с неё обновились.</Info></h2>
        <span className="flex" style={{ gap: 8 }}><Tag kind="acc">{ver.version}</Tag>{ver.updateAvailable && can('owner') && <button className="btn pri sm" onClick={() => setOpen('update')}>{`Обновить до ${ver.latest}`}</button>}</span>
      </span>
      {!can('owner') ? <span className="k">Обновление и откат панели — только у owner.</span> : !data ? <span className="k">Загрузка версий…</span> : data.error ? <ErrorBox error={`список версий с GitHub недоступен: ${data.error}`} /> : !data.versions.length ? <span className="k">Прошлых версий нет.</span> : (
        <div className="flex" style={{ alignItems: 'flex-end', gap: 14 }}>
          <label className="fld" style={{ flex: '0 1 320px' }}>Откатить на
            <select className="inp" value={v?.version ?? ''} onChange={(e) => { setPick(e.target.value); setWithData(true); }}>
              {data.versions.map((x) => <option key={x.version} value={x.version}>{x.version} · {x.published.slice(0, 10)}{x.snapshotAt ? ' · есть копия данных' : ''}</option>)}
            </select>
          </label>
          <label className="cb" title={v?.withData ? undefined : v && !v.snapshotAt ? 'копии данных этой версии нет: с неё обновлялись до появления копий или давно' : `версии до ${data.minWithData} не умеют подменять данные`}>
            <input type="checkbox" checked={!!v?.withData && withData} disabled={!v?.withData} onChange={(e) => setWithData(e.target.checked)} />
            {v?.snapshotAt ? `вернуть данные на ${fmtTime(v.snapshotAt)}` : 'вернуть данные (копии нет)'}
          </label>
          <button className="btn warn" disabled={!v} onClick={() => setOpen('rollback')}>Откатить…</button>
        </div>
      )}
      {v && !v.withData && <span className="k">Без копии данных старая версия запустится на текущей базе — годится для соседних версий; для далёких откатов возможны ошибки.</span>}
      {open && <UpdateModal ver={ver} target={open === 'rollback' ? v?.version : undefined} rollback={open === 'rollback' ? { withData: !!v?.withData && withData } : undefined} onClose={() => setOpen(null)} />}
    </section>
  );
}

interface Blocks { bittorrent: boolean; smtp: boolean; quic: boolean }

/** Блокировки протоколов на всех серверах (вход и выходы). */
function BlocksCard() {
  const { data, setData } = usePoll(() => api.get<Blocks>('/api/v1/settings/blocks'), null);
  const { busy, error, run } = useAsync();
  if (!data) return null;
  const set = (patch: Partial<Blocks>) => run(async () => {
    setData(await api.put<Blocks>('/api/v1/settings/blocks', { ...data, ...patch }));
    toast('Блокировки сохранены — серверы получат их в течение минуты');
  });
  const row = (key: keyof Blocks, title: string, text: string) => (
    <div className="block-row">
      <span className="row-text"><b className="small">{title}</b><span className="k">{text}</span></span>
      <Switch label={title} on={data[key]} disabled={busy || !can('settings.edit')} onChange={(v) => void set({ [key]: v })} />
    </div>
  );
  return (
    <section className="card pad stack">
      <h2>Блокировки <Info>Действуют на всех серверах — и на входе, и на выходах, для всех пользователей и конфигураций. После изменения серверы переприменяют конфиги сами (подключения прервутся на секунды).</Info></h2>
      <div className="block-list">
        {row('bittorrent', 'BitTorrent', 'Протокол по содержимому (TCP и uTP), домены публичных трекеров; на Hysteria2 — ещё и UDP-трекеры. Распознавание работает даже в конфигурациях с выключенным sniffing. Полностью зашифрованные соединения торрент-клиента по содержимому не отличить, но без трекеров и uTP клиенту почти не найти пиров.')}
        {row('smtp', 'Исходящая почта (SMTP)', 'Порты 25, 465, 587, 2525: через VPN нельзя рассылать почту — хостеры блокируют серверы за спам.')}
        {row('quic', 'QUIC (HTTP/3)', 'UDP 443. Браузеры и приложения сами откатываются на обычный HTTPS. Включайте, только если QUIC мешает (например, обходит другие правила).')}
      </div>
      <span className="k">На серверах с 3x-ui маршрутизацию ведёт сама 3x-ui: BitTorrent она режет своими правилами (по умолчанию включено), остальное — в её настройках.</span>
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
      <p className="small muted" style={{ maxWidth: '72ch' }}>Админам бот показывает состояние серверов, то, что требует внимания, выходы «Авто» и запускает бэкап; пользователям — подписку, ссылки на профили и их трафик. Всё — кнопками под сообщением. Отвечает только привязанным: незнакомец увидит лишь свой Telegram ID. Привязка — кнопкой «Привязать» в «Права и роли» и в карточке пользователя. Входящий порт не нужен.</p>
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
  const { busy, error, run } = useAsync();
  return (
    <section className="card pad stack">
      <h2>Бэкапы</h2>
      <p className="small muted">Копия (база и мастер-ключ) шифруется age на публичные ключи ниже и уходит ботом двум админам-получателям. Приватный ключ age храните офлайн: без него копию не расшифровать. Восстановление — в разделе «Бэкапы»: загрузите копию и приватный ключ age.</p>
      <label className="fld">Публичные ключи age получателей (age1…, по одному в строке)<textarea className="inp mono" rows={3} value={v.recipients} onChange={(e) => setV({ ...v, recipients: e.target.value })} /></label>
      <div className="flex">
        <label className="fld">Ежедневно в (UTC)<input className="inp mono" style={{ width: 120 }} value={v.time} onChange={(e) => setV({ ...v, time: e.target.value })} /></label>
        <span className="flex small" style={{ marginTop: 22 }}><Switch label="Включено" on={v.enabled} onChange={(x) => setV({ ...v, enabled: x })} />по расписанию</span>
      </div>
      <div className="flex"><button className="btn pri" disabled={busy} onClick={() => void run(async () => { await api.put('/api/v1/settings/backup', { recipients: v.recipients.split(/\s+/).filter(Boolean), time: v.time, enabled: v.enabled }); toast('Настройки сохранены'); })}>Сохранить</button><a href="#/backups">История бэкапов</a></div>
      <ErrorBox error={error} />
    </section>
  );
}
