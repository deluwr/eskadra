/**
 * Интерактивное управление флотом из терминала (меню eskadra → разделы флота).
 * Ходит в API панели под консольной сессией: вся логика, права и аудит — те же, что в веб-интерфейсе.
 *   node tui.js [overview|servers|users|configs|cores|backups|audit]
 */
import http from 'node:http';
import https from 'node:https';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { config } from './config.js';
import { openDb } from './db.js';
import { randomToken, sha256hex } from './lib/crypto.js';

// ───── оформление ─────
const C = { b: '\x1b[1m', dim: '\x1b[2m', ok: '\x1b[32m', warn: '\x1b[33m', err: '\x1b[31m', acc: '\x1b[38;5;179m', info: '\x1b[36m', x: '\x1b[0m' };
const p = (s = '') => stdout.write(s + '\n');
const title = (s: string) => { p(); p(`${C.acc}${C.b}⛵ ${s}${C.x}`); p(`${C.dim}${'─'.repeat(Math.min(60, s.length + 4))}${C.x}`); };
const tag = (s: string, kind: 'ok' | 'warn' | 'err' | 'info' | 'dim' = 'dim') => `${C[kind]}${s}${C.x}`;
const pad = (s: string, n: number) => { const len = [...s.replace(/\x1b\[[0-9;]*m/g, '')].length; return s + ' '.repeat(Math.max(0, n - len)); };

const rl = createInterface({ input: stdin, output: stdout, terminal: stdin.isTTY });
// строки читаются через буферизованный итератор: так меню работает и в терминале, и при вводе из пайпа
const lines = rl[Symbol.asyncIterator]();
const ask = async (q: string) => {
  stdout.write(`${C.b}${q}${C.x} `);
  const r = await lines.next();
  if (r.done) { p(); process.exit(0); }
  if (!stdin.isTTY) stdout.write(String(r.value) + '\n');
  return String(r.value).trim();
};
const pause = async () => { await ask(`${C.dim}Enter — назад${C.x}`); };
const confirm = async (q: string) => /^(y|д|да|yes)$/i.test(await ask(`${q} [y/N]:`));

// ───── консольная сессия ─────
const db = openDb(config.dataDir);
const owner = db.prepare(`SELECT id, username FROM admins WHERE role = 'owner' ORDER BY id LIMIT 1`).get() as { id: number; username: string } | undefined;
if (!owner) { p(`${C.err}Владелец ещё не создан. Получите ссылку: eskadra url${C.x}`); process.exit(1); }
const token = randomToken();
db.prepare(`INSERT INTO sessions (token_hash, admin_id, expires_at, ip, console) VALUES (?, ?, datetime('now', '+4 hours'), 'console', 1)`).run(sha256hex(token), owner.id);
const cleanup = () => { try { db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256hex(token)); } catch { /* ignore */ } };
process.on('exit', cleanup);
process.on('SIGINT', () => { p(); process.exit(0); });

// ───── клиент API ─────
const scheme = config.tlsCert && config.tlsKey ? 'https' : 'http';
async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = (scheme === 'https' ? https : http).request({
      host: '127.0.0.1', port: config.port, method, path: config.basePath + path.replace(/^\//, ''),
      rejectUnauthorized: false, // свой же сервер на 127.0.0.1; сертификат выписан на внешний IP/домен
      headers: { Cookie: `fleet_session=${token}`, 'X-Fleet': '1', ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}) },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json: any = {};
        try { json = text ? JSON.parse(text) : {}; } catch { json = { error: text.slice(0, 200) }; }
        if ((res.statusCode ?? 500) >= 400) reject(new Error(json.error ?? `HTTP ${res.statusCode}`));
        else resolve(json as T);
      });
    });
    req.on('error', (e) => reject(new Error(`панель не отвечает (${e.message}). Проверьте: eskadra status`)));
    if (data) req.write(data);
    req.end();
  });
}

async function act(label: string, fn: () => Promise<unknown>) {
  try {
    const r = await fn();
    p(`${C.ok}✓ ${label}${C.x}`);
    return r;
  } catch (e) {
    p(`${C.err}✗ ${label}: ${(e as Error).message}${C.x}`);
    return undefined;
  }
}

/** Меню: пункты с номерами; возвращает выбранный ключ ('' — назад). */
async function choose(items: Array<[string, string]>, back = 'Назад'): Promise<string> {
  for (const [k, l] of items) p(`  ${C.acc}${pad(k + ')', 4)}${C.x} ${l}`);
  p(`  ${C.dim}0)  ${back}${C.x}`);
  const a = await ask('Выберите:');
  return a === '0' || a === '' ? '' : a;
}

async function followJob(id: number) {
  let shown = 0;
  for (;;) {
    const j = await api<{ status: string; log: string }>('GET', `api/v1/jobs/${id}`);
    const lines = (j.log ?? '').split('\n').filter(Boolean);
    for (const l of lines.slice(shown)) p(`  ${C.dim}${l.replace(/^\[[^\]]+\]\s*/, '')}${C.x}`);
    shown = lines.length;
    if (j.status !== 'running') { p(j.status === 'ok' ? tag('✓ готово', 'ok') : tag('✗ остановлено', 'err')); return; }
    await new Promise((r) => setTimeout(r, 2000));
  }
}

const ago = (s: string | null) => {
  if (!s) return 'никогда';
  const d = (Date.now() - Date.parse(s.includes('T') ? s : s.replace(' ', 'T') + 'Z')) / 1000;
  return d < 60 ? `${Math.round(d)} с назад` : d < 3600 ? `${Math.round(d / 60)} мин назад` : d < 86400 ? `${Math.round(d / 3600)} ч назад` : `${Math.round(d / 86400)} дн назад`;
};
const STAGES = ['ждёт bootstrap', 'подключён', 'настроен', 'проверен', 'защищён'];
const bytes = (n: number) => (n < 1024 ** 2 ? `${(n / 1024).toFixed(0)} КБ` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} МБ` : `${(n / 1024 ** 3).toFixed(2)} ГБ`);

// ───── разделы ─────

async function overview() {
  const d = await api('GET', 'api/v1/overview');
  title('Обзор');
  p(`  узлов ${C.b}${d.counts.servers}${C.x} (на связи ${d.counts.online}) · пользователей ${C.b}${d.counts.users}${C.x} (активны ${d.counts.activeUsers}) · трафик за месяц ${bytes(d.trafficBytes)}`);
  p(`  последний бэкап: ${d.lastBackup ? `${d.lastBackup.created_at} · ${d.lastBackup.status}` : 'не было'}`);
  p();
  p(`${C.b}Требует внимания${C.x}`);
  if (!d.attention.length) p(`  ${tag('всё в порядке', 'ok')}`);
  for (const a of d.attention) p(`  ${a.level === 'fail' ? tag('●', 'err') : a.level === 'warn' ? tag('●', 'warn') : tag('●', 'info')} ${a.title}${C.dim} — ${a.detail}${C.x}`);
  await pause();
}

async function servers() {
  for (;;) {
    const list = await api<any[]>('GET', 'api/v1/servers');
    title('Серверы');
    list.forEach((s, i) => p(`  ${C.acc}${pad(i + 1 + ')', 4)}${C.x} ${pad(C.b + s.name + C.x, 14)} ${pad(s.host + ':' + s.ssh_port, 24)} ${pad(s.role, 8)} ${pad(STAGES[s.stage] ?? '', 16)} ${s.fail_since ? tag('нет связи', 'err') : tag(ago(s.last_seen_at), s.last_seen_at ? 'ok' : 'dim')}`));
    if (!list.length) p(`  ${C.dim}серверов пока нет${C.x}`);
    p(`  ${C.acc}a)  ${C.x} Добавить сервер`);
    p(`  ${C.dim}0)  Назад${C.x}`);
    const a = await ask('Выберите:');
    if (a === '0' || a === '') return;
    if (a === 'a' || a === 'а') { await addServer(); continue; }
    const s = list[Number(a) - 1];
    if (s) await server(s.id);
  }
}

async function addServer() {
  title('Новый сервер');
  const name = await ask('Имя (например de-1):');
  const host = await ask('IP или домен:');
  const sshPort = Number((await ask('Порт SSH [22]:')) || 22);
  const role = (await ask('Роль: entry / relay / exit / control [entry]:')) || 'entry';
  const r = await act('сервер добавлен', () => api('POST', 'api/v1/servers', { name, host, sshPort, role }));
  if (!r) return pause();
  const s = (r as any).server;
  p();
  p(`${C.b}Выполните на сервере под root (только добавляет доступ панели):${C.x}`);
  p((r as any).snippet);
  p(`${C.dim}Затем откройте сервер в этом меню: «Сверить host key» → «Проверить вход» → «Preflight» → «Установить nodekit».${C.x}`);
  await pause();
  await server(s.id);
}

async function server(id: string) {
  for (;;) {
    const d = await api('GET', `api/v1/servers/${id}`);
    const s = d.server;
    title(`Сервер ${s.name}`);
    p(`  ${s.host}:${s.ssh_port} · ${s.role} · группа ${s.group_name} · ${s.os_info?.pretty ?? 'ОС не определена'}`);
    p(`  этап: ${C.b}${STAGES[s.stage]}${C.x} · защита ${s.protection_current} → цель ${s.protection_target} · firewall ${s.fw_mode} · связь ${s.fail_since ? tag('нет', 'err') : ago(s.last_seen_at)}`);
    p(`  ядра: Xray ${s.cores?.xray?.version ?? (s.coreModeEffective === 'xui' ? `из 3x-ui ${s.cores?.xui?.version ?? ''}` : '—')} · sing-box ${s.cores?.['sing-box']?.version ?? '—'} · режим ${s.coreModeEffective === 'xui' ? 'через 3x-ui' : 'своё ядро'}`);
    if (s.external_cores?.length) p(`  найдено на узле: ${s.external_cores.map((c: any) => `${c.name} (${c.active})`).join(', ')}`);
    p();
    const items: Array<[string, string]> = [];
    if (!s.host_key_fp) items.push(['1', 'Сверить host key (отпечаток из вывода сниппета)']);
    items.push(['2', 'Проверить вход и связь'], ['3', 'Preflight (только чтение)']);
    items.push(['4', s.sudo_mode === 'restricted' ? 'Обновить nodekit' : 'Установить nodekit (сузить sudo)']);
    if (s.sudo_mode === 'restricted') items.push(['5', 'Состояние узла'], ['6', 'Временно открыть SSH'], ['7', 'Аварийно снять блокировки'], ['8', 'Обновить ядро'], ['9', 'Откатить ядро']);
    if (s.external_cores?.some((c: any) => c.name === '3x-ui')) items.push(['x', 'Удалить 3x-ui с этого узла (с резервной копией)']);
    items.push(['s', 'Показать bootstrap-сниппет'], ['d', 'Удалить сервер из панели']);
    const a = await choose(items);
    if (!a) return;
    try {
      if (a === '1') {
        const r = await api('POST', `api/v1/servers/${id}/host-key/fetch`);
        p(`  сервер прислал: ${C.b}${r.fingerprint}${C.x}`);
        const fp = await ask('Вставьте отпечаток из вывода сниппета:');
        if (fp !== r.fingerprint) p(tag('Не совпадает — не доверяйте ключу, пока не выясните причину.', 'err'));
        else await act('host key закреплён', () => api('POST', `api/v1/servers/${id}/host-key/trust`, { fingerprint: fp }));
      }
      if (a === '2') { const r = await api('POST', `api/v1/servers/${id}/check`); p(`  ${r.ok ? tag('✓', 'ok') : tag('✗', 'err')} пользователь ${r.user}, сервер видит панель с ${r.seenFromIp}, sudo: ${r.sudo}`); }
      if (a === '3') {
        p(`${C.dim}собираю снимок…${C.x}`);
        const r = await api('POST', `api/v1/servers/${id}/preflight`);
        for (const c of r.checks) p(`  ${c.status === 'ok' ? tag('✓', 'ok') : c.status === 'warn' ? tag('!', 'warn') : c.status === 'fail' ? tag('✕', 'err') : tag('i', 'info')} ${pad(c.title, 20)} ${C.dim}${c.detail}${C.x}`);
      }
      if (a === '4') { p(`${C.dim}устанавливаю…${C.x}`); await act('nodekit установлен, sudo сужен, строгий режим включён', () => api('POST', `api/v1/servers/${id}/nodekit/install`)); }
      if (a === '5') { const r = await api('POST', `api/v1/servers/${id}/status`); p(r.output); p(`firewall: ${r.fwState}`); }
      if (a === '6') {
        const dur = await choose([['1', '30 минут'], ['2', '1 час'], ['3', '2 часа'], ['4', 'Закрыть сейчас']]);
        const map: Record<string, string> = { '1': '30m', '2': '1h', '3': '2h', '4': 'off' };
        if (map[dur]) { const r = await api('POST', `api/v1/servers/${id}/relax`, { duration: map[dur] }); p(r.output); }
      }
      if (a === '7' && await confirm('Снять все блокировки firewall на узле?')) { const r = await api('POST', `api/v1/servers/${id}/emergency-open`); p(r.output); }
      if (a === '8' || a === '9') {
        const core = (await choose([['1', 'Xray'], ['2', 'sing-box']])) === '2' ? 'sing-box' : 'xray';
        if (a === '8') {
          const ver = (await ask('Версия (Enter — последняя стабильная):')) || 'latest';
          p(`${C.dim}обновляю ${core}…${C.x}`);
          await act(`${core} обновлён`, () => api('POST', `api/v1/servers/${id}/cores/${core}/update`, { version: ver }));
        } else await act(`${core} откачен`, () => api('POST', `api/v1/servers/${id}/cores/${core}/rollback`));
      }
      if (a === 'x' && await confirm('Удалить 3x-ui с узла? Его пользователи потеряют доступ; база сохранится в /var/lib/fleet/baseline.')) {
        const r = await api('POST', `api/v1/servers/${id}/xui-remove`); p(r.output);
      }
      if (a === 's') p(d.snippet);
      if (a === 'd' && await confirm(`Удалить ${s.name} из панели? На самом сервере ничего не изменится.`)) { await api('DELETE', `api/v1/servers/${id}`); p(tag('удалён', 'ok')); await pause(); return; }
    } catch (e) { p(`${C.err}✗ ${(e as Error).message}${C.x}`); }
    await pause();
  }
}

async function users() {
  for (;;) {
    const list = await api<any[]>('GET', 'api/v1/users');
    title('Пользователи');
    list.forEach((u, i) => {
      const used = u.traffic.up + u.traffic.down;
      p(`  ${C.acc}${pad(i + 1 + ')', 4)}${C.x} ${pad(C.b + u.name + C.x, 16)} ${pad(u.status === 'active' ? tag('активен', 'ok') : tag('отключён', 'err'), 12)} ${pad(`${bytes(used)} / ${u.effective.trafficGb ? u.effective.trafficGb + ' ГБ' : '∞'}`, 22)} ${u.effective.expireAt ? 'до ' + u.effective.expireAt.slice(0, 10) : 'бессрочно'} · профилей ${u.profiles}`);
    });
    if (!list.length) p(`  ${C.dim}пользователей пока нет${C.x}`);
    p(`  ${C.acc}a)  ${C.x} Новый пользователь`);
    p(`  ${C.dim}0)  Назад${C.x}`);
    const a = await ask('Выберите:');
    if (a === '0' || a === '') return;
    if (a === 'a' || a === 'а') {
      const name = await ask('Имя:');
      const gb = await ask('Трафик в месяц, ГБ (Enter — без лимита):');
      const days = await ask('Срок, дней (Enter — бессрочно):');
      await act('пользователь создан', () => api('POST', 'api/v1/users', {
        name, trafficLimitGb: gb ? Number(gb) : null,
        expireAt: days ? new Date(Date.now() + Number(days) * 86400_000).toISOString() : null,
      }));
      await pause();
      continue;
    }
    const u = list[Number(a) - 1];
    if (u) await user(u.id);
  }
}

async function user(id: string) {
  for (;;) {
    const u = await api('GET', `api/v1/users/${id}`);
    title(`Пользователь ${u.name}`);
    p(`  ${u.status === 'active' ? tag('активен', 'ok') : tag(`отключён${u.disabled_reason ? ': ' + u.disabled_reason : ''}`, 'err')} · трафик ${bytes(u.traffic.up + u.traffic.down)} / ${u.effective.trafficGb ? u.effective.trafficGb + ' ГБ' : '∞'} · ${u.effective.expireAt ? 'до ' + u.effective.expireAt.slice(0, 10) : 'бессрочно'}`);
    p(`  режимы: ${u.modes.map((m: string) => (m === 'via' ? 'через вход' : 'напрямую')).join(', ')} · белый список: ${u.wl_mode} · IP сейчас: ${u.allowedIps.map((x: any) => x.cidr).join(', ') || '—'}`);
    p();
    const a = await choose([
      ['1', 'Подписка и knock-ссылка'], ['2', 'Отдельные ссылки (vless://, hysteria2://)'],
      ['3', u.status === 'active' ? 'Отключить' : 'Включить'], ['4', 'Изменить лимиты'],
      ['5', 'Сменить токен подписки'], ['6', 'Перевыпустить ссылки (старые перестанут работать)'], ['7', 'Удалить'],
    ]);
    if (!a) return;
    try {
      const body = (patch: Record<string, unknown>) => ({
        name: u.name, tgId: u.tg_id, limitGroup: u.limit_group, trafficLimitGb: u.traffic_limit_gb, expireAt: u.expire_at,
        deviceLimit: u.device_limit, overAction: u.over_action, modes: u.modes, nodeIds: u.node_ids, wlMode: u.wl_mode, status: u.status, ...patch,
      });
      if (a === '1') { p(`  подписка: ${C.b}${u.subUrl ?? 'не настроен адрес сервиса подписок'}${C.x}`); p(`  knock:    ${u.knockUrl ?? '—'}`); }
      if (a === '2') {
        const links = await api<any[]>('GET', `api/v1/users/${id}/links`);
        if (!links.length) p(`  ${C.dim}нет активных профилей — выкатите конфигурацию на доступные узлы${C.x}`);
        for (const l of links) { p(`  ${C.b}${l.name}${C.x}`); p(`  ${l.uri}`); p(); }
      }
      if (a === '3') await act(u.status === 'active' ? 'отключён' : 'включён', () => api('PUT', `api/v1/users/${id}`, body({ status: u.status === 'active' ? 'disabled' : 'active' })));
      if (a === '4') {
        const gb = await ask(`Трафик в месяц, ГБ [${u.traffic_limit_gb ?? '∞'}] (пусто — без изменений, - — без лимита):`);
        const days = await ask(`Продлить на N дней от сегодня (пусто — без изменений, - — бессрочно):`);
        const patch: Record<string, unknown> = {};
        if (gb) patch.trafficLimitGb = gb === '-' ? null : Number(gb);
        if (days) patch.expireAt = days === '-' ? null : new Date(Date.now() + Number(days) * 86400_000).toISOString();
        await act('лимиты сохранены', () => api('PUT', `api/v1/users/${id}`, body(patch)));
      }
      if (a === '5') await act('токен подписки сменён', () => api('POST', `api/v1/users/${id}/rotate`, { what: 'sub' }));
      if (a === '6' && await confirm('Перевыпустить ссылки?')) await act('ссылки перевыпущены', () => api('POST', `api/v1/users/${id}/rotate`, { what: 'links' }));
      if (a === '7' && await confirm(`Удалить ${u.name}?`)) { await api('DELETE', `api/v1/users/${id}`); p(tag('удалён', 'ok')); await pause(); return; }
    } catch (e) { p(`${C.err}✗ ${(e as Error).message}${C.x}`); }
    await pause();
  }
}

async function configs() {
  for (;;) {
    const list = await api<any[]>('GET', 'api/v1/templates');
    const srv = await api<any[]>('GET', 'api/v1/servers');
    const nameOf = (sid: string) => srv.find((s) => s.id === sid)?.name ?? sid;
    title('Конфигурации');
    list.forEach((t, i) => p(`  ${C.acc}${pad(i + 1 + ')', 4)}${C.x} ${pad(C.b + t.name + C.x, 20)} ${pad(t.protocol === 'hysteria2' ? 'Hysteria2' : 'VLESS·REALITY', 15)} :${pad(String(t.port), 6)} ${t.inbounds.filter((x: any) => x.state === 'active').length} активно · ревизия ${t.revision}${t.applied_revision < t.revision ? tag(' · не выкачена', 'warn') : ''}`));
    if (!list.length) p(`  ${C.dim}шаблонов нет — создайте в веб-панели (раздел «Конфигурации»)${C.x}`);
    p(`  ${C.dim}0)  Назад${C.x}`);
    const a = await ask('Выберите:');
    if (a === '0' || a === '') return;
    const t = list[Number(a) - 1];
    if (!t) continue;
    title(`Шаблон ${t.name}`);
    p(`  узлы: ${t.node_ids.map(nameOf).join(', ') || '—'}${t.entry_id ? ` · вход: ${nameOf(t.entry_id)} :${t.entry_port}` : ''}`);
    for (const ib of t.inbounds) p(`  ${pad(nameOf(ib.server_id), 12)} ${pad(ib.kind, 7)} :${pad(String(ib.port), 6)} ${ib.state === 'active' ? tag(ib.state, 'ok') : ib.state === 'error' ? tag(ib.state, 'err') : tag(ib.state, 'warn')}${ib.error ? C.dim + ' ' + ib.error + C.x : ''}`);
    const c = await choose([['1', 'Выкатить (canary → остальные → вход)'], ['2', 'Показать рендер конфига']]);
    try {
      if (c === '1') { const r = await api('POST', `api/v1/templates/${t.id}/rollout`); await followJob(r.jobId); }
      if (c === '2') { const r = await api('GET', `api/v1/templates/${t.id}/preview`); p(r.config ?? 'конфиг появится после выката'); }
    } catch (e) { p(`${C.err}✗ ${(e as Error).message}${C.x}`); }
    if (c) await pause();
  }
}

async function cores() {
  for (;;) {
    const d = await api('GET', 'api/v1/cores');
    title('Ядра');
    p(`  последние стабильные: Xray ${C.b}${d.latest.xray ?? '?'}${C.x} · sing-box ${C.b}${d.latest['sing-box'] ?? '?'}${C.x}`);
    for (const e of d.errors) p(`  ${tag('GitHub недоступен: ' + e, 'warn')}`);
    for (const s of d.servers) {
      const x = s.mode === 'xui' ? `Xray 3x-ui ${s.xui?.version ?? '?'}` : `Xray ${s.xray?.version ?? '—'}`;
      p(`  ${pad(C.b + s.name + C.x, 14)} ${pad(x, 24)} sing-box ${s.singbox?.version ?? '—'} ${s.outdated.length ? tag('устарел: ' + s.outdated.join(', '), 'warn') : ''}`);
    }
    const a = await choose([['1', 'Обновить Xray на всех узлах'], ['2', 'Обновить sing-box на всех узлах'], ['3', 'Закрепить версию для новых узлов']]);
    if (!a) return;
    try {
      if (a === '1' || a === '2') {
        const core = a === '1' ? 'xray' : 'sing-box';
        const ver = (await ask(`Версия ${core} (Enter — ${d.latest[core] ?? 'последняя'}):`)) || 'latest';
        if (await confirm(`Обновить ${core} до ${ver}: canary → остальные, первая ошибка останавливает?`)) {
          const r = await api('POST', `api/v1/cores/${core}/rollout`, { version: ver });
          await followJob(r.jobId);
        }
      }
      if (a === '3') {
        const core = (await choose([['1', 'Xray'], ['2', 'sing-box']])) === '2' ? 'sing-box' : 'xray';
        const ver = (await ask('Версия (latest — всегда последняя):')) || 'latest';
        await act('закреплено', () => api('PUT', 'api/v1/cores/pin', { core, version: ver }));
      }
    } catch (e) { p(`${C.err}✗ ${(e as Error).message}${C.x}`); }
    await pause();
  }
}

async function backups() {
  for (;;) {
    const list = await api<any[]>('GET', 'api/v1/backups');
    title('Бэкапы');
    for (const b of list.slice(0, 15)) {
      const det = (() => { try { return JSON.parse(b.detail ?? '{}'); } catch { return {}; } })();
      p(`  ${b.created_at} · ${pad(b.profile, 7)} · ${b.size ? bytes(b.size) : '—'} · ${b.status === 'ok' ? tag('доставлен ' + (det.delivered ?? '') + '/' + (det.total ?? ''), 'ok') : tag(b.status, 'warn')}`);
    }
    if (!list.length) p(`  ${C.dim}бэкапов ещё не было${C.x}`);
    const a = await choose([['1', 'Сделать бэкап сейчас']]);
    if (!a) return;
    if (a === '1') { await act('бэкап создан', () => api('POST', 'api/v1/backups/run')); await pause(); }
  }
}

async function audit() {
  const d = await api('GET', 'api/v1/audit');
  title('Аудит');
  p(d.chain.ok ? tag('цепочка хэшей цела', 'ok') : tag(`цепочка нарушена на записи #${d.chain.brokenAt}`, 'err'));
  for (const a of d.items.slice(0, 25)) p(`  ${C.dim}${a.ts.replace('T', ' ').slice(0, 16)}${C.x} ${pad(a.actor, 18)} ${pad(a.action, 26)} ${a.target ?? ''}`);
  await pause();
}

const SECTIONS: Record<string, () => Promise<void>> = { overview, servers, users, configs, cores, backups, audit };

async function main() {
  const only = process.argv[2];
  if (only) {
    if (!SECTIONS[only]) throw new Error(`нет раздела ${only}`);
    await SECTIONS[only]!();
    return;
  }
  for (;;) {
    title('Эскадра — управление флотом');
    const a = await choose([['1', 'Обзор'], ['2', 'Серверы'], ['3', 'Пользователи'], ['4', 'Конфигурации'], ['5', 'Ядра'], ['6', 'Бэкапы'], ['7', 'Аудит']], 'Выход');
    if (!a) return;
    const fn = [overview, servers, users, configs, cores, backups, audit][Number(a) - 1];
    if (fn) await fn().catch(async (e) => { p(`${C.err}✗ ${(e as Error).message}${C.x}`); await pause(); });
  }
}

main()
  .catch((e) => { p(`${C.err}✗ ${(e as Error).message}${C.x}`); process.exitCode = 1; })
  .finally(() => { rl.close(); cleanup(); });
