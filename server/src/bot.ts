import { randomBytes } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import type { Ctx, UserRow } from './ctx.js';
import { getSetting } from './db.js';
import { effectiveLimits, period, Vpn } from './vpn.js';
import { subBase } from './routes/users.js';
import { ProxyAgent, type Dispatcher } from 'undici';
import { activeBotProxy } from './botproxy.js';
import { attentionOf } from './attention.js';
import { audit } from './lib/audit.js';
import { Ops } from './ops.js';
import { AdminFlows, cb, esc, helpText, subMessage, type AdminRow, type Button, type Kb, type NotifyCat, type Screen } from './botadmin.js';
import { can as canRole, roleOf } from './roles.js';
import { json } from './vpn.js';

const PART = 45 * 1024 * 1024;
const BIND_TTL = 15 * 60_000;

interface Bind { kind: 'admin' | 'user'; id: string; exp: number; boundTo?: string }
interface TgUpdate {
  update_id: number;
  message?: { message_id: number; chat: { id: number; type: string }; from?: { id: number }; text?: string };
  callback_query?: { id: string; from: { id: number }; data?: string; message?: { message_id: number; chat: { id: number; type: string } } };
}

const gb = (b: number) => `${(b / 1024 ** 3).toFixed(1)} ГБ`;
/** Флаг страны по коду ISO (FI → 🇫🇮). */
const flag = (cc: string) => String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));

/**
 * Telegram-бот (§14): long polling — входящий порт не нужен. Отвечает только в личных чатах и только тем, чей
 * Telegram привязан: админам (по tg_id из «Права и роли») и пользователям VPN. Незнакомцу бот показывает лишь его
 * собственный ID — ни названия панели, ни логинов, ни серверов. Привязка — одноразовой ссылкой из панели.
 */
export class Bot {
  private running = false;
  private offset = 0;
  private abort: AbortController | null = null;
  private me: string | null = null;
  private binds = new Map<string, Bind>();
  onBackupRequest: (() => Promise<string>) | null = null;
  private readonly flows: AdminFlows;
  private adminCommandsSet = new Set<string>();

  constructor(private readonly ctx: Ctx, private readonly log: FastifyBaseLogger) {
    this.flows = new AdminFlows(ctx, {
      show: (c, sc, m) => this.show(c, sc, m),
      send: (c, t, kb) => this.send(c, t, kb),
      drop: (c, m) => this.api('deleteMessage', { chat_id: c, message_id: m }).then(() => undefined, () => undefined),
    });
  }

  token(): string | null {
    const sealed = getSetting<string>(this.ctx.db, 'bot.token', '');
    return sealed ? this.ctx.open(sealed) : null;
  }

  private agent: { port: number; d: Dispatcher } | null = null;

  /** Через прокси бота (если включён): HTTP-прокси Xray-клиента на 127.0.0.1. */
  private async dispatcher(): Promise<Dispatcher | undefined> {
    const p = activeBotProxy(this.ctx);
    if (!p) return undefined;
    await this.ctx.mgmt?.ensure();
    if (this.agent?.port !== p.setting.port) this.agent = { port: p.setting.port, d: new ProxyAgent(`http://127.0.0.1:${p.setting.port}`) };
    return this.agent.d;
  }

  /** Проверка доступа к Telegram: напрямую и (если включён) через прокси. */
  async probe(): Promise<{ direct: string; proxy: string | null }> {
    const ping = async (d?: Dispatcher) => {
      try {
        const r = await fetch('https://api.telegram.org/', { ...(d ? { dispatcher: d } : {}), signal: AbortSignal.timeout(10_000) } as RequestInit);
        return `доступен (HTTP ${r.status})`;
      } catch (e) { return `недоступен: ${((e as Error).cause as Error | undefined)?.message ?? (e as Error).message}`; }
    };
    const d = await this.dispatcher().catch(() => undefined);
    return { direct: await ping(), proxy: activeBotProxy(this.ctx) ? (d ? await ping(d) : 'прокси не запустился') : null };
  }

  private async api(method: string, body: Record<string, unknown> | FormData, signal?: AbortSignal) {
    const t = this.token();
    if (!t) throw new Error('токен бота не задан');
    const dispatcher = await this.dispatcher();
    const res = await fetch(`https://api.telegram.org/bot${t}/${method}`, {
      ...(dispatcher ? { dispatcher } : {}),
      method: 'POST',
      ...(body instanceof FormData ? { body } : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
      signal: signal ?? AbortSignal.timeout(60_000),
    });
    const data = (await res.json()) as { ok: boolean; result?: unknown; description?: string };
    if (!data.ok) throw new Error(`Telegram ${method}: ${data.description ?? res.status}`);
    return data.result;
  }

  async getMe(): Promise<{ username: string }> {
    const r = (await this.api('getMe', {})) as { username: string };
    this.me = r.username;
    return r;
  }

  async send(chatId: string, text: string, kb?: Kb) {
    await this.api('sendMessage', { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true, ...(kb ? { reply_markup: { inline_keyboard: kb } } : {}) });
  }

  private async show(chatId: string, s: Screen, messageId?: number) {
    const body = { chat_id: chatId, text: s.text, parse_mode: 'HTML', disable_web_page_preview: true, reply_markup: { inline_keyboard: s.kb ?? [] } };
    if (messageId === undefined) return void (await this.api('sendMessage', body));
    // «message is not modified» — экран не изменился (повторное нажатие «Обновить»): не ошибка
    await this.api('editMessageText', { ...body, message_id: messageId }).catch((e: Error) => { if (!/not modified/.test(e.message)) throw e; });
  }

  /** Уведомление админам; cat — категория, которую админ может выключить у себя (/notify). Пользователям не шлётся. */
  async notifyAdmins(text: string, kb?: Kb, cat?: NotifyCat) {
    if (!this.token()) return;
    const ids = this.ctx.db.prepare(`SELECT tg_id, notify_off FROM admins WHERE tg_id IS NOT NULL`).all() as Array<{ tg_id: string; notify_off: string }>;
    for (const a of ids) {
      if (cat && json<string[]>(a.notify_off, []).includes(cat)) continue;
      await this.send(a.tg_id, esc(text), kb).catch(() => undefined);
    }
  }

  /** Отправить зашифрованный бэкап всем админам-получателям; большие файлы — частями. */
  async sendBackup(name: string, data: Buffer): Promise<{ ok: number; total: number; errors: string[] }> {
    const ids = this.ctx.db.prepare(`SELECT username, tg_id FROM admins WHERE backup_recipient = 1 AND tg_id IS NOT NULL`).all() as Array<{ username: string; tg_id: string }>;
    if (!this.token() || !ids.length) return { ok: 0, total: 0, errors: this.token() ? ['нет получателей с привязанным Telegram'] : ['бот не настроен'] };
    const parts: Buffer[] = [];
    for (let i = 0; i < data.length; i += PART) parts.push(data.subarray(i, i + PART));
    let ok = 0;
    const errors: string[] = [];
    for (const a of ids) {
      try {
        for (const [i, p] of parts.entries()) {
          const fd = new FormData();
          fd.set('chat_id', a.tg_id);
          fd.set('caption', parts.length > 1 ? `${name} · часть ${i + 1}/${parts.length}` : `Бэкап Эскадры · ${name}`);
          fd.set('document', new Blob([new Uint8Array(p)]), parts.length > 1 ? `${name}.part${i + 1}` : name);
          await this.api('sendDocument', fd, AbortSignal.timeout(300_000));
        }
        ok++;
      } catch (e) {
        errors.push(`${a.username}: ${(e as Error).message}`);
      }
    }
    return { ok, total: ids.length, errors };
  }

  // ───── привязка Telegram одноразовой ссылкой ─────

  /** Ссылка t.me/<бот>?start=<код>: человек открывает её и нажимает «Старт» — бот запоминает его Telegram. */
  async bindLink(kind: Bind['kind'], id: string): Promise<{ code: string; url: string; expiresAt: string }> {
    if (!this.token()) throw new Error('бот не настроен — задайте токен в «Настройках»');
    const name = this.me ?? (await this.getMe()).username;
    const now = Date.now();
    for (const [k, b] of this.binds) if (b.exp < now || (b.kind === kind && b.id === id && !b.boundTo)) this.binds.delete(k);
    const code = randomBytes(12).toString('base64url');
    this.binds.set(code, { kind, id, exp: now + BIND_TTL });
    return { code, url: `https://t.me/${name}?start=${code}`, expiresAt: new Date(now + BIND_TTL).toISOString() };
  }

  bindState(code: string): 'pending' | 'bound' | 'expired' {
    const b = this.binds.get(code);
    if (!b) return 'expired';
    if (b.boundTo) return 'bound';
    return b.exp < Date.now() ? 'expired' : 'pending';
  }

  private bind(code: string, tgId: string): string {
    const b = this.binds.get(code);
    if (!b || b.boundTo || b.exp < Date.now()) return 'Ссылка устарела или уже использована. Попросите новую.';
    const db = this.ctx.db;
    if (b.kind === 'admin') {
      db.prepare('UPDATE admins SET tg_id = NULL WHERE tg_id = ? AND id != ?').run(tgId, Number(b.id));
      db.prepare('UPDATE admins SET tg_id = ? WHERE id = ?').run(tgId, Number(b.id));
    } else {
      db.prepare('UPDATE users SET tg_id = ? WHERE id = ?').run(tgId, b.id);
    }
    b.boundTo = tgId;
    audit(db, 'bot', b.kind === 'admin' ? 'admin.tg_bound' : 'user.tg_bound', b.id);
    return 'Telegram привязан.';
  }

  // ───── цикл ─────

  start() {
    if (this.running || !this.token()) return;
    this.running = true;
    // общий список команд — без админских: незнакомец не узнаёт, чем управляет бот
    void this.api('setMyCommands', { commands: [{ command: 'menu', description: 'Меню' }, { command: 'help', description: 'Справка' }] }).catch(() => undefined);
    void this.loop();
  }

  stop() {
    this.running = false;
    this.abort?.abort();
  }

  restart() { this.stop(); this.me = null; setTimeout(() => this.start(), 500); }

  private async loop() {
    while (this.running) {
      try {
        this.abort = new AbortController();
        const updates = (await this.api('getUpdates', { offset: this.offset, timeout: 50, allowed_updates: ['message', 'callback_query'] },
          AbortSignal.any([this.abort.signal, AbortSignal.timeout(65_000)]))) as TgUpdate[];
        for (const u of updates) {
          this.offset = u.update_id + 1;
          const job = u.message?.text && u.message.chat.type === 'private'
            ? this.onMessage(String(u.message.chat.id), String(u.message.from?.id ?? ''), u.message.text, u.message.message_id)
            : u.callback_query ? this.onCallback(u.callback_query) : null;
          await job?.catch((e) => this.log.warn(`bot: ${(e as Error).message}`));
        }
      } catch (e) {
        if (!this.running) break;
        this.log.warn(`bot poll: ${(e as Error).message}`);
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }

  private who(tgId: string) {
    const admin = this.ctx.db.prepare('SELECT id, username, role FROM admins WHERE tg_id = ?').get(tgId) as AdminRow | undefined;
    const user = this.ctx.db.prepare('SELECT * FROM users WHERE tg_id = ?').get(tgId) as UserRow | undefined;
    return { admin, user };
  }

  private async onMessage(chatId: string, fromId: string, text: string, messageId: number) {
    const [head, arg] = text.trim().split(/\s+/);
    const cmd = head!.replace(/@.*$/, '').toLowerCase();
    if (cmd === '/start' && arg) await this.send(chatId, this.bind(arg, fromId));
    const { admin, user } = this.who(fromId);
    // незнакомцу — только его ID для привязки; ничего о панели, серверах и командах
    if (!admin && !user) return this.send(chatId, `Ваш Telegram ID: <code>${fromId}</code>\nПередайте его тому, кто выдаёт вам доступ.`);
    if (admin) {
      void this.adminCommands(chatId);
      if (await this.flows.onText(chatId, admin, text, messageId)) return;
      if (cmd === '/help') return this.show(chatId, { text: helpText('admin', admin.role, roleOf(this.ctx.db, admin.role)), kb: [[cb('Меню', 'm')]] });
      if (!user || !['/sub', '/links'].includes(cmd)) return this.show(chatId, this.adminMenu());
    }
    if (cmd === '/help') return this.send(chatId, helpText('user'));
    if (cmd === '/sub') return this.send(chatId, subMessage(this.ctx, user!));
    if (cmd === '/links') return this.show(chatId, this.linksScreen(user!));
    return this.show(chatId, this.userMenu(user!));
  }

  /** Админу — полный список команд в его чате (у остальных видны только /menu и /help). */
  private async adminCommands(chatId: string) {
    if (this.adminCommandsSet.has(chatId)) return;
    this.adminCommandsSet.add(chatId);
    await this.api('setMyCommands', {
      scope: { type: 'chat', chat_id: Number(chatId) },
      commands: [['menu', 'Меню'], ['users', 'Пользователи'], ['adduser', 'Добавить пользователя'], ['servers', 'Серверы'], ['addserver', 'Подключить сервер'], ['notify', 'Уведомления'], ['help', 'Справка'], ['cancel', 'Прервать ввод']]
        .map(([command, description]) => ({ command, description })),
    }).catch(() => this.adminCommandsSet.delete(chatId));
  }

  private linksScreen(u: UserRow): Screen {
    const ps = new Vpn(this.ctx).profiles(u);
    if (!ps.length) return { text: 'Профилей пока нет.', kb: [[cb('‹ Меню', 'm')]] };
    return { text: 'Выберите профиль — пришлю ссылку для импорта:', kb: [...ps.slice(0, 40).map((p, i) => [cb(p.name, `l:${i}`)]), [cb('‹ Меню', 'm')]] };
  }

  private async onCallback(q: NonNullable<TgUpdate['callback_query']>) {
    const chat = q.message?.chat;
    if (!chat || chat.type !== 'private' || !q.data) return this.api('answerCallbackQuery', { callback_query_id: q.id });
    const chatId = String(chat.id);
    const mid = q.message!.message_id;
    const { admin, user } = this.who(String(q.from.id));
    const [act0, ...args] = q.data.split(':');
    const act = act0 === 'srv' ? 'sl' : act0!;   // старые кнопки «Серверы»
    const arg = args[0];
    const toast = (text?: string) => this.api('answerCallbackQuery', { callback_query_id: q.id, ...(text ? { text } : {}) }).catch(() => undefined);
    if (!admin && !user) {
      await toast('Нет доступа');
      return this.show(chatId, { text: 'Доступ к этому чату отозван.' }, mid);
    }
    if (admin) {
      if (await this.flows.onButton(chatId, mid, admin, act, args, toast)) return;
      const canBackup = canRole(roleOf(this.ctx.db, admin.role), 'backups.run');
      switch (act) {
        case 'm': await toast(); return this.show(chatId, this.adminMenu(), mid);
        case 'att': await toast(); return this.show(chatId, this.attentionScreen(), mid);
        case 'ex': await toast(); return this.show(chatId, this.exitsScreen(), mid);
        case 'exc': {
          const t = new Vpn(this.ctx).template(arg ?? '');
          if (!t) return toast('Конфигурация не найдена');
          await toast('Проверяю выходы…');
          await this.show(chatId, { text: `Проверяю выходы «${esc(t.name)}»…` }, mid);
          const r = await new Ops(this.ctx).checkExits(t, () => undefined).catch((e: Error) => ({ error: e.message }));
          audit(this.ctx.db, admin.username, 'template.exits_check', t.id, { via: 'bot' });
          const s = this.exitsScreen();
          if (r && 'error' in r) s.text = `Проверка не удалась: ${esc(r.error)}\n\n${s.text}`;
          return this.show(chatId, s, mid);
        }
        case 'bk':
          await toast();
          if (!canBackup) return this.show(chatId, { text: 'Бэкап запускают owner и admin.', kb: [[cb('‹ Меню', 'm')]] }, mid);
          return this.show(chatId, { text: 'Создать бэкап сейчас и отправить его получателям?', kb: [[cb('Создать бэкап', 'bkgo'), cb('Отмена', 'm')]] }, mid);
        case 'bkgo': {
          if (!canBackup || !this.onBackupRequest) return toast('Нет доступа');
          await toast('Бэкап запущен');
          await this.show(chatId, { text: 'Создаю бэкап…' }, mid);
          return this.show(chatId, { text: esc(await this.onBackupRequest()), kb: [[cb('‹ Меню', 'm')]] }, mid);
        }
      }
    }
    if (user) {
      const base = subBase(this.ctx);
      switch (act) {
        case 'm': await toast(); return this.show(chatId, this.userMenu(user), mid);
        case 'sub':
          await toast();
          return this.show(chatId, { text: base ? `Ссылка подписки — добавьте её в приложение:\n<code>${esc(`${base}/s/${user.sub_token}`)}</code>` : 'Подписки пока не настроены.', kb: [[cb('‹ Меню', 'm')]] }, mid);
        case 'knock':
          await toast();
          return this.show(chatId, { text: base ? `Откройте ссылку с телефона <b>без VPN</b> — так сервер узнает ваш адрес:\n${esc(`${base}/k/${user.knock_token}`)}` : 'Подписки пока не настроены.', kb: [[cb('‹ Меню', 'm')]] }, mid);
        case 'lk': await toast(); return this.show(chatId, this.linksScreen(user), mid);
        case 'l': {
          const vpn = new Vpn(this.ctx);
          const p = vpn.profiles(user)[Number(arg)];
          if (!p) return toast('Профиль не найден — откройте список заново');
          await toast();
          // ссылку — отдельным сообщением, чтобы её было удобно скопировать и она не пропала при смене экрана
          return this.send(chatId, `<b>${esc(p.name)}</b>\n<code>${esc(vpn.link(user, p))}</code>`);
        }
      }
    }
    return toast();
  }

  // ───── экраны ─────

  private adminMenu(): Screen {
    const servers = this.ctx.servers();
    const online = servers.filter((s) => s.last_seen_at && !s.fail_since).length;
    const att = attentionOf(this.ctx, new Vpn(this.ctx));
    const head = servers.length ? `Серверов на связи: <b>${online} из ${servers.length}</b>` : 'Серверов пока нет.';
    return {
      text: `${head}\n${att.length ? `Требует внимания: <b>${att.length}</b>` : 'Всё в порядке.'}`,
      kb: [
        [cb('Серверы', 'sl'), cb('Пользователи', 'ul:0')],
        [cb(att.length ? `Внимание · ${att.length}` : 'Внимание', 'att'), cb('Выходы «Авто»', 'ex')],
        [cb('Бэкап', 'bk'), cb('Уведомления', 'nt')],
        [cb('Справка', 'h'), cb('Обновить', 'm')],
      ],
    };
  }

  private attentionScreen(): Screen {
    const icon = { fail: '🔴', warn: '🟠', info: '🔵' } as const;
    const att = attentionOf(this.ctx, new Vpn(this.ctx));
    return {
      text: att.map((a) => `${icon[a.level]} <b>${esc(a.title)}</b>${a.detail ? `\n${esc(a.detail)}` : ''}`).join('\n\n') || 'Всё в порядке.',
      kb: [[cb('‹ Меню', 'm'), cb('Обновить', 'att')]],
    };
  }

  private exitsScreen(): Screen {
    const vpn = new Vpn(this.ctx);
    const db = this.ctx.db;
    const ts = vpn.templates().filter((t) => t.entry_id && vpn.spec(t).autoMode !== 'random');
    if (!ts.length) return { text: 'Нет конфигураций со входом, где «Авто» выбирает выход по качеству или по порядку.', kb: [[cb('‹ Меню', 'm')]] };
    const blocks = ts.map((t) => {
      const rows = db.prepare(`SELECT h.exit_id, s.name, h.rtt_ms, h.mbps, h.ok, h.exit_ip, h.exit_loc FROM exit_health h JOIN servers s ON s.id = h.exit_id WHERE h.template_id = ?`).all(t.id) as Array<{ exit_id: string; name: string; rtt_ms: number | null; mbps: number | null; ok: number; exit_ip: string | null; exit_loc: string | null }>;
      const ov = getSetting<string | null>(db, `auto.actual.${t.id}`, null) ?? getSetting<string | null>(db, `auto.override.${t.id}`, null);
      const sel = ov?.slice(`to-${t.id}-`.length);
      const list = rows.map((r) => `${r.ok ? '🟢' : '🔴'} ${esc(r.name)}${r.exit_id === sel ? ' ← ведёт трафик' : ''}: ${r.ok || r.rtt_ms !== null ? `${r.rtt_ms ?? '—'} мс${r.mbps !== null ? `, ${r.mbps} Мбит/с` : ''}` : 'не отвечает'}${r.exit_ip ? `
    выход: <code>${esc(r.exit_ip)}</code>${r.exit_loc ? ` ${flag(r.exit_loc)} ${r.exit_loc}` : ''}` : ''}`);
      return `<b>${esc(t.name)}</b>\n${list.join('\n') || 'проверок ещё не было'}`;
    });
    return { text: blocks.join('\n\n'), kb: [...ts.map((t) => [cb(`Проверить «${t.name}»`, `exc:${t.id}`)]), [cb('‹ Меню', 'm'), cb('Обновить', 'ex')]] };
  }

  private userMenu(u: UserRow): Screen {
    const lim = effectiveLimits(this.ctx, u);
    const t = this.ctx.db.prepare('SELECT up, down FROM traffic WHERE user_id = ? AND period = ?').get(u.id, period()) as { up: number; down: number } | undefined;
    const used = (t?.up ?? 0) + (t?.down ?? 0);
    const lines = [
      `<b>${esc(u.name)}</b> — ${u.status === 'active' ? 'доступ активен' : 'доступ приостановлен'}`,
      `Трафик за месяц: ${gb(used)}${lim.trafficGb ? ` из ${lim.trafficGb} ГБ` : ''}`,
      ...(lim.expireAt ? [`Действует до ${lim.expireAt.slice(0, 10)}`] : []),
    ];
    const wl = !!this.ctx.db.prepare(`SELECT 1 FROM groups WHERE stealth IN ('S3','S4')`).get();
    return {
      text: lines.join('\n'),
      kb: [[cb('Подписка', 'sub'), cb('Ссылки на профили', 'lk')], ...(wl ? [[cb('Открыть доступ с нового адреса', 'knock')]] : []), [cb('Обновить', 'm')]],
    };
  }
}
