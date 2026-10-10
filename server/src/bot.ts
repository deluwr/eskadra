import type { FastifyBaseLogger } from 'fastify';
import type { Ctx, UserRow } from './ctx.js';
import { getSetting } from './db.js';
import { Vpn } from './vpn.js';
import { subBase } from './routes/users.js';

const PART = 45 * 1024 * 1024;

/**
 * Telegram-бот (§14): long polling — входящий порт не нужен. Бот не ходит в БД напрямую за чужими данными:
 * отвечает только админам (по tg_id из «Права и роли») и пользователям VPN (по tg_id пользователя).
 */
export class Bot {
  private running = false;
  private offset = 0;
  private abort: AbortController | null = null;
  onBackupRequest: (() => Promise<string>) | null = null;

  constructor(private readonly ctx: Ctx, private readonly log: FastifyBaseLogger) {}

  token(): string | null {
    const sealed = getSetting<string>(this.ctx.db, 'bot.token', '');
    return sealed ? this.ctx.open(sealed) : null;
  }

  private async api(method: string, body: Record<string, unknown> | FormData, signal?: AbortSignal) {
    const t = this.token();
    if (!t) throw new Error('токен бота не задан');
    const res = await fetch(`https://api.telegram.org/bot${t}/${method}`, {
      method: 'POST',
      ...(body instanceof FormData ? { body } : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
      signal: signal ?? AbortSignal.timeout(60_000),
    });
    const data = (await res.json()) as { ok: boolean; result?: unknown; description?: string };
    if (!data.ok) throw new Error(`Telegram ${method}: ${data.description ?? res.status}`);
    return data.result;
  }

  async getMe(): Promise<{ username: string }> {
    return (await this.api('getMe', {})) as { username: string };
  }

  async send(chatId: string, text: string) {
    await this.api('sendMessage', { chat_id: chatId, text, disable_web_page_preview: true });
  }

  async notifyAdmins(text: string) {
    if (!this.token()) return;
    const ids = this.ctx.db.prepare(`SELECT tg_id FROM admins WHERE tg_id IS NOT NULL`).all() as Array<{ tg_id: string }>;
    for (const a of ids) await this.send(a.tg_id, text).catch(() => undefined);
  }

  /** Отправить зашифрованный бэкап всем админам-получателям; большие файлы — частями. */
  async sendBackup(name: string, data: Buffer): Promise<{ ok: number; total: number; errors: string[] }> {
    const ids = this.ctx.db.prepare(`SELECT username, tg_id FROM admins WHERE backup_recipient = 1 AND tg_id IS NOT NULL`).all() as Array<{ username: string; tg_id: string }>;
    if (!this.token() || !ids.length) return { ok: 0, total: 0, errors: this.token() ? ['нет получателей с Telegram ID'] : ['бот не настроен'] };
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
          fd.set('document', new Blob([new Uint8Array(p)]),parts.length > 1 ? `${name}.part${i + 1}` : name);
          await this.api('sendDocument', fd, AbortSignal.timeout(300_000));
        }
        ok++;
      } catch (e) {
        errors.push(`${a.username}: ${(e as Error).message}`);
      }
    }
    return { ok, total: ids.length, errors };
  }

  start() {
    if (this.running || !this.token()) return;
    this.running = true;
    void this.loop();
  }

  stop() {
    this.running = false;
    this.abort?.abort();
  }

  restart() { this.stop(); setTimeout(() => this.start(), 500); }

  private async loop() {
    while (this.running) {
      try {
        this.abort = new AbortController();
        const updates = (await this.api('getUpdates', { offset: this.offset, timeout: 50, allowed_updates: ['message'] },
          AbortSignal.any([this.abort.signal, AbortSignal.timeout(65_000)]))) as Array<{ update_id: number; message?: { chat: { id: number }; from?: { id: number }; text?: string } }>;
        for (const u of updates) {
          this.offset = u.update_id + 1;
          if (u.message?.text) await this.handle(String(u.message.chat.id), String(u.message.from?.id ?? ''), u.message.text).catch((e) => this.log.warn(`bot: ${(e as Error).message}`));
        }
      } catch (e) {
        if (!this.running) break;
        this.log.warn(`bot poll: ${(e as Error).message}`);
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }

  private async handle(chatId: string, fromId: string, text: string) {
    const cmd = text.trim().split(/\s+/)[0]!.replace(/@.*$/, '').toLowerCase();
    const admin = this.ctx.db.prepare('SELECT username, role FROM admins WHERE tg_id = ?').get(fromId) as { username: string; role: string } | undefined;
    const user = this.ctx.db.prepare('SELECT * FROM users WHERE tg_id = ?').get(fromId) as UserRow | undefined;

    if (cmd === '/start') {
      const who = admin ? `админ ${admin.username}` : user ? `пользователь ${user.name}` : 'не привязан';
      return this.send(chatId, `Эскадра. Ваш Telegram ID: ${fromId} (${who}).\nАдмину: укажите этот ID в «Права и роли». Пользователю: его указывает администратор.`);
    }
    if (admin) {
      if (cmd === '/status') {
        const rows = this.ctx.servers().map((s) => `${s.fail_since ? '🔴' : '🟢'} ${s.name} · ${s.role} · ${s.protection_current}/${s.protection_target} · ${s.fw_mode}`);
        return this.send(chatId, rows.join('\n') || 'серверов нет');
      }
      if (cmd === '/backup' && this.onBackupRequest) return this.send(chatId, await this.onBackupRequest());
    }
    if (user) {
      const base = subBase(this.ctx);
      if (cmd === '/sub') return this.send(chatId, base ? `Подписка:\n${base}/s/${user.sub_token}` : 'Сервис подписок не настроен');
      if (cmd === '/access') return this.send(chatId, base ? `Откройте с телефона БЕЗ VPN, чтобы открыть доступ:\n${base}/k/${user.knock_token}` : 'Сервис подписок не настроен');
      if (cmd === '/links') {
        const vpn = new Vpn(this.ctx);
        const links = vpn.profiles(user).map((p) => `${p.name}:\n${vpn.link(user, p)}`);
        return this.send(chatId, links.join('\n\n') || 'нет доступных профилей');
      }
    }
    return this.send(chatId, admin ? 'Команды: /status /backup' : user ? 'Команды: /sub /links /access' : 'Нет доступа. /start покажет ваш ID.');
  }
}
