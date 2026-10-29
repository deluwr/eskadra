/**
 * Управление флотом из Telegram для owner, admin и operator: пользователи VPN (добавить по Telegram ID,
 * подписка и ссылки, серверы, включить/отключить, удалить), серверы (подключить по логину и паролю или ключу,
 * уровень защиты, ядра), личные уведомления и справка. Права — те же, что в панели (матрица «Права и роли»).
 */
import type { Ctx, ServerRow, UserRow } from './ctx.js';
import { getSetting } from './db.js';
import { audit } from './lib/audit.js';
import { Ops, coresOff } from './ops.js';
import { effectiveLimits, json, period, Vpn } from './vpn.js';
import { saveUser, subBase, userBody } from './routes/users.js';
import { createBody, createServer } from './routes/servers.js';
import { can as canRole, inScope, roleOf, type Perm, type RoleInfo } from './roles.js';
import { botProxyOptions } from './botproxy.js';

export type Button = { text: string; callback_data?: string; url?: string };
export type Kb = Button[][];
export interface Screen { text: string; kb?: Kb }
export interface AdminRow { id: number; username: string; role: string }

export const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
export const cb = (text: string, data: string): Button => ({ text, callback_data: data });
const gb = (b: number) => `${(b / 1024 ** 3).toFixed(1)} ГБ`;
const back = (data: string, text = '‹ Назад'): Button => cb(text, data);

/** Категории уведомлений админам: каждый выбирает свои (в боте и в панели). */
export const NOTIFY: Record<string, string> = {
  down: 'Связь с серверами',
  auto: 'Переключения «Авто»',
  certs: 'TLS-сертификаты',
  cores: 'Новые версии ядер',
  users: 'Лимиты пользователей',
  billing: 'Оплата серверов',
};
export type NotifyCat = keyof typeof NOTIFY;

const LEVEL: Record<string, string> = { P1: 'обычная', P2: 'средняя', P3: 'высокая' };
const PAGE = 8;

/** Пошаговый ввод (добавить пользователя или сервер): ждём следующее сообщение в этом чате. */
interface Flow {
  kind: 'user' | 'server';
  step: string;
  data: Record<string, string>;
  exp: number;
}

export interface BotIO {
  show(chatId: string, s: Screen, messageId?: number): Promise<void>;
  send(chatId: string, text: string, kb?: Kb): Promise<void>;
  drop(chatId: string, messageId: number): Promise<void>;
}

export function helpText(role: 'admin' | 'user' | null, adminRole?: string, info?: RoleInfo): string {
  if (role === 'user') return [
    '<b>Что умеет бот</b>',
    '/menu — ваш доступ: статус, трафик, срок',
    '/sub — ссылка подписки для приложения',
    '/links — отдельные ссылки на профили',
    '/help — эта справка',
    '',
    'Подписку добавьте в приложение (Hiddify, v2rayNG, Happ, Streisand): оно само обновит список серверов. Ссылку подписки никому не пересылайте.',
  ].join('\n');
  const lines = [
    `<b>Команды</b> · роль ${info?.name ?? adminRole}`,
    '/menu — состояние флота и всё управление кнопками',
    '/users — пользователи: подписка, ссылки, серверы, включить/отключить',
    '/adduser — добавить пользователя (можно сразу: <code>/adduser имя 123456789</code>, число — его Telegram ID)',
    '/servers — серверы: состояние, защита, ядра',
  ];
  if (!info || canRole(info, 'servers.manage')) lines.push('/addserver — подключить сервер по логину и паролю или ключу');
  lines.push('/notify — какие уведомления присылать', '/cancel — прервать ввод', '/help — эта справка', '',
    'Пользователь, которого вы добавили с Telegram ID, пишет боту /sub и получает свою подписку.',
    info && !canRole(info, 'servers.manage') ? `Роль ${info.name}: что ей разрешено, настраивает owner в панели («Права и роли»).` : 'Пароли серверов бот удаляет из чата сразу после чтения и нигде не хранит.');
  return lines.join('\n');
}

export class AdminFlows {
  private flows = new Map<string, Flow>();
  constructor(private readonly ctx: Ctx, private readonly io: BotIO) {}

  /** Право роли админа (roles.ts) и, если указано, сервер или конфигурация в её области. */
  private may(a: AdminRow, p: Perm, where: { server?: string; template?: string; newServer?: boolean } = {}): boolean {
    const r = roleOf(this.ctx.db, a.role);
    if (!canRole(r, p)) return false;
    if (where.server && !inScope(r.scope.servers, where.server)) return false;
    if (where.template && !inScope(r.scope.templates, where.template)) return false;
    return !(where.newServer && !r.owner && r.scope.servers);
  }

  private vpn() { return new Vpn(this.ctx); }
  private user(id: string) { return this.ctx.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined; }

  // ───── текстовые команды и пошаговый ввод ─────

  /** true — сообщение обработано (команда админа или шаг ввода). */
  async onText(chatId: string, a: AdminRow, text: string, messageId: number): Promise<boolean> {
    const [head, ...rest] = text.trim().split(/\s+/);
    const cmd = head!.replace(/@.*$/, '').toLowerCase();
    if (cmd === '/cancel') { this.flows.delete(chatId); await this.io.send(chatId, 'Ввод прерван.'); return true; }
    if (cmd === '/users') { this.flows.delete(chatId); await this.io.show(chatId, this.usersScreen(0)); return true; }
    if (cmd === '/servers') { this.flows.delete(chatId); await this.io.show(chatId, this.serversScreen(a)); return true; }
    if (cmd === '/notify') { await this.io.show(chatId, this.notifyScreen(a)); return true; }
    if (cmd === '/adduser') {
      if (!this.may(a, 'users.edit')) { await this.io.send(chatId, 'Роли не разрешено добавлять пользователей.'); return true; }
      const [name, tg] = rest;
      if (name) return this.addUser(chatId, a, name, tg ?? '').then(() => true);
      this.flows.set(chatId, { kind: 'user', step: 'name', data: {}, exp: Date.now() + 15 * 60_000 });
      await this.io.send(chatId, 'Имя нового пользователя (латиница, цифры, дефис):\n/cancel — отмена');
      return true;
    }
    if (cmd === '/addserver') { await this.startServerFlow(chatId, a); return true; }
    const f = this.flows.get(chatId);
    if (!f || cmd.startsWith('/')) return false;
    if (f.exp < Date.now()) { this.flows.delete(chatId); await this.io.send(chatId, 'Ввод устарел — начните заново.'); return true; }
    if (f.kind === 'user') await this.userStep(chatId, a, f, text.trim());
    else await this.serverStep(chatId, a, f, text, messageId);
    return true;
  }

  // ───── нажатия кнопок ─────

  /** true — кнопка из админских разделов. */
  async onButton(chatId: string, mid: number, a: AdminRow, act: string, args: string[], toast: (t?: string) => Promise<unknown>): Promise<boolean> {
    const db = this.ctx.db;
    switch (act) {
      case 'h': await toast(); await this.io.show(chatId, { text: helpText('admin', a.role, roleOf(this.ctx.db, a.role)), kb: [[back('m', '‹ Меню')]] }, mid); return true;
      case 'nt': {
        if (args[0]) {
          const off = new Set(json<string[]>((db.prepare('SELECT notify_off FROM admins WHERE id = ?').get(a.id) as { notify_off: string }).notify_off, []));
          if (off.has(args[0])) off.delete(args[0]); else off.add(args[0]);
          db.prepare('UPDATE admins SET notify_off = ? WHERE id = ?').run(JSON.stringify([...off]), a.id);
          await toast(off.has(args[0]) ? 'Выключено' : 'Включено');
        } else await toast();
        await this.io.show(chatId, this.notifyScreen(a), mid);
        return true;
      }
      // пользователи
      case 'ul': await toast(); await this.io.show(chatId, this.usersScreen(Number(args[0] ?? 0)), mid); return true;
      case 'uadd':
        if (!this.may(a, 'users.edit')) return toast('Роли не разрешено добавлять пользователей').then(() => true);
        await toast();
        this.flows.set(chatId, { kind: 'user', step: 'name', data: {}, exp: Date.now() + 15 * 60_000 });
        await this.io.send(chatId, 'Имя нового пользователя (латиница, цифры, дефис):\n/cancel — отмена');
        return true;
      case 'uc': { const u = this.user(args[0]!); if (!u) return toast('Пользователь не найден').then(() => true); await toast(); await this.io.show(chatId, this.userCard(a, u), mid); return true; }
      case 'usub': {
        const u = this.user(args[0]!); if (!u) return toast('Пользователь не найден').then(() => true);
        const base = subBase(this.ctx);
        await toast();
        await this.io.send(chatId, base ? `Подписка <b>${esc(u.name)}</b>:\n<code>${esc(`${base}/s/${u.sub_token}`)}</code>\n\nОткрытая в браузере, ссылка показывает QR, срок и лимиты.` : 'Сервис подписок не настроен: задайте адрес в разделе «Пользователи» панели.');
        return true;
      }
      case 'ulnk': {
        const u = this.user(args[0]!); if (!u) return toast('Пользователь не найден').then(() => true);
        const ps = this.vpn().profiles(u);
        await toast();
        if (!ps.length) { await this.io.show(chatId, { text: `У ${esc(u.name)} нет профилей: выкатите конфигурацию на доступные ему серверы.`, kb: [[back(`uc:${u.id}`)]] }, mid); return true; }
        await this.io.show(chatId, { text: `Отдельные ссылки <b>${esc(u.name)}</b> — выберите профиль:`, kb: [...ps.slice(0, 30).map((p, i) => [cb(p.name, `ul1:${u.id}:${i}`)]), [back(`uc:${u.id}`)]] }, mid);
        return true;
      }
      case 'ul1': {
        const u = this.user(args[0]!); const vpn = this.vpn(); const p = u && vpn.profiles(u)[Number(args[1])];
        if (!u || !p) return toast('Профиль не найден — откройте список заново').then(() => true);
        await toast();
        await this.io.send(chatId, `<b>${esc(p.name)}</b> · ${esc(u.name)}\n<code>${esc(vpn.link(u, p))}</code>`);
        return true;
      }
      case 'utpl': case 'usrv': {
        const u = this.user(args[0]!); if (!u) return toast('Пользователь не найден').then(() => true);
        if (act === 'utpl' && args[1]) {
          if (!this.may(a, 'users.edit', { template: args[1] })) return toast('Эта конфигурация вне вашей роли').then(() => true);
          const all = this.vpn().userTemplates().map((t) => t.id);
          const cur = json<string[] | null>(u.template_ids, null) ?? all;
          const next = cur.includes(args[1]) ? cur.filter((x) => x !== args[1]) : [...cur, args[1]];
          const val = all.every((n) => next.includes(n)) ? null : next;
          db.prepare('UPDATE users SET template_ids = ? WHERE id = ?').run(val ? JSON.stringify(val) : null, u.id);
          this.vpn().markDirty();
          audit(db, a.username, 'user.update', u.id, { templateIds: val, via: 'bot' });
          await toast('Сохранено');
        } else await toast();
        await this.io.show(chatId, this.userConfigs(this.user(u.id)!), mid);
        return true;
      }
      case 'uon': {
        const u = this.user(args[0]!); if (!u) return toast('Пользователь не найден').then(() => true);
        if (!this.may(a, 'users.edit')) return toast('Роли не разрешено менять пользователей').then(() => true);
        const st = u.status === 'active' ? 'disabled' : 'active';
        db.prepare(`UPDATE users SET status = ?, disabled_reason = ? WHERE id = ?`).run(st, st === 'disabled' ? 'отключён в боте' : null, u.id);
        this.vpn().markDirty();
        audit(db, a.username, 'user.update', u.id, { status: st, via: 'bot' });
        await toast(st === 'active' ? 'Доступ включён' : 'Доступ отключён');
        await this.io.show(chatId, this.userCard(a, this.user(u.id)!), mid);
        return true;
      }
      case 'udel': {
        const u = this.user(args[0]!); if (!u) return toast('Пользователь не найден').then(() => true);
        if (!this.may(a, 'users.delete')) return toast('Роли не разрешено удалять пользователей').then(() => true);
        await toast();
        await this.io.show(chatId, { text: `Удалить <b>${esc(u.name)}</b>? Его подписка и ссылки перестанут работать.`, kb: [[cb('Удалить', `udelok:${u.id}`), back(`uc:${u.id}`, 'Отмена')]] }, mid);
        return true;
      }
      case 'udelok': {
        const u = this.user(args[0]!); if (!u || !this.may(a, 'users.delete')) return toast('Нет доступа').then(() => true);
        db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
        this.vpn().markDirty();
        audit(db, a.username, 'user.delete', u.id, { name: u.name, via: 'bot' });
        await toast('Удалён');
        await this.io.show(chatId, this.usersScreen(0), mid);
        return true;
      }
      // серверы
      case 'sl': await toast(); await this.io.show(chatId, this.serversScreen(a), mid); return true;
      case 'sc': { const s = this.server(args[0]!); if (!s) return toast('Сервер не найден').then(() => true); await toast(); await this.io.show(chatId, this.serverCard(a, s), mid); return true; }
      case 'sp': {
        const s = this.server(args[0]!); const lvl = args[1]!;
        if (!s || !this.may(a, 'servers.protect', { server: s.id }) || !LEVEL[lvl]) return toast('Нет доступа').then(() => true);
        this.ctx.updateServer(s.id, { protection_target: lvl });
        audit(db, a.username, 'server.update', s.id, { protectionTarget: lvl, via: 'bot' });
        await toast(`Защита: ${LEVEL[lvl]}`);
        const card = this.serverCard(a, this.server(s.id)!);
        if (lvl !== 'P1') card.text += '\n\nБлокировки firewall включаются после чек-листа доступа на вкладке «Защита» в панели — так нельзя случайно закрыть себе SSH.';
        await this.io.show(chatId, card, mid);
        return true;
      }
      case 'sco': {
        const s = this.server(args[0]!); if (!s) return toast('Сервер не найден').then(() => true);
        await toast('Смотрю ядра…');
        await this.io.show(chatId, await this.coresScreen(a, s), mid);
        return true;
      }
      case 'scp': {
        const s = this.server(args[0]!); const core = args[1] as 'xray' | 'sing-box' | 'telemt'; const on = args[2] === '1';
        if (!s || !this.may(a, 'cores.manage', { server: s.id }) || !['xray', 'sing-box', 'telemt'].includes(core)) return toast('Нет доступа').then(() => true);
        if (!on && args[3] !== 'ok') {
          await toast();
          await this.io.show(chatId, { text: `Остановить ${core} на <b>${esc(s.name)}</b>? Пользователи этого сервера потеряют связь, пока ядро не запустят снова.`, kb: [[cb('Остановить', `scp:${s.id}:${core}:0:ok`), back(`sco:${s.id}`, 'Отмена')]] }, mid);
          return true;
        }
        await toast(on ? 'Запускаю…' : 'Останавливаю…');
        try {
          await new Ops(this.ctx).setCorePower(s, core, on);
          audit(db, a.username, on ? 'core.start' : 'core.stop', s.id, { core, via: 'bot' });
        } catch (e) { await this.io.send(chatId, `Не получилось: ${esc((e as Error).message)}`); }
        await this.io.show(chatId, await this.coresScreen(a, this.server(s.id)!), mid);
        return true;
      }
      case 'sadd': await toast(); await this.startServerFlow(chatId, a); return true;
      case 'fr': case 'fm': case 'fv': case 'fvl': case 'fok': case 'fx': {
        const f = this.flows.get(chatId);
        if (!f || f.kind !== 'server') return toast('Ввод устарел — начните заново').then(() => true);
        await toast();
        if (act === 'fx') { this.flows.delete(chatId); await this.io.show(chatId, { text: 'Подключение отменено.' }, mid); return true; }
        if (act === 'fr') { f.data.role = args[0]!; f.step = 'mgmt'; await this.io.show(chatId, this.mgmtAsk(), mid); return true; }
        if (act === 'fm') { f.data.mgmt = args[0]!; f.step = 'via'; await this.io.show(chatId, this.viaAsk(), mid); return true; }
        if (act === 'fv') {
          if (args[0] === 'direct') { delete f.data.viaServer; delete f.data.viaTpl; delete f.data.viaLink; }
          else { f.data.viaServer = args[0]!; f.data.viaTpl = args[1]!; delete f.data.viaLink; }
          f.step = 'confirm'; await this.io.show(chatId, this.serverSummary(f), mid); return true;
        }
        if (act === 'fvl') { f.step = 'vialink'; await this.io.show(chatId, { text: 'Пришлите ссылку прокси за пределами РФ: vless://…, trojan://, vmess:// или ss://. Сообщение удалю сразу после чтения.\n/cancel — отмена' }, mid); return true; }
        return this.finishServer(chatId, mid, a, f).then(() => true);
      }
    }
    return false;
  }

  // ───── пользователи ─────

  private usersScreen(page: number): Screen {
    const users = this.vpn().users();
    const from = page * PAGE;
    const list = users.slice(from, from + PAGE);
    const nav: Button[] = [];
    if (page > 0) nav.push(cb('‹', `ul:${page - 1}`));
    if (from + PAGE < users.length) nav.push(cb('›', `ul:${page + 1}`));
    return {
      text: users.length ? `<b>Пользователи</b> · ${users.length}${users.length > PAGE ? `, стр. ${page + 1}` : ''}` : 'Пользователей пока нет.',
      kb: [...list.map((u) => [cb(`${u.status === 'active' ? '🟢' : '⏸'} ${u.name}${u.tg_id ? ' · tg' : ''}`, `uc:${u.id}`)]), ...(nav.length ? [nav] : []), [cb('➕ Добавить', 'uadd'), back('m', '‹ Меню')]],
    };
  }

  private userCard(a: AdminRow, u: UserRow): Screen {
    const lim = effectiveLimits(this.ctx, u);
    const t = this.ctx.db.prepare('SELECT up, down FROM traffic WHERE user_id = ? AND period = ?').get(u.id, period()) as { up: number; down: number } | undefined;
    const tpls = json<string[] | null>(u.template_ids, null);
    const lines = [
      `<b>${esc(u.name)}</b> — ${u.status === 'active' ? 'доступ активен' : `отключён${u.disabled_reason ? ` (${esc(u.disabled_reason)})` : ''}`}`,
      `Трафик за месяц: ${gb((t?.up ?? 0) + (t?.down ?? 0))}${lim.trafficGb ? ` из ${lim.trafficGb} ГБ` : ''}`,
      `Срок: ${lim.expireAt ? lim.expireAt.slice(0, 10) : 'без срока'}`,
      `Конфигурации: ${tpls ? tpls.map((id) => this.vpn().template(id)?.name ?? id).join(', ') || 'нет' : 'все'}`,
      `Telegram: ${u.tg_id ? `<code>${u.tg_id}</code> — может писать боту /sub` : 'не привязан'}`,
    ];
    return {
      text: lines.join('\n'),
      kb: [
        [cb('Подписка', `usub:${u.id}`), cb('Отдельные ссылки', `ulnk:${u.id}`)],
        [cb('Конфигурации', `utpl:${u.id}`), cb(u.status === 'active' ? 'Отключить' : 'Включить', `uon:${u.id}`)],
        [...(this.may(a, 'users.delete') ? [cb('Удалить', `udel:${u.id}`)] : []), back('ul:0')],
      ],
    };
  }

  /** Конфигурации пользователя: какие дают профили в подписку (с примером профилей каждой). */
  private userConfigs(u: UserRow): Screen {
    const tpls = json<string[] | null>(u.template_ids, null);
    const vpn = this.vpn();
    const all = vpn.profiles({ ...u, template_ids: null });
    const list = vpn.userTemplates();
    const lines = list.map((t) => {
      const ps = all.filter((p) => p.template.id === t.id).map((p) => p.name);
      return `<b>${esc(t.name)}</b>: ${ps.length ? esc(ps.slice(0, 6).join(', ')) + (ps.length > 6 ? ` и ещё ${ps.length - 6}` : '') : 'профилей нет'}`;
    });
    return {
      text: `Конфигурации <b>${esc(u.name)}</b> — какие попадут в подписку. Нажмите, чтобы включить или выключить:\n\n${lines.join('\n')}`,
      kb: [...list.map((t) => [cb(`${!tpls || tpls.includes(t.id) ? '✅' : '⬜'} ${t.name}`, `utpl:${u.id}:${t.id}`)]), [back(`uc:${u.id}`)]],
    };
  }

  private async userStep(chatId: string, a: AdminRow, f: Flow, text: string) {
    if (f.step === 'name') {
      f.data.name = text;
      f.step = 'tg';
      await this.io.send(chatId, `Telegram ID пользователя <b>${esc(text)}</b> — число из ответа бота на его /start.\nНет Telegram — отправьте «-».`);
      return;
    }
    this.flows.delete(chatId);
    await this.addUser(chatId, a, f.data.name!, text === '-' ? '' : text);
  }

  private async addUser(chatId: string, a: AdminRow, name: string, tg: string) {
    const parsed = userBody.safeParse({ name, tgId: tg ? tg : null });
    if (!parsed.success) {
      await this.io.send(chatId, `Не подходит: ${esc(parsed.error.issues.map((i) => (i.path[0] === 'tgId' ? 'Telegram ID — только цифры' : 'имя — буквы, цифры, пробел, точка, дефис')).join('; '))}. Попробуйте ещё раз: /adduser`);
      return;
    }
    if (this.ctx.db.prepare('SELECT 1 FROM users WHERE name = ?').get(parsed.data.name)) { await this.io.send(chatId, 'Пользователь с таким именем уже есть.'); return; }
    if (parsed.data.tgId && this.ctx.db.prepare('SELECT 1 FROM users WHERE tg_id = ?').get(parsed.data.tgId)) { await this.io.send(chatId, 'Этот Telegram ID уже привязан к другому пользователю.'); return; }
    let id: string;
    try { id = saveUser(this.ctx, null, parsed.data, roleOf(this.ctx.db, a.role), a.id); } catch (e) { await this.io.send(chatId, `Не получилось: ${esc((e as Error).message)}`); return; }
    this.vpn().markDirty();
    audit(this.ctx.db, a.username, 'user.create', id, { name: parsed.data.name, via: 'bot' });
    const card = this.userCard(a, this.user(id)!);
    card.text = `Пользователь создан.${parsed.data.tgId ? ' Пусть напишет боту /sub — получит подписку.' : ''}\n\n${card.text}`;
    await this.io.show(chatId, card);
  }

  // ───── серверы ─────

  private server(id: string): ServerRow | undefined { try { return this.ctx.server(id); } catch { return undefined; } }

  private serversScreen(a: AdminRow): Screen {
    const servers = this.ctx.servers();
    return {
      text: servers.length ? '<b>Серверы</b>' : 'Серверов пока нет.',
      kb: [...servers.map((s) => [cb(`${s.fail_since ? '🔴' : s.last_seen_at ? '🟢' : '⚪️'} ${s.name}`, `sc:${s.id}`)]), [...(this.may(a, 'servers.manage', { newServer: true }) ? [cb('➕ Подключить', 'sadd')] : []), back('m', '‹ Меню')]],
    };
  }

  private serverCard(a: AdminRow, s: ServerRow): Screen {
    const role = (s.mgmt_mode === 'local' ? 'Исполнитель (главный)' : s.role === 'exit' ? 'Выход' : 'Relay') + (s.mgmt_mode === 'tunnel' ? ' · туннель' : s.mgmt_mode === 'inbound' ? ' · через конфигурацию' : s.mgmt_mode === 'jump' ? ' · через сервер' : '');
    const lines = [
      `<b>${esc(s.name)}</b> — ${role}`,
      s.fail_since ? `🔴 нет связи с ${esc(s.fail_since.slice(0, 16).replace('T', ' '))}` : s.last_seen_at ? '🟢 на связи' : '⚪️ ещё не подключён',
      `Защита: ${LEVEL[s.protection_current] ?? s.protection_current}${s.protection_target !== s.protection_current ? ` → цель ${LEVEL[s.protection_target]}` : ''}`,
      `Ядра: ${Object.entries(json<Record<string, { version: string }>>(s.cores, {})).map(([k, v]) => `${k} ${v.version}`).join(', ') || 'не установлены'}`,
      ...(coresOff(this.ctx, s.id).length ? [`⏸ остановлено вручную: ${coresOff(this.ctx, s.id).join(', ')}`] : []),
    ];
    const kb: Kb = [];
    if (this.may(a, 'servers.protect', { server: s.id })) kb.push((['P1', 'P2', 'P3'] as const).map((l) => cb(`${s.protection_target === l ? '● ' : ''}${LEVEL[l]}`, `sp:${s.id}:${l}`)));
    if (s.sudo_mode === 'restricted') kb.push([cb('Ядра', `sco:${s.id}`)]);
    kb.push([back('sl')]);
    return { text: lines.join('\n'), kb };
  }

  private async coresScreen(a: AdminRow, s: ServerRow): Promise<Screen> {
    let st: Record<string, { active: boolean; manualOff: boolean }>;
    try { st = await new Ops(this.ctx).coreStates(s); } catch (e) { return { text: `Не удалось связаться с ${esc(s.name)}: ${esc((e as Error).message)}`, kb: [[back(`sc:${s.id}`)]] }; }
    const cores = Object.entries(st);
    return {
      text: cores.length ? `<b>Ядра ${esc(s.name)}</b>\n${cores.map(([c, v]) => `${v.active ? '🟢' : v.manualOff ? '⏸' : '🔴'} ${c} — ${v.active ? 'работает' : v.manualOff ? 'остановлен вручную' : 'не работает'}`).join('\n')}` : 'Ядра не установлены.',
      kb: [...(this.may(a, 'cores.manage', { server: s.id }) ? cores.map(([c, v]) => [cb(v.active ? `Остановить ${c}` : `Запустить ${c}`, `scp:${s.id}:${c}:${v.active ? 0 : 1}`)]) : []), [back(`sc:${s.id}`)]],
    };
  }

  private async startServerFlow(chatId: string, a: AdminRow) {
    if (!this.may(a, 'servers.manage', { newServer: true })) { await this.io.send(chatId, 'Роли не разрешено подключать серверы.'); return; }
    this.flows.set(chatId, { kind: 'server', step: 'name', data: {}, exp: Date.now() + 20 * 60_000 });
    await this.io.send(chatId, 'Подключение сервера. Имя (например, de-1):\n/cancel — отмена');
  }

  private mgmtAsk(): Screen {
    return {
      text: 'Как панель будет управлять сервером?\n<b>Напрямую</b> — по SSH, если главный сервер не в РФ.\n<b>Через туннель</b> — SSH внутри VLESS-REALITY, если прямой SSH через границу режется.',
      kb: [[cb('Напрямую', 'fm:direct'), cb('Через туннель', 'fm:tunnel')], [cb('Отмена', 'fx')]],
    };
  }

  /** Первичный доступ: напрямую или через прокси — если SSH до сервера из РФ режется. */
  private viaAsk(): Screen {
    const opts = botProxyOptions(this.ctx).slice(0, 8);
    return {
      text: 'Как панели первый раз зайти на сервер?\n<b>Напрямую</b> — по SSH.\n<b>Через прокси</b> — если главный сервер в РФ и SSH до сервера за границей режется: панель зайдёт через конфигурацию флота или вашу ссылку VLESS.',
      kb: [[cb('Напрямую', 'fv:direct')], ...opts.map((o) => [cb(`Через ${o.serverName} · ${o.templateName}`, `fv:${o.serverId}:${o.templateId}`)]), [cb('Своя ссылка vless://', 'fvl')], [cb('Отмена', 'fx')]],
    };
  }

  private serverSummary(f: Flow): Screen {
    const d = f.data;
    return {
      text: [`<b>Подключить сервер?</b>`, `Имя: ${esc(d.name!)}`, `Адрес: <code>${esc(d.host!)}:${d.port}</code>`, `Вход: ${esc(d.user!)} по ${d.key ? 'ключу' : 'паролю'}`,
        `Роль: ${d.role === 'exit' ? 'Выход' : 'Relay'}`, `Канал: ${d.mgmt === 'tunnel' ? 'через туннель' : 'напрямую'}`,
        `Первичный доступ: ${d.viaLink ? 'через вашу ссылку' : d.viaServer ? `через ${esc(this.server(d.viaServer)?.name ?? d.viaServer)}` : 'напрямую'}`, '', 'Панель зайдёт один раз, поставит свой ключ и служебные скрипты, затем доступ по паролю ей больше не нужен.'].join('\n'),
      kb: [[cb('Подключить', 'fok'), cb('Отмена', 'fx')]],
    };
  }

  private async serverStep(chatId: string, a: AdminRow, f: Flow, raw: string, messageId: number) {
    const text = raw.trim();
    const d = f.data;
    switch (f.step) {
      case 'name':
        if (!/^[\p{L}0-9 ._-]{1,64}$/u.test(text)) { await this.io.send(chatId, 'Имя — буквы, цифры, пробел, точка, дефис. Ещё раз:'); return; }
        d.name = text; f.step = 'host';
        await this.io.send(chatId, 'IP или домен сервера (порт SSH — через двоеточие, если не 22):');
        return;
      case 'host': {
        const m = text.match(/^([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?$/);
        if (!m) { await this.io.send(chatId, 'Не похоже на адрес. Пример: <code>203.0.113.10</code> или <code>203.0.113.10:2222</code>'); return; }
        d.host = m[1]!.replace(/^\[|\]$/g, ''); d.port = m[2] ?? '22'; f.step = 'user';
        await this.io.send(chatId, 'Логин на сервере (обычно <code>root</code>):');
        return;
      }
      case 'user':
        if (!/^[a-z_][a-z0-9_.-]{0,63}$/i.test(text)) { await this.io.send(chatId, 'Логин — латиница, цифры, точка, дефис. Ещё раз:'); return; }
        d.user = text; f.step = 'secret';
        await this.io.send(chatId, 'Пароль или приватный SSH-ключ (целиком, с -----BEGIN…). Сообщение удалю сразу после чтения.');
        return;
      case 'secret':
        await this.io.drop(chatId, messageId);   // пароль не остаётся в чате
        if (raw.includes('PRIVATE KEY')) d.key = raw.trim(); else d.password = raw.replace(/\r?\n$/, '');
        f.step = 'role';
        await this.io.show(chatId, { text: 'Принято, сообщение удалено. Роль сервера:', kb: [[cb('Relay (вход)', 'fr:entry'), cb('Выход', 'fr:exit')], [cb('Отмена', 'fx')]] });
        return;
      case 'vialink':
        await this.io.drop(chatId, messageId);   // в ссылке секрет прокси
        if (!/^(vless|trojan|vmess|ss):\/\//i.test(text) && !text.startsWith('{')) { await this.io.send(chatId, 'Нужна ссылка vless://, trojan://, vmess:// или ss://. Ещё раз:'); return; }
        d.viaLink = text; delete d.viaServer; delete d.viaTpl; f.step = 'confirm';
        await this.io.show(chatId, this.serverSummary(f));
        return;
      default:
        await this.io.send(chatId, 'Выберите вариант кнопкой выше или /cancel.');
    }
  }

  private async finishServer(chatId: string, mid: number, a: AdminRow, f: Flow) {
    this.flows.delete(chatId);
    const d = f.data;
    const parsed = createBody.safeParse({
      name: d.name, host: d.host, sshPort: d.port, role: d.role, mgmtMode: d.mgmt,
      auth: {
        user: d.user, ...(d.key ? { privateKey: d.key } : { password: d.password }),
        ...(d.viaLink ? { via: { kind: 'link', link: d.viaLink } } : d.viaServer ? { via: { kind: 'fleet', serverId: d.viaServer, templateId: d.viaTpl } } : {}),
        // через прокси и с туннелем — туннель управления дальше тоже идёт через этот прокси (сервер недоступен из РФ)
        ...((d.viaLink || d.viaServer) && d.mgmt === 'tunnel' ? { keepVia: true } : {}),
      },
    });
    if (!parsed.success) { await this.io.show(chatId, { text: `Данные не подошли: ${esc(parsed.error.issues.map((i) => i.message).join('; '))}` }, mid); return; }
    let r: { id: string; jobId: number | null };
    try { r = createServer(this.ctx, parsed.data, a.username); } catch (e) { await this.io.show(chatId, { text: `Не получилось: ${esc((e as Error).message)}` }, mid); return; }
    await this.io.show(chatId, { text: `Подключаю <b>${esc(d.name!)}</b>… Сообщу, когда закончу (обычно 1–3 минуты).` }, mid);
    if (r.jobId) void this.watchJob(chatId, a, r.id, r.jobId);
  }

  /** Ждём окончания подключения и присылаем итог с последними строками журнала. */
  private async watchJob(chatId: string, a: AdminRow, serverId: string, jobId: number) {
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      const j = this.ctx.db.prepare('SELECT status, log FROM jobs WHERE id = ?').get(jobId) as { status: string; log: string } | undefined;
      if (!j || j.status === 'running') continue;
      const tail = j.log.trim().split('\n').slice(-4).map((l) => l.replace(/^\[[^\]]+\]\s*/, '')).join('\n');
      const s = this.server(serverId);
      await this.io.show(chatId, {
        text: j.status === 'ok' ? `✅ <b>${esc(s?.name ?? serverId)}</b> подключён и настроен.` : `⛔ Подключить не удалось:\n<code>${esc(tail)}</code>\n\nПроверьте логин и пароль; подробности — в панели, карточка сервера → «Задачи».`,
        kb: s ? [[cb('Открыть сервер', `sc:${s.id}`)]] : undefined,
      });
      return;
    }
  }

  // ───── уведомления ─────

  notifyScreen(a: AdminRow): Screen {
    const off = new Set(json<string[]>((this.ctx.db.prepare('SELECT notify_off FROM admins WHERE id = ?').get(a.id) as { notify_off: string } | undefined)?.notify_off ?? '[]', []));
    return {
      text: '<b>Уведомления</b> — какие сообщения присылать вам. Пользователям VPN бот такие сообщения не шлёт.',
      kb: [...Object.entries(NOTIFY).map(([k, label]) => [cb(`${off.has(k) ? '⬜' : '✅'} ${label}`, `nt:${k}`)]), [back('m', '‹ Меню')]],
    };
  }
}

/** Пользователю — подписка как сообщение (команда /sub). */
export function subMessage(ctx: Ctx, u: UserRow): string {
  const base = subBase(ctx);
  if (!base) return 'Подписки пока не настроены — напишите администратору.';
  return `Ваша подписка — добавьте её в приложение (Hiddify, v2rayNG, Happ, Streisand):\n<code>${esc(`${base}/s/${u.sub_token}`)}</code>\n\nОткройте ссылку в браузере — там QR-код и кнопки для приложений.`;
}

export const langOf = (ctx: Ctx) => (getSetting<string>(ctx.db, 'ui.lang', 'ru') === 'en' ? 'en' : 'ru');
