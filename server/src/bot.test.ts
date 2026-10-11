import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, setSetting } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx } from './ctx.js';
import { Bot } from './bot.js';

type Call = { method: string; body: Record<string, unknown> };

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'esk-bot-'));
  const db = openDb(dir);
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 2)));
  setSetting(db, 'bot.token', ctx.seal('123456:' + 'x'.repeat(35)));
  db.prepare(`INSERT INTO admins (id, username, pw_hash, role) VALUES (1, 'secret-owner', 'x', 'owner'), (2, 'op', 'x', 'operator')`).run();
  db.prepare(`INSERT INTO users (id, name, sub_token, knock_token) VALUES ('u1', 'anna', 's1', 'k1')`).run();
  const log = { warn: () => undefined, info: () => undefined } as never;
  const bot = new Bot(ctx, log);
  const calls: Call[] = [];
  (bot as unknown as { api: (m: string, b: Record<string, unknown>) => Promise<unknown> }).api = async (method, body) => {
    calls.push({ method, body });
    return method === 'getMe' ? { username: 'test_bot' } : true;
  };
  const b = bot as unknown as {
    onMessage: (chat: string, from: string, text: string, mid?: number) => Promise<void>;
    onCallback: (q: unknown) => Promise<void>;
  };
  const press = (from: string, data: string) => b.onCallback({ id: 'q', from: { id: Number(from) }, data, message: { message_id: 5, chat: { id: Number(from), type: 'private' } } });
  return { db, bot, b, calls, press, last: () => calls.filter((c) => c.method !== 'answerCallbackQuery').at(-1)! };
}

test('bot: стороннему человеку /start показывает только его ID', async () => {
  const f = fixture();
  await f.b.onMessage('999', '999', '/start');
  const text = String(f.last().body.text);
  assert.match(text, /999/);
  assert.doesNotMatch(text, /secret-owner|Эскадр|админ/i);
  assert.equal(f.last().body.reply_markup, undefined);
  // кнопки чужого меню не работают
  await f.press('999', 'srv');
  assert.doesNotMatch(String(f.last().body.text), /entry|сервер/i);
});

test('bot: привязка одноразовой ссылкой и меню админа без логина', async () => {
  const f = fixture();
  const link = await f.bot.bindLink('admin', '1');
  assert.match(link.url, /^https:\/\/t\.me\/test_bot\?start=[\w-]{16}$/);
  assert.equal(f.bot.bindState(link.code), 'pending');
  await f.b.onMessage('4242', '4242', `/start ${link.code}`);
  assert.equal(f.bot.bindState(link.code), 'bound');
  assert.equal((f.db.prepare('SELECT tg_id FROM admins WHERE id = 1').get() as { tg_id: string }).tg_id, '4242');
  const menu = f.last();
  assert.doesNotMatch(String(menu.body.text), /secret-owner/);
  const kb = JSON.stringify(menu.body.reply_markup);
  assert.match(kb, /"callback_data":"sl"/);
  // повторно ссылка не работает
  await f.b.onMessage('5555', '5555', `/start ${link.code}`);
  assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM admins WHERE tg_id = ?').get('5555') as { n: number }).n, 0);
});

test('bot: operator не запускает бэкап; пользователь получает свои кнопки', async () => {
  const f = fixture();
  f.db.prepare(`UPDATE admins SET tg_id = '77' WHERE id = 2`).run();
  let ran = false;
  f.bot.onBackupRequest = async () => { ran = true; return 'ok'; };
  await f.press('77', 'bkgo');
  assert.equal(ran, false);
  const link = await f.bot.bindLink('user', 'u1');
  await f.b.onMessage('88', '88', `/start ${link.code}`);
  const kb = JSON.stringify(f.last().body.reply_markup);
  assert.match(kb, /"callback_data":"sub"/);
  assert.doesNotMatch(kb, /"callback_data":"sl"/);
  await f.press('88', 'srv');   // админская кнопка у пользователя ничего не открывает
  assert.notEqual(f.last().body.message_id, 5);
});

test('bot: operator добавляет пользователя по Telegram ID, тот получает /sub; серверы и уведомления', async () => {
  const f = fixture();
  f.db.prepare(`UPDATE admins SET tg_id = '77' WHERE id = 2`).run();   // operator
  f.db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed) VALUES ('srv-a', 'de-1', '203.0.113.2', 'exit', 'k', 'x'), ('srv-b', 'nl-1', '203.0.113.3', 'exit', 'k', 'x')`).run();
  await f.b.onMessage('77', '77', '/adduser boris 555123');
  const u = f.db.prepare(`SELECT * FROM users WHERE name = 'boris'`).get() as { id: string; tg_id: string; node_ids: string | null };
  assert.equal(u.tg_id, '555123');
  assert.match(String(f.last().body.text), /Пусть напишет боту \/sub/);
  // пользователь пишет /sub — получает свою ссылку, а не админское меню
  await f.b.onMessage('555123', '555123', '/sub');
  assert.match(String(f.last().body.text), /Подписки пока не настроены|\/s\//);
  // выключить пользователю один сервер
  await f.press('77', `usrv:${u.id}:srv-a`);
  assert.deepEqual(JSON.parse((f.db.prepare('SELECT node_ids FROM users WHERE id = ?').get(u.id) as { node_ids: string }).node_ids), ['srv-b']);
  // operator не удаляет и не подключает серверы
  await f.press('77', `udelok:${u.id}`);
  assert.ok(f.db.prepare('SELECT 1 FROM users WHERE id = ?').get(u.id));
  await f.b.onMessage('77', '77', '/addserver');
  assert.match(String(f.last().body.text), /admin и owner/);
  // уведомления: выключил «Связь с серверами» — сообщение о падении не приходит
  await f.press('77', 'nt:down');
  f.calls.length = 0;
  await f.bot.notifyAdmins('x упал', undefined, 'down');
  assert.ok(!f.calls.some((c) => c.body.chat_id === '77'));
  await f.bot.notifyAdmins('x переключён', undefined, 'auto');
  assert.ok(f.calls.some((c) => c.body.chat_id === '77'));
});

test('bot: подключение сервера — пароль удаляется из чата сразу', async () => {
  const f = fixture();
  f.db.prepare(`UPDATE admins SET tg_id = '42' WHERE id = 1`).run();   // owner
  for (const [t, id] of [['/addserver', 1], ['fi-1', 2], ['203.0.113.9:2222', 3], ['root', 4], ['s3cret pass', 5]] as const) await f.b.onMessage('42', '42', t, id);
  assert.ok(f.calls.some((c) => c.method === 'deleteMessage' && c.body.message_id === 5), 'сообщение с паролем удалено');
  assert.match(JSON.stringify(f.last().body.reply_markup), /fr:entry/);
  await f.b.onMessage('42', '42', '/help', 6);
  assert.match(String(f.last().body.text), /\/addserver/);
});
