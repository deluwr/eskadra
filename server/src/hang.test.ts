import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { SshSession } from './ssh/executor.js';
import { deadline } from './workers.js';

test('exec: соединение не отвечает на открытие канала — ошибка по сроку, а не вечное ожидание', async () => {
  let ended = false;
  // «полумёртвое» соединение: exec принят, но ответа (обратного вызова) нет никогда
  const client = { exec: () => undefined, end: () => { ended = true; } };
  const s = new SshSession(client as never);
  const t0 = Date.now();
  await assert.rejects(s.exec('true', { timeoutMs: 200 }), /не ответил за/);
  assert.ok(Date.now() - t0 < 2000);
  assert.ok(ended, 'соединение закрыто — блокировка узла освобождается');
});

test('exec: обычный ответ — как раньше; поздний ответ после срока игнорируется', async () => {
  const mk = (delay: number) => ({
    exec: (_c: string, cb: (e: Error | undefined, ch: unknown) => void) => setTimeout(() => {
      const ch = Object.assign(new EventEmitter(), { stderr: new EventEmitter(), close: () => undefined, end: () => { ch.emit('data', Buffer.from('pong')); ch.emit('close', 0); } });
      cb(undefined, ch);
    }, delay),
    end: () => undefined,
  });
  assert.deepEqual(await new SshSession(mk(5) as never).exec('ping', { timeoutMs: 500 }), { code: 0, signal: undefined, stdout: 'pong', stderr: '' });
  await assert.rejects(new SshSession(mk(300) as never).exec('ping', { timeoutMs: 100 }), /не ответил/);
});

test('deadline: зависшее обещание не держит опрос', async () => {
  await assert.rejects(deadline(new Promise(() => undefined), 50, 'srv: опрос не уложился'), /опрос не уложился/);
  assert.equal(await deadline(Promise.resolve(7), 50, 'x'), 7);
});
