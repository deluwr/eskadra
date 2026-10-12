import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from './db.js';
import { Sealer } from './lib/crypto.js';
import { Ctx, guard, type UserRow } from './ctx.js';
import { checkTemplateServers, mergeScoped, roleOf, ScopeError, scopeUserBody } from './roles.js';
import { saveUser, userBody } from './routes/users.js';

function fixture() {
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'esk-roles-')));
  const ctx = new Ctx(db, new Sealer(Buffer.alloc(32, 7)));
  for (const id of ['s1', 's2', 's3'])
    db.prepare(`INSERT INTO servers (id, name, host, role, key_pub, key_priv_sealed) VALUES (?, ?, '203.0.113.1', 'exit', 'k', 'x')`).run(id, id);
  for (const id of ['t1', 't2', 't3'])
    db.prepare(`INSERT INTO templates (id, name, core, protocol, port, sni, node_ids) VALUES (?, ?, 'xray', 'vless', 443, '[]', '[]')`).run(id, id);
  db.prepare(`INSERT INTO limit_groups (name, devices) VALUES ('vip', 10)`).run();
  // «реселлер»: выдаёт только t1 и t2, только через вход, только группу default, на серверах s1 и s2
  db.prepare(`INSERT INTO roles (id, name, perms, scope) VALUES ('seller', 'seller', '["users.edit","configs.rollout"]', ?)`)
    .run(JSON.stringify({ templates: ['t1', 't2'], servers: ['s1', 's2'], modes: ['via'], limitGroups: ['default'] }));
  return { db, ctx };
}
const user = (db: ReturnType<typeof openDb>, id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as UserRow;

test('роли: owner — всё; встроенные admin и operator с прежними правами; неизвестная роль — без прав', () => {
  const { db } = fixture();
  assert.equal(roleOf(db, 'owner').owner, true);
  assert.ok(roleOf(db, 'admin').perms.includes('servers.protect'));
  assert.deepEqual(roleOf(db, 'operator').perms, ['users.edit', 'configs.edit', 'configs.rollout']);
  assert.deepEqual(roleOf(db, 'nope').perms, []);
});

test('область: выданное вне области роли остаётся как было, в области — как прислали', () => {
  const all = ['t1', 't2', 't3'];
  // у пользователя были t1 и t3 (t3 выдал owner); роль видит t1, t2 и снимает t1, ставит t2
  assert.deepEqual(mergeScoped(all, ['t1', 't3'], ['t2'], ['t1', 't2']), ['t2', 't3']);
  // попытка выдать t3 (вне области) не проходит, снять тоже нельзя
  assert.deepEqual(mergeScoped(all, ['t1'], ['t1', 't3'], ['t1', 't2']), ['t1']);
  assert.deepEqual(mergeScoped(all, ['t3'], [], ['t1', 't2']), ['t3']);
  // «все» → null
  assert.equal(mergeScoped(all, ['t3'], ['t1', 't2'], ['t1', 't2']), null);
  assert.deepEqual(mergeScoped(all, null, ['t9'], null), ['t9'], 'без области — как прислали');
});

test('пользователь от роли с областью: новый — только своё; группа и режимы — из области', () => {
  const { ctx, db } = fixture();
  const seller = roleOf(db, 'seller');
  // «все конфигурации и серверы» от роли с областью = только её конфигурации и серверы
  const id = saveUser(ctx, null, userBody.parse({ name: 'kate', modes: ['via', 'direct'] }), seller);
  const u = user(db, id);
  assert.deepEqual(JSON.parse(u.template_ids!), ['t1', 't2']);
  assert.deepEqual(JSON.parse(u.node_ids!), ['s1', 's2']);
  assert.deepEqual(JSON.parse(u.modes), ['via'], 'напрямую роль не выдаёт');
  assert.throws(() => saveUser(ctx, null, userBody.parse({ name: 'kim', modes: ['direct'] }), seller), /только: через вход/);
  assert.throws(() => saveUser(ctx, null, userBody.parse({ name: 'kim', limitGroup: 'vip' }), seller), /группу лимитов «vip»/);
  // owner выдал kate t3 и напрямую; роль меняет kate — t3 и «напрямую» остаются
  saveUser(ctx, id, userBody.parse({ name: 'kate', templateIds: null, nodeIds: null, modes: ['via', 'direct'], limitGroup: 'vip' }));
  saveUser(ctx, id, userBody.parse({ name: 'kate', templateIds: ['t1'], nodeIds: ['s1'], modes: ['via'], limitGroup: 'vip' }), seller);
  const k = user(db, id);
  assert.deepEqual(JSON.parse(k.template_ids!), ['t1', 't3']);
  assert.deepEqual(JSON.parse(k.node_ids!), ['s1', 's3']);
  assert.deepEqual(JSON.parse(k.modes).sort(), ['direct', 'via']);
  assert.equal(k.limit_group, 'vip', 'прежняя группа вне области остаётся допустимой');
});

test('конфигурация от роли с областью серверов: добавить и убрать можно только свои серверы', () => {
  const { db } = fixture();
  const seller = roleOf(db, 'seller');
  checkTemplateServers(seller, ['s1', 's3'], ['s2', 's3']);
  assert.throws(() => checkTemplateServers(seller, ['s1'], ['s1', 's3']), ScopeError);
  assert.throws(() => checkTemplateServers(seller, ['s1', 's3'], ['s1']), ScopeError);
  checkTemplateServers(roleOf(db, 'owner'), [], ['s3']);
  assert.doesNotThrow(() => scopeUserBody(db, roleOf(db, 'admin'), null, { templateIds: null, nodeIds: null, modes: ['direct'], limitGroup: 'vip' }));
});

test('проверка в API: право роли и сервер/конфигурация в её области', async () => {
  const { ctx } = fixture();
  const run = async (role: string, need: Parameters<typeof guard>[1], url = '/api/v1/users', id?: string) => {
    let code = 200; let body: unknown = null;
    const reply = { code: (c: number) => { code = c; return { send: (b: unknown) => { body = b; return reply; } }; } };
    await guard(ctx, need)({ admin: { id: 1, username: 'x', role, totp: false, totpSecret: null }, params: id ? { id } : {}, routeOptions: { url }, headers: {} } as never, reply as never);
    return { code, body };
  };
  assert.equal((await run('seller', 'users.edit')).code, 200);
  assert.equal((await run('seller', 'users.delete')).code, 403);
  assert.equal((await run('operator', 'servers.manage')).code, 403);
  assert.equal((await run('admin', 'owner')).code, 403);
  assert.equal((await run('seller', 'configs.rollout', '/api/v1/templates/:id/rollout', 't1')).code, 200);
  assert.equal((await run('seller', 'configs.rollout', '/api/v1/templates/:id/rollout', 't3')).code, 403);
  assert.equal((await run('admin', 'configs.rollout', '/api/v1/templates/:id/rollout', 't3')).code, 200);
});
