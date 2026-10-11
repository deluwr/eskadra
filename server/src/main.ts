import fs from 'node:fs';
import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { ZodError } from 'zod';
import { config } from './config.js';
import { openDb } from './db.js';
import { loadOrCreateMasterKey, Sealer } from './lib/crypto.js';
import { Ctx, HttpError } from './ctx.js';
import { authRoutes, requireAdmin } from './routes/auth.js';
import { serverRoutes } from './routes/servers.js';
import { templateRoutes } from './routes/templates.js';
import { userRoutes } from './routes/users.js';
import { adminRoutes } from './routes/admin.js';
import { coreRoutes } from './routes/cores.js';
import { HostKeyError } from './ssh/executor.js';
import { Bot } from './bot.js';
import { Backups } from './backup.js';
import { SubService } from './subsvc.js';
import { Workers } from './workers.js';
import { Mgmt } from './mgmt.js';
import { applyStagedRestore } from './restorelib.js';

fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
// восстановление из бэкапа, подготовленное в панели: подмена данных до открытия базы
applyStagedRestore(config.dataDir, (m) => console.log(m));
const db = openDb(config.dataDir);
const ctx = new Ctx(db, new Sealer(loadOrCreateMasterKey(config.dataDir)));

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? 'info' },
  ...(config.tlsCert && config.tlsKey
    ? { https: { cert: fs.readFileSync(config.tlsCert), key: fs.readFileSync(config.tlsKey) } }
    : {}),
}) as unknown as FastifyInstance;
await app.register(cookie);
const prefix = config.basePath.replace(/\/$/, '');

app.setErrorHandler((err, _req, reply) => {
  if (err instanceof ZodError) return reply.code(400).send({ error: err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '), issues: err.issues });
  if (err instanceof HostKeyError) return reply.code(409).send({ error: err.message, kind: 'host_key' });
  if (err instanceof HttpError) return reply.code(err.statusCode).send({ error: err.message, ...err.extra });
  const e = err as Error & { statusCode?: number; level?: string };
  if (e.level === 'client-authentication')
    return reply.code(502).send({ error: 'SSH: вход по ключу отклонён (сниппет выполнен? from= совпадает с вашим IP?)' });
  const code = e.statusCode ?? 500;
  if (code >= 500) app.log.error(err);
  return reply.code(code).send({ error: e.message });
});

// клиент служебных туннелей (§5.8): поднимается при первом SSH к туннельному узлу
const mgmt = new Mgmt(ctx, config.dataDir, app.log);
ctx.mgmt = mgmt;
for (const sig of ['SIGTERM', 'SIGINT'] as const) process.once(sig, () => { mgmt.stop(); process.exit(0); });
process.once('exit', () => mgmt.stop());

const bot = new Bot(ctx, app.log);
const backups = new Backups(ctx, bot);
bot.onBackupRequest = async () => {
  try {
    const r = await backups.run('manual', 'bot');
    return `Бэкап ${r.file} создан, доставлен ${r.delivered} из ${r.total}.`;
  } catch (e) { return `Бэкап не создан: ${(e as Error).message}`; }
};
const sub = new SubService(ctx, process.env.FLEET_SUB_BIND ?? config.host);

// Всё приложение живёт под базовым путём; вне его — нейтральный 404, панель не светится сканерам.
await app.register(async (root) => {
  await authRoutes(root, ctx);
  await root.register(async (secured) => {
    secured.addHook('preHandler', requireAdmin(ctx));
    await serverRoutes(secured, ctx);
    await templateRoutes(secured, ctx);
    await userRoutes(secured, ctx);
    await coreRoutes(secured, ctx);
    await adminRoutes(secured, ctx, { backups, bot, sub });
  });
  if (fs.existsSync(config.webDist)) await root.register(fastifyStatic, { root: config.webDist, prefix: '/' });
}, { prefix });

// «/путь» без слэша → «/путь/»: иначе относительные ассеты и API разрешатся от корня
if (prefix) app.addHook('onRequest', async (req, reply) => { if (req.url === prefix) return reply.redirect(config.basePath); });
app.setNotFoundHandler((req, reply) => {
  const url = req.url.split('?')[0]!;
  const index = path.join(config.webDist, 'index.html');
  if (url.startsWith(config.basePath) && !url.startsWith(config.basePath + 'api/') && fs.existsSync(index))
    return reply.type('text/html; charset=utf-8').send(fs.readFileSync(index));
  return reply.code(404).type('text/plain').send('404 page not found');
});

await app.listen({ host: config.host, port: config.port });

// Let's Encrypt продлевает сертификат раз в несколько дней: подхватываем новый без перезапуска панели
if (config.tlsCert && config.tlsKey) {
  const reload = () => {
    try {
      (app.server as import('node:https').Server).setSecureContext({ cert: fs.readFileSync(config.tlsCert!), key: fs.readFileSync(config.tlsKey!) });
      sub.reloadTls();
      app.log.info('TLS-сертификат обновлён');
    } catch (e) { app.log.warn(`не удалось перечитать сертификат: ${(e as Error).message}`); }
  };
  fs.watchFile(config.tlsCert, { interval: 60_000 }, (cur, prev) => { if (cur.mtimeMs !== prev.mtimeMs) reload(); });
}
const subPort = await sub.start();
app.log.info(`сервис подписок: ${process.env.FLEET_SUB_BIND ?? config.host}:${subPort}`);
bot.start();
if (process.env.FLEET_WORKERS !== '0') new Workers(ctx, app.log, backups, bot).start();
