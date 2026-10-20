import Fastify, { type FastifyInstance } from 'fastify';
import fs from 'node:fs';
import { config } from './config.js';
import { randomInt } from 'node:crypto';
import type { Ctx, UserRow } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { effectiveLimits, json, period, Vpn, type Profile } from './vpn.js';
import { singboxOutbound } from './protocols.js';
import { pushAllowedIp } from './access.js';
import { audit } from './lib/audit.js';
import { renderSubPage, wantsPage } from './subpage.js';
import { subBase } from './routes/users.js';

/** Порт подписок: случайный при первом запуске, а не известный по умолчанию (§4.3). */
export function ensureSubPort(ctx: Ctx): number {
  let port = getSetting<number>(ctx.db, 'sub.port', 0);
  if (!port) {
    do port = randomInt(10000, 60000); while ([10085, 51820].includes(port));
    setSetting(ctx.db, 'sub.port', port);
  }
  return port;
}

function singboxConfig(vpn: Vpn, u: UserRow, profiles: Profile[]) {
  // протоколы и транспорты, которых нет в sing-box (MTProto, XHTTP), в JSON не попадают — они есть в ссылках
  const outs = profiles
    .map((p) => singboxOutbound(vpn.spec(p.template), vpn.cred(u.id, p.credKey), vpn.target(p)))
    .filter((o): o is Record<string, unknown> & { tag: string } => !!o);
  const tags = outs.map((o) => o.tag);
  return {
    outbounds: [
      { type: 'selector', tag: 'Эскадра', outbounds: ['auto', ...tags] },
      { type: 'urltest', tag: 'auto', outbounds: tags },
      ...outs,
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'Эскадра' },
  };
}

export class SubService {
  private app: FastifyInstance | null = null;
  private hits = new Map<string, { n: number; at: number }>();
  constructor(private readonly ctx: Ctx, private readonly bind: string) {}

  private limited(ip: string): boolean {
    const now = Date.now();
    const h = this.hits.get(ip);
    if (!h || now - h.at > 60_000) { this.hits.set(ip, { n: 1, at: now }); return false; }
    return ++h.n > 30;
  }

  private tls() {
    return config.subTls && config.tlsCert && config.tlsKey
      ? { cert: fs.readFileSync(config.tlsCert), key: fs.readFileSync(config.tlsKey) }
      : null;
  }

  reloadTls() {
    const t = this.tls();
    if (t && this.app) (this.app.server as import('node:https').Server).setSecureContext(t);
  }

  async start() {
    const port = ensureSubPort(this.ctx);
    const tls = this.tls();
    const app = (tls ? Fastify({ logger: false, trustProxy: false, https: tls }) : Fastify({ logger: false, trustProxy: false })) as unknown as FastifyInstance;
    const vpn = new Vpn(this.ctx);
    const notFound = (reply: { code: (c: number) => { type: (t: string) => { send: (b: string) => unknown } } }) =>
      reply.code(404).type('text/plain').send('not found');

    app.get<{ Params: { token: string }; Querystring: { fmt?: string } }>('/s/:token', async (req, reply) => {
      if (this.limited(req.ip)) return reply.code(429).send('slow down');
      const u = this.ctx.db.prepare(`SELECT * FROM users WHERE sub_token = ?`).get(req.params.token) as UserRow | undefined;
      if (!u || u.status !== 'active') return notFound(reply);
      const profiles = vpn.profiles(u);
      const t = this.ctx.db.prepare('SELECT up, down FROM traffic WHERE user_id = ? AND period = ?').get(u.id, period()) as { up: number; down: number } | undefined;
      const lim = effectiveLimits(this.ctx, u);
      reply.header('subscription-userinfo',
        `upload=${t?.up ?? 0}; download=${t?.down ?? 0}; total=${lim.trafficGb ? Math.round(lim.trafficGb * 1024 ** 3) : 0}; expire=${lim.expireAt ? Math.floor(Date.parse(lim.expireAt) / 1000) : 0}`);
      reply.header('profile-update-interval', '12');
      reply.header('profile-title', 'base64:' + Buffer.from('Эскадра').toString('base64'));
      // ссылку открыли в браузере — страница с QR, сроком, лимитами и ссылками; приложения получают подписку как обычно
      if (!req.query.fmt && wantsPage(req.headers.accept, req.headers['user-agent'])) {
        const base = subBase(this.ctx);
        const names = new Set<string>();
        for (const p of profiles) {
          names.add(this.ctx.server(p.inbound.server_id).name);
          if (p.mode === 'via' && p.targetName !== 'auto') names.add(p.targetName);
        }
        reply.header('cache-control', 'no-store');
        return reply.type('text/html; charset=utf-8').send(renderSubPage({
          lang: getSetting<string>(this.ctx.db, 'ui.lang', 'ru') === 'en' ? 'en' : 'ru',
          name: u.name, active: u.status === 'active', subUrl: `${base ?? `${tls ? 'https' : 'http'}://${req.headers.host ?? ''}`}/s/${u.sub_token}`,
          expireAt: lim.expireAt, usedBytes: (t?.up ?? 0) + (t?.down ?? 0), limitGb: lim.trafficGb, devices: lim.devices,
          nodes: [...names], links: profiles.map((p) => ({ name: p.name, uri: vpn.link(u, p) })),
        }));
      }
      const ua = String(req.headers['user-agent'] ?? '').toLowerCase();
      const fmt = req.query.fmt ?? (/sing-box|hiddify|karing/.test(ua) ? 'singbox' : 'base64');
      if (fmt === 'singbox') return reply.type('application/json').send(JSON.stringify(singboxConfig(vpn, u, profiles), null, 2));
      // MTProto (tg://) VPN-клиенты не понимают — он выдаётся отдельной ссылкой в карточке пользователя
      const links = profiles.filter((p) => vpn.spec(p.template).protocol !== 'mtproto').map((p) => vpn.link(u, p)).join('\n');
      if (fmt === 'raw') return reply.type('text/plain').send(links);
      return reply.type('text/plain').send(Buffer.from(links).toString('base64'));
    });

    // Knock: фиксирует РЕАЛЬНЫЙ адрес устройства (запрос должен идти без VPN, §13.4)
    app.get<{ Params: { token: string } }>('/k/:token', async (req, reply) => {
      if (this.limited(req.ip)) return reply.code(429).send('slow down');
      const u = this.ctx.db.prepare(`SELECT * FROM users WHERE knock_token = ?`).get(req.params.token) as UserRow | undefined;
      if (!u || u.status !== 'active') return notFound(reply);
      const ip = req.ip.replace(/^::ffff:/, '');
      const ttl = getSetting<number>(this.ctx.db, 'knock.ttlHours', 12) * 3600;
      const r = await pushAllowedIp(this.ctx, u, ip, 'knock', ttl);
      audit(this.ctx.db, `user:${u.name}`, 'knock', u.id, { cidr: r.cidr });
      return reply.type('text/html; charset=utf-8').send(
        `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Эскадра</title>` +
        `<body style="font-family:system-ui;background:#0B1019;color:#E7ECF3;display:grid;place-items:center;min-height:100vh;margin:0">` +
        `<div style="text-align:center;padding:24px"><h1 style="font-weight:600">Доступ открыт</h1>` +
        `<p>Адрес ${r.cidr} разрешён на ${Math.round(ttl / 3600)} ч.</p><p style="color:#97A3B6">Если включён VPN, выключите его и откройте ссылку снова.</p></div>`);
    });

    await app.listen({ host: this.bind, port });
    this.app = app;
    return port;
  }

  async restart() {
    await this.app?.close();
    return this.start();
  }
}
