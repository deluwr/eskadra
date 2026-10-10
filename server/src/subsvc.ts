import Fastify, { type FastifyInstance } from 'fastify';
import fs from 'node:fs';
import { config } from './config.js';
import { randomInt } from 'node:crypto';
import type { Ctx, UserRow } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { effectiveLimits, json, period, Vpn, type Profile } from './vpn.js';
import { pushAllowedIp } from './access.js';
import { audit } from './lib/audit.js';

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
  const outs = profiles.map((p) => {
    const t = p.template;
    const sni = json<string[]>(t.sni, [])[0] ?? '';
    const secret = vpn.cred(u.id, p.credKey);
    if (t.protocol === 'hysteria2')
      return { type: 'hysteria2', tag: p.name, server: p.host, server_port: p.port, password: secret, tls: { enabled: true, server_name: sni, insecure: true } };
    return {
      type: 'vless', tag: p.name, server: p.host, server_port: p.port, uuid: secret, flow: 'xtls-rprx-vision',
      tls: { enabled: true, server_name: sni, utls: { enabled: true, fingerprint: t.fingerprint }, reality: { enabled: true, public_key: p.inbound.public_key, short_id: p.inbound.short_id } },
    };
  });
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
      const ua = String(req.headers['user-agent'] ?? '').toLowerCase();
      const fmt = req.query.fmt ?? (/sing-box|hiddify|karing/.test(ua) ? 'singbox' : 'base64');
      if (fmt === 'singbox') return reply.type('application/json').send(JSON.stringify(singboxConfig(vpn, u, profiles), null, 2));
      const links = profiles.map((p) => vpn.link(u, p)).join('\n');
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
