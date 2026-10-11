import type { FastifyInstance } from 'fastify';
import { createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { getSetting, setSetting } from '../db.js';
import { z } from 'zod';
import { Ctx, guard, HttpError, type TemplateRow } from '../ctx.js';
import { audit } from '../lib/audit.js';
import { Ops, startJob } from '../ops.js';
import { json, Vpn } from '../vpn.js';
import { PROTOCOLS, SS_METHODS, specOf, type Protocol } from '../protocols.js';

const settingsBody = z.object({
  security: z.enum(['reality', 'tls', 'none']).optional(),
  transport: z.enum(['tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade']).optional(),
  flow: z.enum(['', 'xtls-rprx-vision']).optional(),
  path: z.string().max(256).regex(/^\/[\x21-\x7e]*$/, 'путь начинается с /').optional(),
  host: z.string().max(253).regex(/^[A-Za-z0-9.-]*$/).optional(),
  serviceName: z.string().max(64).regex(/^[A-Za-z0-9._-]*$/).optional(),
  xhttpMode: z.enum(['auto', 'packet-up', 'stream-up', 'stream-one']).optional(),
  alpn: z.array(z.enum(['h3', 'h2', 'http/1.1'])).max(3).optional(),
  certMode: z.enum(['ip', 'domain', 'custom', 'self']).optional(),
  domain: z.string().max(253).regex(/^[A-Za-z0-9.*-]*$/).optional(),
  domains: z.record(z.string(), z.string().max(253).regex(/^[A-Za-z0-9.-]+$/)).optional(),
  ssMethod: z.enum(SS_METHODS).optional(),
  hy2Obfs: z.string().max(128).optional(),
  mtDomain: z.string().max(253).regex(/^[A-Za-z0-9.-]*$/).optional(),
  sniffing: z.boolean().optional(),
  autoMode: z.enum(['random', 'smart', 'order']).optional(),
  exitOrder: z.array(z.string().max(64)).max(64).optional(),
  maxRttMs: z.number().int().min(20).max(2000).optional(),
  minMbps: z.number().min(0.5).max(10000).optional(),
  checkMin: z.number().int().min(5).max(1440).optional(),
  testMB: z.number().int().min(1).max(100).optional(),
}).default({});

const TRANSLIT: Record<string, string> = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya' };
/** Имя конфигурации: строчная латиница, цифры и дефис — регистр и пробелы исправляются сами, кириллица транслитерируется. */
export const slugName = (v: string) => v.toLowerCase().split('').map((c) => TRANSLIT[c] ?? c).join('')
  .replace(/[\s_.]+/g, '-').replace(/[^a-z0-9-]/g, '').replace(/-+/g, '-').replace(/^-/, '').slice(0, 48);

const body = z.object({
  name: z.preprocess((v) => (typeof v === 'string' ? slugName(v).replace(/-$/, '') : v), z.string().min(1, 'имя: укажите латиницей или цифрами').max(48)),
  protocol: z.enum(['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'mtproto']),
  port: z.number().int().min(1).max(65535),
  sni: z.array(z.string().trim().regex(/^[A-Za-z0-9.-]{1,253}$/)).max(16).default([]),
  fingerprint: z.enum(['chrome', 'firefox', 'safari', 'edge', 'random']).default('chrome'),
  ech: z.boolean().default(false),
  nodeIds: z.array(z.string()).default([]),
  entryId: z.string().nullable().default(null),
  entryPort: z.number().int().min(1).max(65535).nullable().default(null),
  settings: settingsBody,
  /** загруженный сертификат (режим custom): полная цепочка и ключ в PEM; хранится зашифрованным */
  customCert: z.object({ fullchain: z.string().max(65536), privkey: z.string().max(16384) }).optional(),
});

let ctx_hasCert: (t: TemplateRow) => boolean = () => false;

export function templateView(vpn: Vpn, t: TemplateRow) {
  return {
    ...t,
    core: t.core,
    sni: json<string[]>(t.sni, []),
    spec: specOf(t),
    hasCustomCert: !!ctx_hasCert(t),
    node_ids: json<string[]>(t.node_ids, []),
    ech: !!t.ech,
    inbounds: vpn.inbounds('template_id = ?', t.id).map((i) => ({ id: i.id, server_id: i.server_id, kind: i.kind, port: i.port, proto: i.proto, state: i.state, error: i.error })),
  };
}

export async function templateRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const ops = new Ops(ctx);
  const vpn = ops.vpn;
  ctx_hasCert = (t) => !!getSetting(db, `cert.${t.id}`, null);
  const running = new Set<string>();
  /** Загруженный сертификат шаблона (режим custom): проверяем, что ключ подходит к сертификату, храним зашифрованным. */
  const saveCert = (id: string, c?: { fullchain: string; privkey: string }) => {
    if (!c) return;
    try {
      const cert = new X509Certificate(c.fullchain);
      if (!cert.checkPrivateKey(createPrivateKey(c.privkey))) throw new Error('ключ не подходит к сертификату');
      if (new Date(cert.validTo) < new Date()) throw new Error(`сертификат истёк ${cert.validTo}`);
    } catch (e) {
      throw new HttpError(400, `сертификат: ${(e as Error).message}`);
    }
    setSetting(db, `cert.${id}`, { fullchain: c.fullchain, privkey: ctx.seal(c.privkey) });
  };

  const validate = (b: z.infer<typeof body>) => {
    for (const id of [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])]) ctx.server(id);
    const info = PROTOCOLS[b.protocol as Protocol];
    if (b.entryId) {
      if (!info.relay) throw new HttpError(400, `режим «через вход» не поддерживается для ${info.name}`);
      if (!b.entryPort) throw new HttpError(400, 'укажите порт входа');
    }
    const sp = specOf({ protocol: b.protocol, sni: JSON.stringify(b.sni), fingerprint: b.fingerprint, settings: JSON.stringify(b.settings) });
    if (sp.security === 'reality' && !b.sni.length) throw new HttpError(400, 'для REALITY укажите сайт маскировки (SNI)');
    if (sp.transport === 'xhttp' && sp.protocol !== 'vless') throw new HttpError(400, 'XHTTP — только для VLESS');
    if ((sp.security === 'tls' || sp.protocol === 'hysteria2') && sp.certMode === 'domain')
      for (const id of [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])])
        if (!sp.domains[id]) throw new HttpError(400, `укажите домен для сервера ${ctx.server(id).name}`);
    if ((sp.security === 'tls' || sp.protocol === 'hysteria2') && sp.certMode === 'ip')
      for (const id of [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])])
        if (!/^[0-9.]+$|:/.test(ctx.server(id).host)) throw new HttpError(400, `сертификат на IP: у сервера ${ctx.server(id).name} адрес — домен; выберите «свой домен»`);
  };

  app.get('/api/v1/templates', async () => vpn.templates().map((t) => templateView(vpn, t)));

  app.post('/api/v1/templates', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const b = body.parse(req.body);
    validate(b);
    const id = 'tpl-' + randomBytes(3).toString('hex');
    db.prepare(
      `INSERT INTO templates (id, name, core, protocol, port, sni, fingerprint, ech, node_ids, entry_id, entry_port, settings)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, b.name, PROTOCOLS[b.protocol as Protocol].core, b.protocol, b.port, JSON.stringify(b.sni), b.fingerprint,
      b.ech ? 1 : 0, JSON.stringify(b.nodeIds), b.entryId, b.entryPort, JSON.stringify(b.settings));
    saveCert(id, b.customCert);
    audit(db, req.admin!.username, 'template.create', id, b);
    return templateView(vpn, vpn.template(id)!);
  });

  app.put<{ Params: { id: string } }>('/api/v1/templates/:id', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const b = body.parse(req.body);
    validate(b);
    if (b.protocol !== specOf(t).protocol) throw new HttpError(400, 'протокол шаблона менять нельзя — создайте новый');
    db.prepare(
      `UPDATE templates SET name = ?, port = ?, sni = ?, fingerprint = ?, ech = ?, node_ids = ?, entry_id = ?, entry_port = ?, settings = ?,
       revision = revision + 1, updated_at = datetime('now') WHERE id = ?`,
    ).run(b.name, b.port, JSON.stringify(b.sni), b.fingerprint, b.ech ? 1 : 0, JSON.stringify(b.nodeIds), b.entryId, b.entryPort, JSON.stringify(b.settings), t.id);
    saveCert(t.id, b.customCert);
    // узлы, убранные из шаблона, теряют inbound при следующем выкате
    const keep = new Set([...b.nodeIds.map((id) => `${id}:direct`), ...(b.entryId ? [`${b.entryId}:relay`] : [])]);
    for (const ib of vpn.inbounds('template_id = ?', t.id))
      if (!keep.has(`${ib.server_id}:${ib.kind}`)) db.prepare(`UPDATE inbounds SET state = 'removed' WHERE id = ?`).run(ib.id);
    audit(db, req.admin!.username, 'template.update', t.id, b);
    return templateView(vpn, vpn.template(t.id)!);
  });

  /** Состояние выходов «Авто через вход»: последние замеры и выбранный выход. */
  app.get<{ Params: { id: string } }>('/api/v1/templates/:id/health', async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const rows = db.prepare(`SELECT h.exit_id, s.name, h.rtt_ms, h.mbps, h.ok, h.error, h.checked_at FROM exit_health h JOIN servers s ON s.id = h.exit_id WHERE h.template_id = ? ORDER BY s.name`).all(t.id);
    const ov = getSetting<string | null>(db, `auto.override.${t.id}`, null);
    const act = getSetting<string | null>(db, `auto.actual.${t.id}`, null);
    const id = (tag: string | null) => (tag ? tag.slice(`to-${t.id}-`.length) : null);
    // selected — что назначила панель; actual — через какой выход вход реально ведёт трафик (по данным Xray входа)
    return { rows, selected: id(ov), actual: id(act), checkedAt: getSetting<string>(db, `auto.checked.${t.id}`, '') || null };
  });

  app.post<{ Params: { id: string } }>('/api/v1/templates/:id/health/check', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const lines: string[] = [];
    const r = await ops.checkExits(t, (l) => lines.push(l));
    if (!r) throw new HttpError(409, 'проверка выходов работает для конфигурации со входом и режимом «по качеству»');
    audit(db, req.admin!.username, 'template.exits_check', t.id, { switched: r.switched });
    return { ...r, log: lines };
  });

  app.get<{ Params: { id: string }; Querystring: { server?: string } }>('/api/v1/templates/:id/preview', async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const sid = req.query.server ?? json<string[]>(t.node_ids, [])[0] ?? t.entry_id;
    if (!sid) return { config: null };
    const s = ctx.server(sid);
    const cfg = t.core === 'xray' ? vpn.renderXray(s) : t.core === 'sing-box' ? vpn.renderSingbox(s) : vpn.renderTelemt(s);
    if (!cfg) return { server: sid, config: null };
    // приватные ключи, UUID, пароли и секреты MTProto в предпросмотре скрываем
    const text = (typeof cfg === 'string' ? cfg : JSON.stringify(cfg, null, 2))
      .replace(/("privateKey": ")[^"]+/g, '$1‹на узле›')
      .replace(/("(?:id|password)": ")[^"]+/g, '$1‹секрет›')
      .replace(/^(".+" = ")[0-9a-f]{32}"/gm, '$1‹секрет›"');
    return { server: sid, config: text };
  });

  app.post<{ Params: { id: string } }>('/api/v1/templates/:id/rollout', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    if (running.has(t.id)) throw new HttpError(409, 'выкат этого шаблона уже идёт');
    const job = startJob(ctx, null, `rollout:${t.name}`);
    running.add(t.id);
    audit(db, req.admin!.username, 'template.rollout', t.id, { revision: t.revision });
    // выкат идёт в фоне; UI опрашивает задачу
    void (async () => {
      try {
        // снять inbounds, убранные из шаблона
        const removed = vpn.inbounds(`template_id = ? AND state = 'removed'`, t.id);
        for (const sid of [...new Set(removed.map((i) => i.server_id))]) {
          const s = ctx.server(sid);
          await ctx.onNode(s, async (n) => {
            await ops.applyServer(s, n, job.log);
            for (const ib of removed.filter((i) => i.server_id === sid))
              if (!ops.portUsed(sid, ib.port, ib.proto)) await n.op(['port-close', ib.proto, ib.port]);
          });
          db.prepare(`DELETE FROM inbounds WHERE template_id = ? AND server_id = ? AND state = 'removed'`).run(t.id, sid);
        }
        await ops.rollout(vpn.template(t.id)!, job.log);
        job.log('готово');
        job.finish('ok');
      } catch (e) {
        job.log(`остановлено: ${(e as Error).message}`);
        job.finish('failed');
      } finally {
        running.delete(t.id);
      }
    })();
    return { jobId: job.id };
  });

  app.get<{ Params: { jobId: string } }>('/api/v1/jobs/:jobId', async (req) =>
    db.prepare('SELECT * FROM jobs WHERE id = ?').get(Number(req.params.jobId)));

  app.delete<{ Params: { id: string } }>('/api/v1/templates/:id', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const job = startJob(ctx, null, `remove:${t.name}`);
    await ops.removeTemplate(t, job.log);
    job.finish('ok');
    audit(db, req.admin!.username, 'template.delete', t.id);
    return { ok: true };
  });
}
