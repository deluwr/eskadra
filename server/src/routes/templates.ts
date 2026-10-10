import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { Ctx, guard, HttpError, type TemplateRow } from '../ctx.js';
import { audit } from '../lib/audit.js';
import { Ops, startJob } from '../ops.js';
import { json, Vpn } from '../vpn.js';

const body = z.object({
  name: z.string().trim().min(1).max(48).regex(/^[a-z0-9-]+$/, 'только латиница в нижнем регистре, цифры и дефис'),
  protocol: z.enum(['vless-reality', 'hysteria2']),
  port: z.number().int().min(1).max(65535),
  sni: z.array(z.string().trim().regex(/^[A-Za-z0-9.-]{1,253}$/)).min(1).max(16),
  fingerprint: z.enum(['chrome', 'firefox', 'safari', 'edge', 'random']).default('chrome'),
  ech: z.boolean().default(false),
  nodeIds: z.array(z.string()).default([]),
  entryId: z.string().nullable().default(null),
  entryPort: z.number().int().min(1).max(65535).nullable().default(null),
});

export function templateView(vpn: Vpn, t: TemplateRow) {
  return {
    ...t,
    core: t.core,
    sni: json<string[]>(t.sni, []),
    node_ids: json<string[]>(t.node_ids, []),
    ech: !!t.ech,
    inbounds: vpn.inbounds('template_id = ?', t.id).map((i) => ({ id: i.id, server_id: i.server_id, kind: i.kind, port: i.port, proto: i.proto, state: i.state, error: i.error })),
  };
}

export async function templateRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const ops = new Ops(ctx);
  const vpn = ops.vpn;
  const running = new Set<string>();

  const validate = (b: z.infer<typeof body>) => {
    for (const id of [...b.nodeIds, ...(b.entryId ? [b.entryId] : [])]) ctx.server(id);
    if (b.entryId) {
      if (b.protocol !== 'vless-reality') throw new HttpError(400, 'режим «через вход» пока поддерживается для VLESS · REALITY');
      if (!b.entryPort) throw new HttpError(400, 'укажите порт входа');
    }
  };

  app.get('/api/v1/templates', async () => vpn.templates().map((t) => templateView(vpn, t)));

  app.post('/api/v1/templates', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const b = body.parse(req.body);
    validate(b);
    const id = 'tpl-' + randomBytes(3).toString('hex');
    db.prepare(
      `INSERT INTO templates (id, name, core, protocol, port, sni, fingerprint, ech, node_ids, entry_id, entry_port)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, b.name, b.protocol === 'hysteria2' ? 'sing-box' : 'xray', b.protocol, b.port, JSON.stringify(b.sni), b.fingerprint,
      b.ech ? 1 : 0, JSON.stringify(b.nodeIds), b.entryId, b.entryPort);
    audit(db, req.admin!.username, 'template.create', id, b);
    return templateView(vpn, vpn.template(id)!);
  });

  app.put<{ Params: { id: string } }>('/api/v1/templates/:id', { preHandler: guard(ctx, 'operator') }, async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const b = body.parse(req.body);
    validate(b);
    if (b.protocol !== t.protocol) throw new HttpError(400, 'протокол шаблона менять нельзя — создайте новый');
    db.prepare(
      `UPDATE templates SET name = ?, port = ?, sni = ?, fingerprint = ?, ech = ?, node_ids = ?, entry_id = ?, entry_port = ?,
       revision = revision + 1, updated_at = datetime('now') WHERE id = ?`,
    ).run(b.name, b.port, JSON.stringify(b.sni), b.fingerprint, b.ech ? 1 : 0, JSON.stringify(b.nodeIds), b.entryId, b.entryPort, t.id);
    // узлы, убранные из шаблона, теряют inbound при следующем выкате
    const keep = new Set([...b.nodeIds.map((id) => `${id}:direct`), ...(b.entryId ? [`${b.entryId}:relay`] : [])]);
    for (const ib of vpn.inbounds('template_id = ?', t.id))
      if (!keep.has(`${ib.server_id}:${ib.kind}`)) db.prepare(`UPDATE inbounds SET state = 'removed' WHERE id = ?`).run(ib.id);
    audit(db, req.admin!.username, 'template.update', t.id, b);
    return templateView(vpn, vpn.template(t.id)!);
  });

  app.get<{ Params: { id: string }; Querystring: { server?: string } }>('/api/v1/templates/:id/preview', async (req) => {
    const t = vpn.template(req.params.id);
    if (!t) throw new HttpError(404, 'шаблон не найден');
    const sid = req.query.server ?? json<string[]>(t.node_ids, [])[0] ?? t.entry_id;
    if (!sid) return { config: null };
    const cfg = t.core === 'xray' ? vpn.renderXray(ctx.server(sid)) : vpn.renderSingbox(ctx.server(sid));
    // приватные ключи и UUID в предпросмотре скрываем
    const text = JSON.stringify(cfg, null, 2)
      .replace(/("privateKey": ")[^"]+/g, '$1‹на узле›')
      .replace(/("(?:id|password)": ")[0-9a-f-]{36}/g, '$1‹uuid›');
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
