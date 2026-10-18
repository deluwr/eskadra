import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { guard, HttpError, type Ctx } from '../ctx.js';
import { audit } from '../lib/audit.js';
import { analyticsSummary, buildDiagnostics, diagFileName } from '../analytics.js';

export async function analyticsRoutes(app: FastifyInstance, ctx: Ctx) {
  let building = false;

  /** Нагрузка серверов за 48 ч (срезы раз в 5 минут) и потери связи. */
  app.get('/api/v1/analytics', async () => analyticsSummary(ctx));

  /** Файл диагностики (Markdown) для разбора человеком или нейросетью: собирается по запросу, по одному за раз. */
  app.get<{ Querystring: { hours?: string } }>('/api/v1/analytics/export', { preHandler: guard(ctx, 'servers.manage') }, async (req, reply) => {
    const hours = z.coerce.number().int().min(1).max(48).catch(48).parse(req.query.hours);
    if (building) throw new HttpError(409, 'выгрузка уже собирается — подождите минуту');
    building = true;
    try {
      const md = await buildDiagnostics(ctx, hours);
      audit(ctx.db, req.admin!.username, 'analytics.export', undefined, { hours, bytes: md.length });
      return reply
        .header('content-type', 'text/markdown; charset=utf-8')
        .header('content-disposition', `attachment; filename="${diagFileName(hours)}"`)
        .header('cache-control', 'no-store')
        .send(md);
    } finally {
      building = false;
    }
  });
}
