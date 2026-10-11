import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { coreMode, Ctx, foreignCore, guard, HttpError } from '../ctx.js';
import { getSetting, setSetting } from '../db.js';
import { audit } from '../lib/audit.js';
import { Ops, startJob } from '../ops.js';
import { cmpVersion, listReleases, type Core } from '../releases.js';
import { json } from '../vpn.js';

const CORES: Core[] = ['xray', 'sing-box', 'telemt'];
const coreParam = z.enum(['xray', 'sing-box', 'telemt']);
const versionBody = z.object({ version: z.string().regex(/^(latest|v?\d+\.\d+\.\d+([-.][A-Za-z0-9.]+)?)$/).default('latest') });

export async function coreRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;
  const ops = new Ops(ctx);
  const running = new Set<string>();

  /** Версии ядер по флоту, последние релизы и закреплённые версии. */
  app.get('/api/v1/cores', async () => {
    const releases: Record<string, unknown> = {};
    const errors: string[] = [];
    for (const c of CORES) {
      try { releases[c] = await listReleases(c); } catch (e) { releases[c] = []; errors.push(`${c}: ${(e as Error).message}`); }
    }
    const latest = Object.fromEntries(CORES.map((c) => [c, (releases[c] as Array<{ version: string; prerelease: boolean }>).find((r) => !r.prerelease)?.version ?? null]));
    return {
      latest,
      releases,
      pins: getSetting<Record<string, string>>(db, 'cores.pin', {}),
      errors,
      servers: ctx.servers().filter((s) => s.sudo_mode === 'restricted').map((s) => {
        const cores = json<Record<string, { version: string; previous?: string }>>(s.cores, {});
        return {
          id: s.id, name: s.name, mode: coreMode(s),
          xray: cores.xray ?? null, singbox: cores['sing-box'] ?? null, xui: cores.xui ?? null,
          outdated: CORES.filter((c) => cores[c] && latest[c] && cmpVersion(cores[c]!.version, latest[c]!) < 0),
        };
      }),
    };
  });

  app.put('/api/v1/cores/pin', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const b = z.object({ core: coreParam, version: versionBody.shape.version }).parse(req.body);
    const pins = getSetting<Record<string, string>>(db, 'cores.pin', {});
    pins[b.core] = b.version.replace(/^v/, '');
    setSetting(db, 'cores.pin', pins);
    audit(db, req.admin!.username, 'core.pin', b.core, { version: b.version });
    return pins;
  });

  app.post<{ Params: { id: string; core: string } }>('/api/v1/servers/:id/cores/:core/update', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const s = ctx.server(req.params.id);
    const core = coreParam.parse(req.params.core);
    const { version } = versionBody.parse(req.body ?? {});
    const job = startJob(ctx, s.id, `core.update:${core}`);
    try {
      const v = await ops.upgradeCore(s, core, version, job.log);
      job.finish('ok');
      audit(db, req.admin!.username, 'core.update', s.id, { core, version: v });
      return { version: v, jobId: job.id };
    } catch (e) {
      job.log(`ошибка: ${(e as Error).message}`);
      job.finish('failed');
      throw new HttpError(500, (e as Error).message, { jobId: job.id });
    }
  });

  app.get<{ Params: { id: string } }>('/api/v1/servers/:id/cores/state', async (req) => {
    const s = ctx.server(req.params.id);
    if (s.sudo_mode !== 'restricted') return {};
    return ops.coreStates(s);
  });

  /** Ручное включение/выключение ядра — например, проверить, что «Авто» уходит на другой выход. */
  app.post<{ Params: { id: string; core: string } }>('/api/v1/servers/:id/cores/:core/power', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const s = ctx.server(req.params.id);
    const core = coreParam.parse(req.params.core);
    const { on } = z.object({ on: z.boolean() }).parse(req.body);
    if (core === 'xray' && coreMode(s) === 'xui') throw new HttpError(409, 'Xray этого узла принадлежит 3x-ui — управляйте им там');
    try {
      const out = await ops.setCorePower(s, core, on);
      audit(db, req.admin!.username, on ? 'core.start' : 'core.stop', s.id, { core });
      return { output: out, state: await ops.coreStates(s) };
    } catch (e) { throw new HttpError(500, (e as Error).message); }
  });

  app.post<{ Params: { id: string; core: string } }>('/api/v1/servers/:id/cores/:core/rollback', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const s = ctx.server(req.params.id);
    const core = coreParam.parse(req.params.core);
    const job = startJob(ctx, s.id, `core.rollback:${core}`);
    try {
      const v = await ops.rollbackCore(s, core, job.log);
      job.finish('ok');
      audit(db, req.admin!.username, 'core.rollback', s.id, { core, version: v });
      return { version: v };
    } catch (e) {
      job.log(`ошибка: ${(e as Error).message}`);
      job.finish('failed');
      throw new HttpError(500, (e as Error).message, { jobId: job.id });
    }
  });

  /** Обновление ядра по флоту волнами (§11.3): canary → остальные по одному; первая ошибка останавливает выкат. */
  app.post<{ Params: { core: string } }>('/api/v1/cores/:core/rollout', { preHandler: guard(ctx, 'admin') }, async (req) => {
    const core = coreParam.parse(req.params.core);
    const b = versionBody.extend({ serverIds: z.array(z.string()).optional() }).parse(req.body ?? {});
    if (running.has(core)) throw new HttpError(409, `обновление ${core} уже идёт`);
    // узлы, где ядра ещё нет, тоже: обновление ставит его (кроме Xray из 3x-ui и узлов с чужим ядром)
    const targets = ctx.servers().filter((s) =>
      s.sudo_mode === 'restricted' && !(core === 'xray' && coreMode(s) === 'xui') &&
      (json<Record<string, unknown>>(s.cores, {})[core] || !foreignCore(s, core)) &&
      (!b.serverIds || b.serverIds.includes(s.id)));
    if (!targets.length) throw new HttpError(409, `нет узлов, где можно поставить или обновить ${core}`);
    const job = startJob(ctx, null, `core.rollout:${core}`);
    running.add(core);
    audit(db, req.admin!.username, 'core.rollout', core, { version: b.version, servers: targets.map((t) => t.name) });
    void (async () => {
      try {
        for (const [i, s] of targets.entries()) {
          job.log(`${i === 0 ? 'canary' : 'волна'}: ${s.name}`);
          await ops.upgradeCore(ctx.server(s.id), core, b.version, job.log);
        }
        job.log('готово');
        job.finish('ok');
      } catch (e) {
        job.log(`остановлено: ${(e as Error).message}`);
        job.finish('failed');
      } finally {
        running.delete(core);
      }
    })();
    return { jobId: job.id, servers: targets.map((t) => t.name) };
  });
}
