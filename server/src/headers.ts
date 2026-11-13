import type { FastifyInstance } from 'fastify';

/**
 * Заголовки безопасности панели: её нельзя встроить во фрейм (кликджекинг), секретный путь панели не уходит
 * в Referer на сторонние сайты, браузер не угадывает типы, ответы API не кэшируются, по HTTPS — HSTS.
 */
export function registerSecurityHeaders(app: FastifyInstance, opts: { tls: boolean }) {
  app.addHook('onSend', async (req, reply) => {
    reply.header('X-Frame-Options', 'DENY');
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('Cross-Origin-Opener-Policy', 'same-origin');
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    reply.header('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'");
    if (opts.tls) reply.header('Strict-Transport-Security', 'max-age=31536000');
    if (req.url.includes('/api/')) reply.header('Cache-Control', 'no-store');
  });
}
