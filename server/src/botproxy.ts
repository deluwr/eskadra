/**
 * Прокси для Telegram-бота (§4.5): если с главного сервера api.telegram.org недоступен, бот ходит через одну из
 * конфигураций флота. Xray-клиент на главном сервере (тот же, что держит туннели управления, mgmt.ts) открывает
 * HTTP-прокси на 127.0.0.1 и выводит его через выбранный inbound узла под служебным клиентом «svc.bot».
 */
import { randomInt } from 'node:crypto';
import { getSetting, setSetting } from './db.js';
import type { Ctx, ServerRow, TemplateRow } from './ctx.js';
import { PROTOCOLS, specOf, xrayOutbound } from './protocols.js';
import { Vpn } from './vpn.js';

export interface BotProxySetting { enabled: boolean; serverId: string; templateId: string; port: number }

const KEY = 'bot.proxy';

export function botProxySetting(ctx: Ctx): BotProxySetting {
  return getSetting<BotProxySetting>(ctx.db, KEY, { enabled: false, serverId: '', templateId: '', port: 0 });
}

export function saveBotProxy(ctx: Ctx, s: Omit<BotProxySetting, 'port'>): BotProxySetting {
  const cur = botProxySetting(ctx);
  let port = cur.port;
  if (!port) do port = randomInt(40000, 50000); while (ctx.servers().some((x) => x.mgmt_local_port === port));
  const next = { ...s, port };
  setSetting(ctx.db, KEY, next);
  return next;
}

/** Конфигурации, через которые может ходить бот: активные прямые inbounds протоколов Xray на узлах (не на самом главном сервере). */
export function botProxyOptions(ctx: Ctx) {
  const vpn = new Vpn(ctx);
  const out: Array<{ serverId: string; serverName: string; templateId: string; templateName: string; protocol: string }> = [];
  for (const t of vpn.templates()) {
    const sp = specOf(t);
    if (PROTOCOLS[sp.protocol].core !== 'xray') continue;
    for (const ib of vpn.inbounds(`template_id = ? AND kind = 'direct' AND state = 'active'`, t.id)) {
      const s = ctx.servers().find((x) => x.id === ib.server_id);
      if (!s || s.mgmt_mode === 'local') continue;
      out.push({ serverId: s.id, serverName: s.name, templateId: t.id, templateName: t.name, protocol: PROTOCOLS[sp.protocol].name });
    }
  }
  return out;
}

/**
 * Пара «сервер + конфигурация», через которую ходит бот. Выбранную удалили (или её inbound снят) — берётся другая
 * доступная, сначала на том же сервере (fallback): без этого бот молча шёл напрямую, а с главного сервера в РФ
 * Telegram недоступен — уведомления переставали приходить. Запасная пара ходит под служебным клиентом svc.mgmt,
 * который уже есть во всех inbound'ах узлов, — работает сразу, без перевыката.
 */
export function activeBotProxy(ctx: Ctx): { setting: BotProxySetting; server: ServerRow; template: TemplateRow; fallback: boolean } | null {
  const st = botProxySetting(ctx);
  if (!st.enabled || !st.port) return null;
  const vpn = new Vpn(ctx);
  const server = ctx.servers().find((s) => s.id === st.serverId);
  const template = vpn.template(st.templateId);
  const live = server && template && vpn.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct' AND state = 'active'`, template.id, server.id).length > 0;
  if (live) return { setting: st, server: server!, template: template!, fallback: false };
  const opts = botProxyOptions(ctx);
  const pick = opts.find((o) => o.serverId === st.serverId) ?? opts[0];
  if (!pick) return null;
  return { setting: st, server: ctx.server(pick.serverId), template: vpn.template(pick.templateId)!, fallback: true };
}

/** Служебный секрет первичного доступа через прокси (onboard.ts): клиент svc.mgmt есть в каждом inbound Xray узлов. */
export const mgmtCredKey = (templateId: string, serverId: string) => `mgmt:${templateId}:${serverId}`;

/** Служебный секрет бота для выбранной конфигурации (клиент добавляется в inbound узла, vpn.directClients). */
export const botCredKey = (templateId: string, serverId: string) => `bot:${templateId}:${serverId}`;

/** Часть конфига Xray-клиента главного сервера: HTTP-прокси 127.0.0.1:<порт> → inbound узла. */
export function botProxyClientPart(ctx: Ctx): { inbound: object; outbound: object; rule: object } | null {
  const a = activeBotProxy(ctx);
  if (!a) return null;
  const vpn = new Vpn(ctx);
  const ib = vpn.inbounds(`template_id = ? AND server_id = ? AND kind = 'direct' AND state = 'active'`, a.template.id, a.server.id)[0];
  if (!ib) return null;
  const sp = specOf(a.template);
  const secret = vpn.svcCred(a.fallback ? mgmtCredKey(a.template.id, a.server.id) : botCredKey(a.template.id, a.server.id));
  return {
    inbound: { tag: 'bot-in', listen: '127.0.0.1', port: a.setting.port, protocol: 'http', settings: {} },
    outbound: xrayOutbound(sp, ib, 'bot-out', a.server.host, secret, a.server.id),
    rule: { type: 'field', inboundTag: ['bot-in'], outboundTag: 'bot-out' },
  };
}
