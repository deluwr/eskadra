import type { Ctx } from './ctx.js';
import type { Vpn } from './vpn.js';
import { certProblems } from './certs.js';
import { coresOff } from './ops.js';
import { backupPassword, backupSettings } from './backup.js';

/**
 * Входы, которые за последние 30 минут дошли до выхода serverId (пробы «Авто» через сам выход): по ним видно, что
 * сервер жив и VPN через вход работает, даже когда панель на него не заходит.
 */
export function seenByEntries(ctx: Ctx, serverId: string): string[] {
  const rows = ctx.db.prepare(`SELECT DISTINCT s.name FROM exit_health h JOIN templates t ON t.id = h.template_id JOIN servers s ON s.id = t.entry_id
    WHERE h.exit_id = ? AND h.ok = 1 AND h.checked_at >= datetime('now', '-30 minutes') ORDER BY s.name`).all(serverId) as Array<{ name: string }>;
  return rows.map((r) => r.name);
}

export interface Attention { level: 'fail' | 'warn' | 'info'; title: string; detail: string; serverId?: string }

/** «Требует внимания»: обзор панели и меню бота. */
export function attentionOf(ctx: Ctx, vpn: Vpn): Attention[] {
  const { db } = ctx;
  const servers = ctx.servers();
  const attention: Attention[] = [];
  for (const s of servers) {
    const protect = s.protection_target !== 'P1';   // при обычной защите про firewall и проверку не напоминаем
    if (s.fail_since) {
      // панель не заходит на сервер, но вход до него доходит: VPN работает, отрезан путь панель → сервер (SSH)
      const via = seenByEntries(ctx, s.id);
      attention.push(via.length
        ? { level: 'warn', title: `${s.name}: панель не видит сервер, а вход ${via.join(', ')} видит`, detail: `VPN через вход работает; не доходит SSH панели (с ${s.fail_since}) — выкат и статистика на нём недоступны. Похоже на блокировку пути с главного сервера: смените канал управления на вкладке «Доступ и SSH».`, serverId: s.id }
        : { level: 'fail', title: `${s.name}: нет связи`, detail: `с ${s.fail_since}`, serverId: s.id });
    }
    if (protect && s.ufw_active) attention.push({ level: 'warn', title: `${s.name}: включён ufw/firewalld`, detail: 'Он мешает защите Эскадры — выключите его на вкладке «Хост».', serverId: s.id });
    if (s.fw_mode === 'pending') attention.push({ level: 'warn', title: `${s.name}: защита ждёт подтверждения`, detail: `до ${s.fw_pending_until}`, serverId: s.id });
    if (protect && s.fw_mode !== 'enforced' && s.sudo_mode === 'restricted' && !s.checklist_passed_at)
      attention.push({ level: 'info', title: `${s.name}: защита не включена`, detail: 'Отметьте проверку доступа на вкладке «Защита», затем включите защиту.', serverId: s.id });
    const off = coresOff(ctx, s.id);
    if (off.length) attention.push({ level: 'warn', title: `${s.name}: ${off.join(', ')} остановлен вручную`, detail: 'Пользователи этого сервера без связи. Запустите ядро на вкладке «Хост».', serverId: s.id });
    for (const p of certProblems(s, (id) => vpn.template(id)?.name)) attention.push({ level: p.level, title: p.title, detail: p.detail, serverId: s.id });
    for (const ib of vpn.inbounds(`server_id = ? AND state = 'error'`, s.id))
      attention.push({ level: 'warn', title: `${s.name}: конфигурация не поднялась`, detail: ib.error ?? '', serverId: s.id });
  }
  if (!backupPassword(ctx)) attention.push({ level: 'warn', title: 'Бэкапы не делаются: не задан пароль бэкапа', detail: 'Задайте пароль и Telegram ID получателей в «Настройках».' });
  else if (backupSettings(db).tgIds.length < 2) attention.push({ level: 'warn', title: 'Бэкапы: меньше двух получателей', detail: 'Если единственный получатель удалит чат, копии пропадут.' });
  return attention;
}
