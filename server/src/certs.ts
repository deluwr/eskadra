import type { ServerRow } from './ctx.js';

/**
 * TLS-сертификаты узлов. Let's Encrypt продлевает сам узел (таймер eskadra-certbot, дважды в сутки);
 * панель раз в несколько часов читает сроки и результат последнего продления (fleet-core cert-status)
 * и предупреждает, если продление не удаётся или срок подходит к концу.
 */
export interface TlsState {
  checkedAt: string;
  certs: Array<{ name: string; notAfter: string | null; le: boolean }>;
  /** holder — кто держал порт 80, когда продление не прошло: программа, pid, служба systemd (её можно остановить из панели) */
  renew: { at: string; code: number; err: string; holder?: { name: string; pid: string; unit: string } | null } | null;
  timer: boolean;
  /** службы, которые останавливаются на время выпуска и продления (порт 80 для Let's Encrypt) и сразу запускаются обратно */
  port80Units?: string[];
}

export interface CertProblem { key: string; level: 'fail' | 'warn'; title: string; detail: string }

export function parseCertStatus(out: string, now = new Date()): TlsState {
  const certs: TlsState['certs'] = [];
  const kv: Record<string, string> = {};
  for (const line of out.split('\n')) {
    const m = line.match(/^cert (\S+) (\d+) ([01])$/);
    if (m) { certs.push({ name: m[1]!, notAfter: m[2] !== '0' ? new Date(Number(m[2]) * 1000).toISOString() : null, le: m[3] === '1' }); continue; }
    const k = line.match(/^([a-z0-9_]+)=(.*)$/);
    if (k) kv[k[1]!] = k[2]!;
  }
  return {
    checkedAt: now.toISOString(),
    certs,
    renew: kv.renew_at ? { at: new Date(Number(kv.renew_at) * 1000).toISOString(), code: Number(kv.renew_code ?? 0), err: (kv.renew_err ?? '').trim(), holder: holderOf(kv.renew_holder) } : null,
    timer: kv.timer === 'active',
    port80Units: kv.port80_units ? kv.port80_units.split(',').filter(Boolean) : [],
  };
}

/** «nginx|812|nginx.service» → кто держит порт 80. */
const holderOf = (v?: string) => {
  if (!v) return null;
  const [name = '?', pid = '', unit = ''] = v.trim().split('|');
  return { name, pid, unit };
};

/** Кто мешает Let's Encrypt: «порт 80 занят: nginx (служба nginx.service)». */
export const holderText = (h: { name: string; unit: string }) => `порт 80 занят: ${h.name}${h.unit ? ` (служба ${h.unit})` : ''}`;

/** Понятное имя сертификата: ip — на IP сервера, dom-<домен>, tpl-<id> — загруженный для конфигурации, cdn-<id> — входа за CDN. */
export function certLabel(name: string, templateName?: (id: string) => string | undefined): string {
  if (name === 'ip') return 'сертификат на IP';
  if (name.startsWith('dom-')) return `сертификат ${name.slice(4)}`;
  if (name.startsWith('tpl-')) return `загруженный сертификат «${templateName?.(name) ?? name}»`;
  if (name.startsWith('cdn-')) return 'сертификат входа за CDN';
  return `сертификат ${name}`;
}

const left = (iso: string, now: number) => {
  const ms = Date.parse(iso) - now;
  const h = Math.floor(ms / 3600_000);
  return h >= 48 ? `${Math.floor(h / 24)} дн` : `${Math.max(h, 0)} ч`;
};

export function certProblems(s: Pick<ServerRow, 'id' | 'name'> & { tls_state: string | null }, templateName?: (id: string) => string | undefined, now = Date.now()): CertProblem[] {
  if (!s.tls_state) return [];
  let st: TlsState;
  try { st = JSON.parse(s.tls_state) as TlsState; } catch { return []; }
  const out: CertProblem[] = [];
  const renewFailed = !!st.renew && st.renew.code !== 0;
  // порт 80 занят чужой программой — главное в ошибке; её можно остановить кнопкой на вкладке «Хост»
  const why = st.renew?.holder ? `${holderText(st.renew.holder)} — на вкладке «Хост» включите её остановку на время продления` : st.renew?.err ?? '';
  for (const c of st.certs) {
    if (!c.notAfter) continue;
    const label = certLabel(c.name, templateName);
    const ms = Date.parse(c.notAfter) - now;
    const key = `${s.id}:${c.name}`;
    if (ms <= 0) {
      out.push({ key: `${key}:expired`, level: 'fail', title: `${s.name}: ${label} истёк`, detail: c.le ? `Клиенты с TLS не подключатся. Продление не прошло${renewFailed ? `: ${why}` : ''}. Нажмите «Продлить сейчас» на вкладке «Хост».` : 'Клиенты с TLS не подключатся. Загрузите новый сертификат в конфигурации.' });
    } else if (c.le && ms < 2 * 86400_000) {
      out.push({ key: `${key}:soon`, level: 'fail', title: `${s.name}: ${label} не продлён`, detail: `Истекает через ${left(c.notAfter, now)}.${renewFailed ? ` Ошибка продления: ${why}.` : ''}${st.renew?.holder ? '' : ' Проверьте, открыт ли порт 80 снаружи.'}` });
    } else if (!c.le && ms < 14 * 86400_000) {
      out.push({ key: `${key}:upload`, level: 'warn', title: `${s.name}: ${label} истекает через ${left(c.notAfter, now)}`, detail: 'Он не продлевается сам — загрузите новый в конфигурации.' });
    }
  }
  const le = st.certs.some((c) => c.le);
  if (le && renewFailed && !out.some((p) => p.level === 'fail')) out.push({ key: `${s.id}:renew`, level: 'warn', title: `${s.name}: не удалось продлить сертификат`, detail: `${why || 'certbot завершился с ошибкой'}. Сертификат пока действует; узел повторит попытку через 12 часов.` });
  if (le && !st.timer) out.push({ key: `${s.id}:timer`, level: 'warn', title: `${s.name}: продление сертификатов выключено`, detail: 'Таймер eskadra-certbot не активен — нажмите «Продлить сейчас» на вкладке «Хост», он включится.' });
  return out;
}
