export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly body: Record<string, unknown>) {
    super(message);
  }
}

/** Запрос кода 2FA: App подставляет модальное окно. */
let otpProvider: (() => Promise<string | null>) | null = null;
export const setOtpProvider = (fn: () => Promise<string | null>) => { otpProvider = fn; };

async function call<T>(method: string, url: string, body?: unknown, otp?: string): Promise<T> {
  // относительный путь: панель может жить под случайным базовым путём (/k3x9…/)
  const res = await fetch(url.replace(/^\//, ''), {
    method,
    credentials: 'same-origin',
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      'X-Fleet': '1',
      ...(otp ? { 'X-Fleet-OTP': otp } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (res.status === 428 && data.kind === 'otp' && !otp && otpProvider) {
    const code = await otpProvider();
    if (code) return call<T>(method, url, body, code);
  }
  if (!res.ok) {
    const lint = Array.isArray(data.lint) ? ': ' + (data.lint as string[]).join('; ') : '';
    throw new ApiError(String(data.error ?? `HTTP ${res.status}`) + lint, res.status, data);
  }
  return data as T;
}

export const api = {
  get: <T>(url: string) => call<T>('GET', url),
  post: <T>(url: string, body: unknown = {}) => call<T>('POST', url, body),
  put: <T>(url: string, body: unknown) => call<T>('PUT', url, body),
  patch: <T>(url: string, body: unknown) => call<T>('PATCH', url, body),
  del: <T>(url: string) => call<T>('DELETE', url),
};

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info';
export interface Check { id: string; title: string; status: CheckStatus; detail: string }

export interface Server {
  id: string; name: string; host: string; ssh_port: number; role: string; status: string; group_name: string;
  host_key_fp: string | null; host_key_pending_fp: string | null; sudo_mode: 'bootstrap' | 'restricted';
  ssh_mode: 'loose' | 'strict' | 'shell'; protection_target: 'P1' | 'P2' | 'P3'; protection_current: string;
  fw_mode: string; fw_pending_until: string | null; seen_from_ip: string | null; os_info: { pretty: string } | null;
  last_seen_at: string | null; fail_since: string | null; direct_access: number; peer_ssh: string; key_only: number;
  ufw_active: number; ssh_ports: number[]; admin_ips: string[]; cores: Record<string, { version: string }>;
  checklist_passed_at: string | null; kit_version: string | null; stage: number; executorOk: boolean; created_at: string;
  core_mode: 'auto' | 'own' | 'xui'; coreModeEffective: 'own' | 'xui'; xuiConfigured: boolean; xui_user: string | null;
  tls_state: { checkedAt: string; certs: Array<{ name: string; notAfter: string | null; le: boolean }>; renew: { at: string; code: number; err: string } | null; timer: boolean } | null;
  certProblems: Array<{ key: string; level: 'fail' | 'warn'; title: string; detail: string }>;
  external_cores: Array<{ name: string; active: string; version: string }>;
  mgmt_mode: 'direct' | 'tunnel' | 'local'; config_dirty: number;
  mgmt: { via: string | null; mode: 'direct' | 'tunnel' | 'local'; port: number | null; sni: string | null; localPort: number | null; client: { running: boolean; version: string | null; error: string | null } | null };
}

export interface Preflight { checks: Check[]; sshPorts: number[]; clientIp: string | null; ufwActive: boolean; blocking: boolean; baselinePath?: string; created_at?: string }
export interface Job { id: number; kind: string; status: string; started_at: string; finished_at: string | null; log?: string }
export interface ChecklistItem { id: string; title: string; auto: boolean; done: boolean }
export interface InboundView { id: string; kind: string; port: number; proto: string; state: string; error: string | null; template: string; protocol: string; core: string }

export interface ServerDetail {
  server: Server; snippet: string | null; preflight: Preflight | null; jobs: Job[]; inbounds: InboundView[];
  checklist: { items: ChecklistItem[]; passedAt: string | null; done: number; total: number };
  nodekitVersion: string; kvmCommand: string | null;
  onboarding: { running: boolean; job: { id: number; status: string; log: string; started_at: string; finished_at: string | null } | null };
}

export interface Template {
  id: string; name: string; core: string; protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'mtproto'; port: number; sni: string[]; fingerprint: string;
  spec: { protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'mtproto'; security: 'reality' | 'tls' | 'none'; transport: 'tcp' | 'ws' | 'grpc' | 'xhttp' | 'httpupgrade'; autoMode?: 'random' | 'smart'; [k: string]: unknown };
  hasCustomCert: boolean;
  ech: boolean; node_ids: string[]; entry_id: string | null; entry_port: number | null; revision: number; applied_revision: number;
  inbounds: Array<{ id: string; server_id: string; kind: string; port: number; proto: string; state: string; error: string | null }>;
}

export interface User {
  id: string; name: string; tg_id: string | null; status: 'active' | 'disabled'; disabled_reason: string | null; limit_group: string;
  traffic_limit_gb: number | null; expire_at: string | null; device_limit: number | null; over_action: string;
  modes: string[]; node_ids: string[] | null; template_ids: string[] | null; wl_mode: 'exact' | 'prefix' | 'asn';
  configs: Array<{ id: string; name: string; allowed: boolean; profiles: string[] }>;
  effective: { trafficGb: number | null; devices: number | null; expireAt: string | null };
  traffic: { up: number; down: number; period: string };
  allowedIps: Array<{ id: number; cidr: string; source: string; expires_at: string }>;
  subUrl: string | null; knockUrl: string | null; profiles: number;
}

export const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} Б`;
  const u = ['КБ', 'МБ', 'ГБ', 'ТБ'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
};
export const fmtTime = (s: string | null | undefined) => (s ? s.replace('T', ' ').slice(0, 16) : '—');
export const ago = (s: string | null | undefined) => {
  if (!s) return 'никогда';
  const d = (Date.now() - Date.parse(s.includes('T') ? s : s.replace(' ', 'T') + 'Z')) / 1000;
  if (d < 60) return `${Math.max(1, Math.round(d))} с назад`;
  if (d < 3600) return `${Math.round(d / 60)} мин назад`;
  if (d < 86400) return `${Math.round(d / 3600)} ч назад`;
  return `${Math.round(d / 86400)} дн назад`;
};
