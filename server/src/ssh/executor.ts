import ssh2, { type Client as SshClient } from 'ssh2';
const { Client } = ssh2;
type Client = SshClient;
import { createHash } from 'node:crypto';

export interface SshTarget {
  host: string;
  port: number;
  username: string;
  privateKey: string;
  /** Закреплённый вручную fingerprint (SHA256:...). Без него подключение запрещено (TOFU выключен, §5.3). */
  hostKeyFp: string | null;
  /** Подготовка пути до узла перед подключением (поднять служебный туннель, §5.8). */
  prepare?: () => Promise<void>;
  /** Описание пути для сообщений об ошибках, если подключение идёт не напрямую. */
  via?: string;
}

/** Ошибка соединения через туннель — с подсказкой, что проверить. */
function viaError(t: { via?: string }, e: Error): Error {
  if (!t.via || e instanceof HostKeyError || (e as Error & { level?: string }).level === 'client-authentication') return e;
  return new Error(`SSH через ${t.via}: ${e.message}. Проверьте, что bootstrap-сниппет выполнен на узле (служба fleet-mgmt работает) и порт туннеля открыт в firewall хостера`);
}

export interface ExecResult {
  code: number | null;
  signal?: string;
  stdout: string;
  stderr: string;
}

export class HostKeyError extends Error {}

// Только ed25519: именно его отпечаток печатает bootstrap-сниппет (ssh-keygen -lf ..._ed25519_key.pub).
const HOST_KEY_ALGOS = ['ssh-ed25519' as const];

export function fingerprintOf(key: Buffer): { fp: string; algo: string } {
  const len = key.readUInt32BE(0);
  const algo = key.subarray(4, 4 + len).toString('ascii');
  const fp = 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
  return { fp, algo };
}

/** Получить host key без аутентификации — для ручной сверки при добавлении сервера (шаг 2 runbook). */
export async function fetchHostKey(host: string, port: number, timeoutMs = 10000, path: { prepare?: () => Promise<void>; via?: string } = {}): Promise<{ fp: string; algo: string }> {
  await path.prepare?.();
  return new Promise<{ fp: string; algo: string }>((resolve, reject) => {
    const c = new Client();
    let got: { fp: string; algo: string } | null = null;
    const done = () => {
      c.end();
      if (got) resolve(got);
    };
    c.on('error', (e) => (got ? done() : reject(viaError(path, e))));
    c.on('ready', done);
    c.connect({
      host,
      port,
      username: 'fleet',
      readyTimeout: timeoutMs,
      algorithms: { serverHostKey: HOST_KEY_ALGOS },
      hostVerifier: (key: Buffer) => {
        got = fingerprintOf(key);
        return false; // дальше не идём: нам нужен только ключ
      },
    });
  });
}

export class SshSession {
  constructor(private readonly client: Client) {}

  exec(cmd: string, opts: { stdin?: string | Buffer; timeoutMs?: number } = {}): Promise<ExecResult> {
    const timeoutMs = opts.timeoutMs ?? 120_000;
    return new Promise((resolve, reject) => {
      this.client.exec(cmd, (err, stream) => {
        if (err) return reject(err);
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
          stream.close();
          reject(new Error(`timeout after ${timeoutMs} ms`));
        }, timeoutMs);
        stream.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
        stream.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
        stream.on('close', (code: number | null, signal?: string) => {
          clearTimeout(timer);
          resolve({ code, signal, stdout, stderr });
        });
        if (opts.stdin !== undefined) stream.end(opts.stdin);
        else stream.end();
      });
    });
  }
}

async function connect(t: SshTarget, timeoutMs: number): Promise<Client> {
  await t.prepare?.();
  return new Promise<Client>((resolve, reject) => {
    if (!t.hostKeyFp) return reject(new HostKeyError('host key is not pinned yet'));
    const c = new Client();
    let mismatch: string | null = null;
    c.on('ready', () => resolve(c));
    c.on('error', (e) => reject(mismatch ? new HostKeyError(mismatch) : viaError(t, e)));
    c.connect({
      host: t.host,
      port: t.port,
      username: t.username,
      privateKey: t.privateKey,
      readyTimeout: timeoutMs,
      keepaliveInterval: 15_000,
      algorithms: { serverHostKey: HOST_KEY_ALGOS },
      hostVerifier: (key: Buffer) => {
        const { fp } = fingerprintOf(key);
        if (fp === t.hostKeyFp) return true;
        mismatch = `host key changed: pinned ${t.hostKeyFp}, server presented ${fp}`;
        return false;
      },
    });
  });
}

export async function withSession<T>(t: SshTarget, fn: (s: SshSession) => Promise<T>, timeoutMs = 15_000): Promise<T> {
  const client = await connect(t, timeoutMs);
  try {
    return await fn(new SshSession(client));
  } finally {
    client.end();
  }
}

/** Не больше одной операции на узел одновременно (§5.4). */
const locks = new Map<string, Promise<unknown>>();
export async function withNodeLock<T>(nodeId: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(nodeId) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((r) => (release = r));
  const chained = prev.then(() => mine);
  locks.set(nodeId, chained);
  await prev.catch(() => undefined);
  try {
    return await fn();
  } finally {
    release();
    if (locks.get(nodeId) === chained) locks.delete(nodeId);
  }
}

/** Маскирование секретов в журналах (§5.4). */
export function mask(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 6) out = out.split(s).join('***');
  return out;
}
