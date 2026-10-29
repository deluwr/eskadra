import ssh2, { type Client as SshClient, type ClientChannel } from 'ssh2';
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
  /**
   * Узел-посредник (ssh -J): панель заходит на него своим ключом и открывает через него соединение до host:port.
   * Команды на целевом узле выполняет сама панель — посредник только пересылает зашифрованный SSH.
   */
  jump?: SshTarget;
}

/** Ошибка соединения через туннель — с подсказкой, что проверить. */
/** ssh2 «no matching host key format»: sshd узла не предлагает ed25519, а панель принимает только его. */
export function noEd25519(e: Error): Error | null {
  if (!/no matching host key/i.test(e.message)) return null;
  return new Error('SSH-сервер не предлагает ключ хоста ed25519, а панель принимает только его. На сервере под root: '
    + '«ssh-keygen -A», проверьте, что в /etc/ssh/sshd_config нет строк HostKey/HostKeyAlgorithms без ed25519 '
    + '(или добавьте «HostKey /etc/ssh/ssh_host_ed25519_key»), и перезапустите sshd: «systemctl restart sshd || systemctl restart ssh»');
}

function viaError(t: { via?: string }, e: Error): Error {
  const hk = noEd25519(e);
  if (hk) return hk;
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
export async function fetchHostKey(host: string, port: number, timeoutMs = 10000, path: { prepare?: () => Promise<void>; via?: string; jump?: SshTarget } = {}): Promise<{ fp: string; algo: string }> {
  await path.prepare?.();
  // через сервер-посредник: ключ узла читается через пересланное посредником соединение
  const hop = path.jump ? await jumpSocket({ host, port, username: 'fleet', privateKey: '', hostKeyFp: null, jump: path.jump }, timeoutMs) : null;
  return new Promise<{ fp: string; algo: string }>((resolve, reject) => {
    const c = new Client();
    let got: { fp: string; algo: string } | null = null;
    const done = () => {
      c.end();
      hop?.jc.end();
      if (got) resolve(got);
    };
    c.on('error', (e) => { if (got) done(); else { hop?.jc.end(); reject(viaError(path, e)); } });
    c.on('ready', done);
    c.connect({
      ...(hop ? { sock: hop.sock } : {}),
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

/** Соединение до host:port через узел-посредник (direct-tcpip); посредник закрывается вместе с ним. */
export async function jumpSocket(t: SshTarget, timeoutMs: number): Promise<{ sock: ClientChannel; jc: Client }> {
  const jc = await connect(t.jump!, timeoutMs).catch((e: Error) => { throw new Error(`посредник ${t.jump!.host}: ${e.message}`); });
  try {
    const sock = await new Promise<ClientChannel>((resolve, reject) =>
      jc.forwardOut('127.0.0.1', 0, t.host, t.port, (err, s) => (err ? reject(new Error(`посредник ${t.jump!.host} не открыл соединение до ${t.host}:${t.port}: ${err.message} — разрешите пересылку заново (смените канал управления)`)) : resolve(s))));
    return { sock, jc };
  } catch (e) { jc.end(); throw e; }
}

async function connect(t: SshTarget, timeoutMs: number): Promise<Client> {
  await t.prepare?.();
  const hop = t.jump ? await jumpSocket(t, timeoutMs) : null;
  return new Promise<Client>((resolve, reject) => {
    if (!t.hostKeyFp) { hop?.jc.end(); return reject(new HostKeyError('host key is not pinned yet')); }
    const c = new Client();
    let mismatch: string | null = null;
    c.on('ready', () => resolve(c));
    c.on('error', (e) => { hop?.jc.end(); reject(mismatch ? new HostKeyError(mismatch) : viaError(t, e)); });
    c.on('close', () => hop?.jc.end());
    c.connect({
      ...(hop ? { sock: hop.sock } : {}),
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
