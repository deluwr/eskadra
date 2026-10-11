/**
 * Служебный туннель управления (§5.8): SSH панели идёт к узлу внутри VLESS-REALITY.
 *
 * На узле — отдельный Xray (fleet-mgmt.service): один inbound VLESS-REALITY, единственный outbound
 * freedom с redirect на 127.0.0.1:<ssh>. На главном сервере — Xray-клиент (дочерний процесс панели):
 * на каждый туннельный узел dokodemo-door на 127.0.0.1:<локальный порт> → VLESS-REALITY к узлу.
 * SSH Executor подключается к локальному порту; закрепление host key узла работает как прежде.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, randomInt, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import { getSetting, setSetting } from './db.js';
import type { Ctx, ServerRow } from './ctx.js';
import { releaseFor } from './releases.js';
import { botProxyClientPart } from './botproxy.js';

/** Сайты для маскировки REALITY: TLS 1.3 + HTTP/2. Проверены с Xray 26.3: с www.microsoft.com рукопожатие REALITY не проходит. */
export const MGMT_SNIS = ['www.apple.com', 'dl.google.com', 'www.cloudflare.com', 'www.samsung.com'];
const AVOID = new Set([10085, 51820, 2053, 2096, 54321, 8443]);

export interface TunnelCreds {
  port: number; uuid: string; privateKey: string; publicKey: string; shortId: string; sni: string; localPort: number;
}

export interface XrayPin { version: string; sha: { amd64: string; arm64: string } }

/** Новые ключи и порты туннеля. Порт на узле — случайный; локальный порт на главном сервере — не занятый другими узлами. */
export function newTunnel(usedLocal: number[]): TunnelCreds {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  // JWK x25519: d и x — ровно 32 байта в base64url без «=», как ждёт Xray
  const d = privateKey.export({ format: 'jwk' }).d!;
  const x = publicKey.export({ format: 'jwk' }).x!;
  let port: number;
  do port = randomInt(20000, 60000); while (AVOID.has(port));
  let localPort: number;
  do localPort = randomInt(40000, 50000); while (usedLocal.includes(localPort));
  return {
    port, uuid: randomUUID(), privateKey: d, publicKey: x,
    shortId: randomBytes(8).toString('hex'), sni: MGMT_SNIS[randomInt(MGMT_SNIS.length)]!, localPort,
  };
}

/** Конфиг служебного Xray на узле: доступ только к локальному SSH, других направлений нет. */
export function nodeConfig(t: TunnelCreds, sshPort: number): object {
  return {
    log: { loglevel: 'warning' },
    inbounds: [{
      tag: 'mgmt', listen: '::', port: t.port, protocol: 'vless',
      settings: { clients: [{ id: t.uuid, flow: 'xtls-rprx-vision' }], decryption: 'none' },
      streamSettings: {
        network: 'tcp', security: 'reality',
        realitySettings: { show: false, target: `${t.sni}:443`, serverNames: [t.sni], privateKey: t.privateKey, shortIds: [t.shortId] },
      },
    }],
    outbounds: [{ tag: 'ssh', protocol: 'freedom', settings: { redirect: `127.0.0.1:${sshPort}` } }],
    routing: { rules: [{ type: 'field', inboundTag: ['mgmt'], outboundTag: 'ssh' }] },
  };
}

export interface TunnelNode { id: string; host: string; sshPort: number; creds: TunnelCreds }

export interface ClientExtra { inbound: object; outbound: object; rule: object }

/** Конфиг Xray-клиента на главном сервере: локальный порт узла → VLESS-REALITY к узлу; extra — прокси бота. */
export function clientConfig(nodes: TunnelNode[], extra?: ClientExtra | ClientExtra[] | null): object {
  const extras = Array.isArray(extra) ? extra : extra ? [extra] : [];
  return {
    log: { loglevel: 'warning' },
    inbounds: [...extras.map((e) => e.inbound), ...nodes.map((n) => ({
      tag: `in-${n.id}`, listen: '127.0.0.1', port: n.creds.localPort, protocol: 'dokodemo-door',
      settings: { address: '127.0.0.1', port: n.sshPort, network: 'tcp' },
    }))],
    outbounds: [
      ...extras.map((e) => e.outbound),
      ...nodes.map((n) => ({
        tag: `out-${n.id}`, protocol: 'vless',
        settings: { vnext: [{ address: n.host, port: n.creds.port, users: [{ id: n.creds.uuid, encryption: 'none', flow: 'xtls-rprx-vision' }] }] },
        streamSettings: {
          network: 'tcp', security: 'reality',
          realitySettings: { serverName: n.creds.sni, fingerprint: 'chrome', publicKey: n.creds.publicKey, shortId: n.creds.shortId },
        },
      })),
      { tag: 'block', protocol: 'blackhole' },
    ],
    routing: { rules: [...extras.map((e) => e.rule), ...nodes.map((n) => ({ type: 'field', inboundTag: [`in-${n.id}`], outboundTag: `out-${n.id}` }))] },
  };
}

/** Один файл из zip-архива (stored или deflate) — без внешних unzip/python. */
export function extractFromZip(zip: Buffer, name: string): Buffer {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 0xffff); i--)
    if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('zip: нет каталога архива');
  const entries = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let k = 0; k < entries; k++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error('zip: повреждён каталог');
    const method = zip.readUInt16LE(p + 10);
    const csize = zip.readUInt32LE(p + 20);
    const nlen = zip.readUInt16LE(p + 28), elen = zip.readUInt16LE(p + 30), clen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const entry = zip.subarray(p + 46, p + 46 + nlen).toString('utf8');
    if (entry === name) {
      if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error('zip: повреждён заголовок файла');
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + csize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return zlib.inflateRawSync(data);
      throw new Error(`zip: метод сжатия ${method} не поддерживается`);
    }
    p += 46 + nlen + elen + clen;
  }
  throw new Error(`zip: в архиве нет ${name}`);
}

/** Учётные данные туннеля узла из базы (приватный ключ хранится зашифрованным). */
export function credsOf(ctx: Ctx, r: ServerRow): TunnelCreds | null {
  if (!r.mgmt_port || !r.mgmt_uuid || !r.mgmt_key_sealed || !r.mgmt_pub || !r.mgmt_sid || !r.mgmt_sni || !r.mgmt_local_port) return null;
  return {
    port: r.mgmt_port, uuid: r.mgmt_uuid, privateKey: ctx.open(r.mgmt_key_sealed), publicKey: r.mgmt_pub,
    shortId: r.mgmt_sid, sni: r.mgmt_sni, localPort: r.mgmt_local_port,
  };
}

/** Поля строки servers для новых учётных данных туннеля. */
export function credsFields(ctx: Ctx, t: TunnelCreds): Partial<ServerRow> {
  return {
    mgmt_port: t.port, mgmt_uuid: t.uuid, mgmt_key_sealed: ctx.seal(t.privateKey), mgmt_pub: t.publicKey,
    mgmt_sid: t.shortId, mgmt_sni: t.sni, mgmt_local_port: t.localPort,
  };
}

/**
 * Версия Xray для туннелей и хэши архивов под обе архитектуры (узел может быть amd64 или arm64).
 * Закрепляется при первом запросе: панель и все узлы держат одну версию, хэш вписывается в bootstrap-сниппет.
 */
export async function xrayPin(ctx: Ctx): Promise<XrayPin> {
  const have = getSetting<XrayPin | null>(ctx.db, 'mgmt.xray', null);
  if (have) return have;
  const a = await releaseFor('xray', 'latest', 'amd64');
  const b = await releaseFor('xray', a.version, 'arm64');
  const pin = { version: a.version, sha: { amd64: a.sha256, arm64: b.sha256 } };
  setSetting(ctx.db, 'mgmt.xray', pin);
  return pin;
}

const mainArch = (): 'amd64' | 'arm64' => (process.arch === 'arm64' ? 'arm64' : 'amd64');

interface Log { info(msg: string): void; warn(msg: string): void }

/** Xray-клиент туннелей на главном сервере: скачивается при первой нужде, перезапускается при смене конфига. */
export class Mgmt {
  private child: ChildProcess | null = null;
  private runningHash = '';
  private queue: Promise<unknown> = Promise.resolve();
  private lastError: string | null = null;

  constructor(private readonly ctx: Ctx, private readonly dataDir: string, private readonly log: Log) {}

  private get dir() { return path.join(this.dataDir, 'mgmt'); }
  private get bin() { return path.join(this.dir, 'xray'); }

  pin = () => xrayPin(this.ctx);

  private async ensureBinary(pin: XrayPin): Promise<void> {
    const marker = path.join(this.dir, 'xray.version');
    if (fs.existsSync(this.bin) && fs.existsSync(marker) && fs.readFileSync(marker, 'utf8').trim() === pin.version) return;
    const arch = mainArch();
    const asset = arch === 'amd64' ? 'Xray-linux-64.zip' : 'Xray-linux-arm64-v8a.zip';
    const res = await fetch(`https://github.com/XTLS/Xray-core/releases/download/v${pin.version}/${asset}`, { signal: AbortSignal.timeout(300_000) });
    if (!res.ok) throw new Error(`скачивание Xray ${pin.version}: HTTP ${res.status}`);
    const zip = Buffer.from(await res.arrayBuffer());
    const sum = createHash('sha256').update(zip).digest('hex');
    if (sum !== pin.sha[arch]) throw new Error(`SHA-256 архива Xray не совпал (${sum})`);
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(this.bin + '.new', extractFromZip(zip, 'xray'), { mode: 0o755 });
    fs.renameSync(this.bin + '.new', this.bin);
    fs.writeFileSync(marker, pin.version + '\n');
    this.log.info(`туннели управления: Xray ${pin.version} установлен`);
  }

  private nodes(): TunnelNode[] {
    return this.ctx.servers()
      .filter((r) => r.mgmt_mode === 'tunnel')
      .map((r) => ({ id: r.id, host: r.host, sshPort: r.ssh_port, creds: credsOf(this.ctx, r) }))
      .filter((n): n is TunnelNode => !!n.creds);
  }

  /** Поднять (или перезапустить с новым конфигом) клиента туннелей. Вызывается перед каждым SSH к туннельному узлу. */
  ensure(): Promise<void> {
    const run = this.queue.then(() => this.ensureNow());
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async ensureNow(): Promise<void> {
    const nodes = this.nodes();
    const bot = botProxyClientPart(this.ctx);
    const extra = bot ? [bot] : [];
    if (!nodes.length && !extra.length) { this.stop(); return; }
    try {
      const pin = await this.pin();
      await this.ensureBinary(pin);
      const cfg = JSON.stringify(clientConfig(nodes, extra), null, 2);
      const hash = createHash('sha256').update(cfg).digest('hex');
      if (this.child && this.child.exitCode === null && hash === this.runningHash) return;
      this.stop();
      const file = path.join(this.dir, 'client.json');
      fs.writeFileSync(file, cfg, { mode: 0o600 });
      const child = spawn(this.bin, ['run', '-c', file], { stdio: ['ignore', 'pipe', 'pipe'] });
      const tail: string[] = [];
      const onOut = (d: Buffer) => { for (const l of d.toString('utf8').split('\n')) if (l.trim()) { tail.push(l); if (tail.length > 20) tail.shift(); } };
      child.stdout?.on('data', onOut);
      child.stderr?.on('data', onOut);
      child.on('exit', (code) => {
        if (this.child === child) {
          this.child = null;
          this.runningHash = '';
          this.lastError = `Xray туннелей завершился (код ${code}): ${tail.slice(-3).join(' | ')}`;
          this.log.warn(this.lastError);
        }
      });
      this.child = child;
      this.runningHash = hash;
      await waitListen(nodes[0]?.creds.localPort ?? (extra[0]!.inbound as { port: number }).port, 5000);
      if (child.exitCode !== null) throw new Error(this.lastError ?? 'Xray туннелей не запустился');
      this.lastError = null;
    } catch (e) {
      this.lastError = (e as Error).message;
      throw new Error(`туннель управления: ${this.lastError}`);
    }
  }

  /**
   * Открыть временный проброс к SSH сервера через прокси (outbound Xray). Возвращает локальный порт;
   * close() убирает проброс. Нужен для первичного доступа, когда SSH напрямую режется.
   */
  async openVia(outbound: Record<string, unknown>, host: string, port: number): Promise<{ port: number; close: () => Promise<void> }> {
    // отдельный процесс Xray: неудачный конфиг прокси не задевает туннели к другим серверам
    const pin = await this.pin();
    await this.ensureBinary(pin);
    const used = new Set(this.ctx.servers().map((s) => s.mgmt_local_port ?? 0));
    let local = 0;
    do local = 47000 + Math.floor(Math.random() * 2000); while (used.has(local));
    const cfg = {
      log: { loglevel: 'warning' },
      inbounds: [{ tag: 'boot-in', listen: '127.0.0.1', port: local, protocol: 'dokodemo-door', settings: { address: host, port, network: 'tcp' } }],
      outbounds: [{ ...outbound, tag: 'boot-out' }, { tag: 'block', protocol: 'blackhole' }],
      routing: { rules: [{ type: 'field', inboundTag: ['boot-in'], outboundTag: 'boot-out' }] },
    };
    const file = path.join(this.dir, `boot-${local}.json`);
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    const child = spawn(this.bin, ['run', '-c', file], { stdio: ['ignore', 'pipe', 'pipe'] });
    const tail: string[] = [];
    const onOut = (d: Buffer) => { for (const l of d.toString('utf8').split('\n')) if (l.trim()) { tail.push(l); if (tail.length > 10) tail.shift(); } };
    child.stdout?.on('data', onOut);
    child.stderr?.on('data', onOut);
    const close = async () => { child.kill('SIGTERM'); fs.rmSync(file, { force: true }); };
    try {
      await waitListen(local, 5000);
      if (child.exitCode !== null) throw new Error('');
    } catch {
      await close();
      throw new Error(`Xray не принял конфигурацию прокси: ${tail.slice(-2).join(' | ') || 'неизвестная ошибка'}`);
    }
    return { port: local, close };
  }

  stop() {
    if (this.child) {
      const c = this.child;
      this.child = null;
      this.runningHash = '';
      c.kill('SIGTERM');
    }
  }

  status() {
    const pin = getSetting<XrayPin | null>(this.ctx.db, 'mgmt.xray', null);
    return { running: !!this.child && this.child.exitCode === null, version: pin?.version ?? null, error: this.lastError };
  }
}

function waitListen(port: number, ms: number): Promise<void> {
  const until = Date.now() + ms;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(); });
      s.on('error', () => {
        s.destroy();
        if (Date.now() > until) reject(new Error(`клиент туннелей не открыл порт ${port}`));
        else setTimeout(tryOnce, 150);
      });
    };
    tryOnce();
  });
}
