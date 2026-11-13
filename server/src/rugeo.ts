/**
 * Списки российских сайтов и адресов от runetfreedom (github.com/runetfreedom/russia-v2ray-rules-dat) для
 * «Российские сайты напрямую». Они ДОПОЛНЯЮТ правила по базам ядра (geosite:category-ru, geoip:ru), а не заменяют их:
 * правила по ядру работают всегда, в том числе пока файлов runetfreedom на узле нет.
 *
 * Их geosite.dat — около 90 МБ (там и полные списки заблокированного), geoip.dat — около 18 МБ, а Xray держит загруженные
 * категории в памяти. Поэтому панель сама скачивает базы, сверяет SHA-256 с опубликованными, вырезает только нужные
 * категории и раздаёт входам с настройкой пару файлов одного набора:
 *   eskadra-ru-<хэш>.dat   — сайты: ru-available-only-inside, category-ru (свежее, чем в архиве Xray);
 *   eskadra-ruip-<хэш>.dat — адреса: ru (свежее, чем в архиве Xray), yandex (сети Яндекса).
 * Сайты и адреса — разные форматы Xray, поэтому файлов два. Узлы в GitHub не ходят.
 *
 * Правила ссылаются только на набор, который уже лежит на узле (ruGeo.node.<id> — имя файла сайтов). Обновление — раз
 * в неделю: новый набор → вход переприменяет конфиг.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import type { Ctx, ServerRow } from './ctx.js';
import { getSetting, setSetting } from './db.js';
import { pickGeo } from './geodat.js';
import { ruDirectOf, ruDirectOn } from './rudirect.js';
import { config } from './config.js';

const BASE = 'https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release';
export const RU_GEO_SOURCE = `${BASE}/geosite.dat`;
export const RU_GEOIP_SOURCE = `${BASE}/geoip.dat`;
/** Сайты: доступные только из России и общий список российских сайтов. */
export const RU_SITE_CODES = ['ru-available-only-inside', 'category-ru'];
/** Адреса: российские сети и сети Яндекса (часть сервисов Яндекса — на адресах вне geoip:ru). */
export const RU_IP_CODES = ['ru', 'yandex'];
export const RU_GEO_EVERY_MS = 7 * 24 * 3600_000;
const RETRY_MS = 6 * 3600_000;

export interface RuGeo {
  file: string;              // eskadra-ru-<12 hex>.dat — сайты; имя набора
  ipFile: string;            // eskadra-ruip-<12 hex>.dat — адреса
  sha256: string;
  ipSha256: string;
  srcSha256: string;         // исходных баз
  ipSrcSha256: string;
  counts: Record<string, number>;
  fetchedAt: string;         // когда скачаны базы, из которых собран набор
}
export interface RuGeoCheck { at: string; error: string | null }

const dir = () => path.join(config.dataDir, 'rugeo');
/** Файл адресов того же набора. */
export const ruIpFileOf = (file: string) => file.replace(/^eskadra-ru-/, 'eskadra-ruip-');
export const ruGeoOf = (ctx: Ctx) => {
  const g = getSetting<RuGeo | null>(ctx.db, 'ruGeo', null);
  return g && g.ipFile ? g : null;   // набор без файла адресов (сборка до этой версии) — как будто его нет
};
export const ruGeoCheck = (ctx: Ctx) => getSetting<RuGeoCheck | null>(ctx.db, 'ruGeo.check', null);
/** Набор, который лежит на узле (правила ссылаются только на него), — имя файла сайтов. */
export const ruGeoOnNode = (ctx: Ctx, serverId: string) => getSetting<string | null>(ctx.db, `ruGeo.node.${serverId}`, null);

const haveLocal = (g: RuGeo) => fs.existsSync(path.join(dir(), g.file)) && fs.existsSync(path.join(dir(), g.ipFile));

/** Набор у панели есть, а на включённом входе — другой или никакого. */
function needsPush(ctx: Ctx, s: ServerRow): boolean {
  const g = ruGeoOf(ctx);
  return !!g && ruDirectOn(ctx.db, s.id) && ruGeoOnNode(ctx, s.id) !== g.file && haveLocal(g);
}

/** Узлу нужен выкат набора — для фоновой синхронизации: после неудачной доставки повтор не раньше чем через 6 часов. */
export function ruGeoPending(ctx: Ctx, s: ServerRow): boolean {
  const failed = getSetting<string | null>(ctx.db, `ruGeo.fail.${s.id}`, null);
  return needsPush(ctx, s) && !(failed && Date.now() - Date.parse(failed) < RETRY_MS);
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

/** Собрать набор из исходных баз (без сети — для тестов и для `refresh`). */
export function buildRuGeo(siteSrc: Buffer, ipSrc: Buffer) {
  const site = pickGeo(siteSrc, RU_SITE_CODES);
  const ip = pickGeo(ipSrc, RU_IP_CODES);
  const h = sha(Buffer.concat([site.dat, Buffer.from([0]), ip.dat])).slice(0, 12);
  return {
    file: `eskadra-ru-${h}.dat`, dat: site.dat, sha256: sha(site.dat),
    ipFile: `eskadra-ruip-${h}.dat`, ipDat: ip.dat, ipSha256: sha(ip.dat),
    counts: { ...site.counts, ...Object.fromEntries(Object.entries(ip.counts).map(([k, v]) => [`ip:${k}`, v])) },
  };
}

/**
 * Скачать базы и собрать набор. force — не ждать недели. Набор изменился — входы с настройкой отмечаются к переприменению.
 * Ошибка сети или формата не трогает прежний набор: входы продолжают работать на нём (и на базах ядра).
 */
export async function refreshRuGeo(ctx: Ctx, opts: { force?: boolean; fetch?: typeof fetch } = {}): Promise<{ changed: boolean; geo: RuGeo | null }> {
  const prev = ruGeoOf(ctx);
  const check = ruGeoCheck(ctx);
  const now = Date.now();
  if (!opts.force) {
    if (!ruDirectOf(ctx.db).entries.length) return { changed: false, geo: prev };
    if (prev && now - Date.parse(prev.fetchedAt) < RU_GEO_EVERY_MS) return { changed: false, geo: prev };
    if (check?.error && now - Date.parse(check.at) < RETRY_MS) return { changed: false, geo: prev };
  }
  const f = opts.fetch ?? fetch;
  const published = async (url: string) => {
    const r = await f(`${url}.sha256sum`, { signal: AbortSignal.timeout(30_000) });
    if (!r.ok) throw new Error(`контрольная сумма ${path.basename(url)}: HTTP ${r.status}`);
    const v = (await r.text()).trim().split(/\s+/)[0]?.toLowerCase() ?? '';
    if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`контрольная сумма ${path.basename(url)}: неверный формат`);
    return v;
  };
  const download = async (url: string, want: string) => {
    const r = await f(url, { signal: AbortSignal.timeout(600_000) });
    if (!r.ok) throw new Error(`${path.basename(url)}: HTTP ${r.status}`);
    const b = Buffer.from(await r.arrayBuffer());
    const got = sha(b);
    if (got !== want) throw new Error(`SHA-256 ${path.basename(url)} не совпал с опубликованным (${got.slice(0, 12)}…)`);
    return b;
  };
  try {
    const [want, ipWant] = [await published(RU_GEO_SOURCE), await published(RU_GEOIP_SOURCE)];
    let geo: RuGeo;
    if (prev && prev.srcSha256 === want && prev.ipSrcSha256 === ipWant && haveLocal(prev)) {
      geo = { ...prev, fetchedAt: new Date(now).toISOString() };   // базы не менялись — качать ~100 МБ незачем
    } else {
      const b = buildRuGeo(await download(RU_GEO_SOURCE, want), await download(RU_GEOIP_SOURCE, ipWant));
      fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
      for (const [name, data] of [[b.file, b.dat], [b.ipFile, b.ipDat]] as const) {
        const p = path.join(dir(), name);
        fs.writeFileSync(p + '.new', data, { mode: 0o600 });
        fs.renameSync(p + '.new', p);
      }
      geo = { file: b.file, ipFile: b.ipFile, sha256: b.sha256, ipSha256: b.ipSha256, srcSha256: want, ipSrcSha256: ipWant, counts: b.counts, fetchedAt: new Date(now).toISOString() };
    }
    setSetting(ctx.db, 'ruGeo', geo);
    setSetting(ctx.db, 'ruGeo.check', { at: new Date(now).toISOString(), error: null });
    // прежние наборы у панели не нужны
    for (const name of fs.existsSync(dir()) ? fs.readdirSync(dir()) : [])
      if (name !== geo.file && name !== geo.ipFile && /^eskadra-ru(ip)?-[0-9a-f]{12}\.dat(\.new)?$/.test(name)) fs.rmSync(path.join(dir(), name), { force: true });
    const changed = prev?.file !== geo.file;
    if (changed) for (const id of ruDirectOf(ctx.db).entries) ctx.db.prepare('UPDATE servers SET config_dirty = 1 WHERE id = ?').run(id);
    return { changed, geo };
  } catch (e) {
    setSetting(ctx.db, 'ruGeo.check', { at: new Date(now).toISOString(), error: (e as Error).message });
    throw e;
  }
}

interface NodeOps {
  op(args: (string | number)[], o?: { stdin?: string; timeoutMs?: number }): Promise<{ code: number | null; stdout: string; stderr: string }>;
}

/**
 * Перед сборкой конфига входа с настройкой: сверить, что на узле правда лежит записанный набор (сервер могли
 * переставить), и доставить текущий, если нужен. Не вышло — конфиг соберётся с тем, что на узле уже есть
 * (или только с правилами по базам ядра), выкат не прерывается.
 */
export async function syncRuGeo(ctx: Ctx, s: ServerRow, n: NodeOps, log: (l: string) => void): Promise<void> {
  if (!ruDirectOn(ctx.db, s.id)) return;
  const ls = await n.op(['geo-list'], { timeoutMs: 30_000 });
  // старый nodekit не знает geo-list: записанным наборам не верим, правила — по базам ядра, пока nodekit не обновится
  const have = ls.code === 0 ? new Set(ls.stdout.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)) : new Set<string>();
  const onNode = (file: string | null) => !!file && have.has(file) && have.has(ruIpFileOf(file));
  const rec = ruGeoOnNode(ctx, s.id);
  if (rec && !onNode(rec)) setSetting(ctx.db, `ruGeo.node.${s.id}`, null);
  const prevRec = getSetting<string | null>(ctx.db, `ruGeo.node.${s.id}.prev`, null);
  if (prevRec && !onNode(prevRec)) setSetting(ctx.db, `ruGeo.node.${s.id}.prev`, null);
  if (!needsPush(ctx, s)) return;
  const fail = (why: string) => { setSetting(ctx.db, `ruGeo.fail.${s.id}`, new Date().toISOString()); log(`списки runetfreedom не доставлены — ${why}; правила — по базам ядра`); };
  if (ls.code !== 0) { fail(`nodekit без geo-list (${(ls.stderr || ls.stdout).trim() || `exit ${ls.code}`})`); return; }
  const g = ruGeoOf(ctx)!;
  // сначала адреса, потом сайты: набор считается доставленным, только когда на месте оба файла
  for (const [name, sum] of [[g.ipFile, g.ipSha256], [g.file, g.sha256]] as const) {
    const b64 = fs.readFileSync(path.join(dir(), name)).toString('base64');
    const r = await n.op(['geo-put', name, sum], { stdin: b64, timeoutMs: 120_000 });
    if (r.code !== 0) { fail((r.stderr || r.stdout).trim() || `exit ${r.code}`); return; }
  }
  setSetting(ctx.db, `ruGeo.fail.${s.id}`, null);
  const was = ruGeoOnNode(ctx, s.id);
  if (was) setSetting(ctx.db, `ruGeo.node.${s.id}.prev`, was);
  setSetting(ctx.db, `ruGeo.node.${s.id}`, g.file);
  log(`списки runetfreedom: ${g.file}, ${g.ipFile}`);
}

/** После успешного применения: на узле остаются текущий набор и предыдущий (на него ссылается резервный конфиг). */
export async function pruneRuGeo(ctx: Ctx, s: ServerRow, n: NodeOps): Promise<void> {
  const cur = ruGeoOnNode(ctx, s.id);
  if (!cur) return;
  const prev = getSetting<string | null>(ctx.db, `ruGeo.node.${s.id}.prev`, null);
  const keep = [cur, ...(prev && prev !== cur ? [prev] : [])].flatMap((f) => [f, ruIpFileOf(f)]);
  await n.op(['geo-prune', ...keep], { timeoutMs: 30_000 });
}
