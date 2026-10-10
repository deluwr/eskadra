import { createHash } from 'node:crypto';

export type Core = 'xray' | 'sing-box';
export interface Release { version: string; sha256: string; asset: string }
export interface ReleaseInfo { version: string; published: string; prerelease: boolean }

const REPO: Record<Core, string> = { xray: 'XTLS/Xray-core', 'sing-box': 'SagerNet/sing-box' };
const cache = new Map<string, { at: number; value: unknown }>();
const TTL = 6 * 3600_000;

function assetName(core: Core, version: string, arch: 'amd64' | 'arm64') {
  if (core === 'xray') return arch === 'amd64' ? 'Xray-linux-64.zip' : 'Xray-linux-arm64-v8a.zip';
  return `sing-box-${version}-linux-${arch}.tar.gz`;
}

async function gh<T>(path: string): Promise<T> {
  const hit = cache.get(path);
  if (hit && Date.now() - hit.at < TTL) return hit.value as T;
  const res = await fetch(`https://api.github.com/repos/${path}`, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'eskadra-panel' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status} (${path})`);
  const value = (await res.json()) as T;
  cache.set(path, { at: Date.now(), value });
  return value;
}

/** Сравнение версий вида 25.10.15 / 1.12.0-beta.3: по числам, предрелиз младше релиза. */
export function cmpVersion(a: string, b: string): number {
  const [ma, pa = ''] = a.replace(/^v/, '').split('-', 2);
  const [mb, pb = ''] = b.replace(/^v/, '').split('-', 2);
  const na = ma!.split('.').map(Number), nb = mb!.split('.').map(Number);
  for (let i = 0; i < Math.max(na.length, nb.length); i++) {
    const d = (na[i] ?? 0) - (nb[i] ?? 0);
    if (d) return Math.sign(d);
  }
  if (pa === pb) return 0;
  if (!pa) return 1;
  if (!pb) return -1;
  return pa < pb ? -1 : 1;
}

/** Последние релизы ядра (без черновиков); предрелизы помечены. */
export async function listReleases(core: Core, limit = 30): Promise<ReleaseInfo[]> {
  const data = await gh<Array<{ tag_name: string; published_at: string; prerelease: boolean; draft: boolean }>>(`${REPO[core]}/releases?per_page=30`);
  return data.filter((r) => !r.draft).slice(0, limit)
    .map((r) => ({ version: r.tag_name.replace(/^v/, ''), published: r.published_at, prerelease: r.prerelease }));
}

/**
 * Релиз конкретной версии (или последний стабильный) и sha256 архива для архитектуры узла.
 * Хэш берём из поля digest GitHub API, а если его нет — скачиваем архив и считаем сами.
 * Узел скачивает тот же файл и сверяет хэш (fleet-core install).
 */
export async function releaseFor(core: Core, version: string | 'latest', arch: 'amd64' | 'arm64'): Promise<Release> {
  const key = `rel:${core}:${version}:${arch}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL) return hit.value as Release;
  const data = await gh<{ tag_name: string; assets: Array<{ name: string; digest?: string; browser_download_url: string }> }>(
    version === 'latest' ? `${REPO[core]}/releases/latest` : `${REPO[core]}/releases/tags/v${version.replace(/^v/, '')}`,
  );
  const v = data.tag_name.replace(/^v/, '');
  const asset = assetName(core, v, arch);
  const a = data.assets.find((x) => x.name === asset);
  if (!a) throw new Error(`в релизе ${core} ${v} нет файла ${asset}`);
  let sha = a.digest?.startsWith('sha256:') ? a.digest.slice(7) : '';
  if (!/^[0-9a-f]{64}$/.test(sha)) {
    const bin = await fetch(a.browser_download_url, { signal: AbortSignal.timeout(300_000) });
    if (!bin.ok) throw new Error(`скачивание ${asset}: HTTP ${bin.status}`);
    sha = createHash('sha256').update(Buffer.from(await bin.arrayBuffer())).digest('hex');
  }
  const rel = { version: v, sha256: sha, asset };
  cache.set(key, { at: Date.now(), value: rel });
  return rel;
}

export const latestRelease = (core: Core, arch: 'amd64' | 'arm64') => releaseFor(core, 'latest', arch);
