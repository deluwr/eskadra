import { createHash } from 'node:crypto';

export type Core = 'xray' | 'sing-box';
export interface Release { version: string; sha256: string; asset: string }

const REPO: Record<Core, string> = { xray: 'XTLS/Xray-core', 'sing-box': 'SagerNet/sing-box' };
const cache = new Map<string, { at: number; rel: Release }>();

function assetName(core: Core, version: string, arch: 'amd64' | 'arm64') {
  if (core === 'xray') return arch === 'amd64' ? 'Xray-linux-64.zip' : 'Xray-linux-arm64-v8a.zip';
  return `sing-box-${version}-linux-${arch}.tar.gz`;
}

/**
 * Последний стабильный релиз и sha256 архива для архитектуры узла.
 * Хэш берём из поля digest GitHub API, а если его нет — скачиваем архив и считаем сами.
 * Узел скачивает тот же файл и сверяет хэш (fleet-core install).
 */
export async function latestRelease(core: Core, arch: 'amd64' | 'arm64'): Promise<Release> {
  const key = `${core}/${arch}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < 6 * 3600_000) return hit.rel;
  const res = await fetch(`https://api.github.com/repos/${REPO[core]}/releases/latest`, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'eskadra-panel' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status} для ${core}`);
  const data = (await res.json()) as { tag_name: string; assets: Array<{ name: string; digest?: string; browser_download_url: string }> };
  const version = data.tag_name.replace(/^v/, '');
  const asset = assetName(core, version, arch);
  const a = data.assets.find((x) => x.name === asset);
  if (!a) throw new Error(`в релизе ${core} ${version} нет файла ${asset}`);
  let sha = a.digest?.startsWith('sha256:') ? a.digest.slice(7) : '';
  if (!/^[0-9a-f]{64}$/.test(sha)) {
    const bin = await fetch(a.browser_download_url, { signal: AbortSignal.timeout(300_000) });
    if (!bin.ok) throw new Error(`скачивание ${asset}: HTTP ${bin.status}`);
    sha = createHash('sha256').update(Buffer.from(await bin.arrayBuffer())).digest('hex');
  }
  const rel = { version, sha256: sha, asset };
  cache.set(key, { at: Date.now(), rel });
  return rel;
}
