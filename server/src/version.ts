/** Версия панели и наличие обновления: проверяется при открытии панели, ответ GitHub кэшируется на 10 минут. */
import fs from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from './config.js';
import { cmpVersion } from './releases.js';

const read = (f: string) => { try { return fs.readFileSync(path.join(REPO_ROOT, f), 'utf8').trim(); } catch { return ''; } };
let cache: { at: number; latest: string | null; error: string | null } | null = null;

export async function versionInfo() {
  const version = read('VERSION') || 'dev';
  const repo = read('REPO') || 'deluwr/eskadra';
  if (!cache || Date.now() - cache.at > 10 * 60_000) {
    try {
      const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
        headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'eskadra-panel' }, signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) throw new Error(`GitHub ${res.status}`);
      cache = { at: Date.now(), latest: ((await res.json()) as { tag_name: string }).tag_name, error: null };
    } catch (e) {
      cache = { at: Date.now(), latest: cache?.latest ?? null, error: (e as Error).message };
    }
  }
  const updateAvailable = version !== 'dev' && !!cache.latest && cmpVersion(cache.latest, version) > 0;
  return { version, latest: cache.latest, updateAvailable, error: cache.error };
}
