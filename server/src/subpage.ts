/**
 * Страница подписки для браузера: та же ссылка /s/<токен>, что добавляют приложения. Приложение получает
 * подписку как обычно, а человек, открывший ссылку в браузере, — страницу с QR, сроком, лимитами, узлами
 * и отдельными ссылками на профили. Всё в одном HTML без внешних ресурсов.
 */
import qrcode from 'qrcode-generator';

export interface SubPageData {
  lang: 'ru' | 'en';
  name: string;
  active: boolean;
  subUrl: string;
  expireAt: string | null;
  usedBytes: number;
  limitGb: number | null;
  devices: number | null;
  nodes: string[];
  links: Array<{ name: string; uri: string }>;
}

const T = {
  ru: {
    title: 'Подписка', active: 'доступ активен', off: 'доступ приостановлен', add: 'Добавить в приложение', copy: 'Копировать', copied: 'Скопировано',
    scan: 'Отсканируйте QR в приложении или нажмите кнопку на телефоне, где оно установлено.', until: 'Действует до', forever: 'без срока', daysLeft: (d: number) => `осталось ${d} дн`,
    traffic: 'Трафик за месяц', of: 'из', unlimited: 'без лимита', devices: 'Устройств', nodes: 'Доступные узлы', links: 'Отдельные ссылки',
    gb: 'ГБ', linksHint: 'Для приложений без подписок или чтобы добавить один профиль. Сами не обновляются.', qr: 'QR', secret: 'Не пересылайте эту страницу: по ссылке подключается любой, у кого она есть.',
  },
  en: {
    title: 'Subscription', active: 'access active', off: 'access suspended', add: 'Add to app', copy: 'Copy', copied: 'Copied',
    scan: 'Scan the QR in your app or tap a button on the phone where the app is installed.', until: 'Valid until', forever: 'no expiry', daysLeft: (d: number) => `${d} days left`,
    traffic: 'Traffic this month', of: 'of', unlimited: 'unlimited', devices: 'Devices', nodes: 'Available nodes', links: 'Individual links',
    gb: 'GB', linksHint: 'For apps without subscriptions or to add a single profile. They don’t update by themselves.', qr: 'QR', secret: 'Don’t share this page: anyone with the link can connect.',
  },
};

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function qrSvg(text: string): string {
  const q = qrcode(0, 'M');
  q.addData(text);
  q.make();
  return q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}

const gb = (b: number) => (b / 1024 ** 3 >= 100 ? (b / 1024 ** 3).toFixed(0) : (b / 1024 ** 3).toFixed(1));

/** Приложения VPN шлют свой User-Agent и не просят HTML; браузер — просит. */
export function wantsPage(accept: string | undefined, ua: string | undefined): boolean {
  const a = (accept ?? '').toLowerCase();
  const u = (ua ?? '').toLowerCase();
  if (!a.includes('text/html') || !u.includes('mozilla')) return false;
  return !/clash|v2ray|hiddify|sing-box|streisand|shadowrocket|happ|nekobox|nekoray|karing|foxray|v2box|stash|surge|quantumult|loon/.test(u);
}

export function importButtons(url: string, name: string): Array<[string, string]> {
  const u = encodeURIComponent(url);
  const n = encodeURIComponent(`Эскадра · ${name}`);
  return [
    ['Hiddify', `hiddify://import/${url}#${n}`],
    ['v2rayNG', `v2rayng://install-sub?url=${u}&name=${n}`],
    ['Happ', `happ://add/${url}`],
    ['Streisand', `streisand://import/${url}#${n}`],
    ['sing-box', `sing-box://import-remote-profile?url=${u}#${n}`],
  ];
}

export function renderSubPage(d: SubPageData): string {
  const t = T[d.lang];
  const days = d.expireAt ? Math.max(0, Math.ceil((Date.parse(d.expireAt) - Date.now()) / 86400_000)) : null;
  const pct = d.limitGb ? Math.min(100, Math.round((d.usedBytes / (d.limitGb * 1024 ** 3)) * 100)) : 0;
  const btn = (text: string) => `<button type="button" class="b" data-copy="${esc(text)}">${t.copy}</button>`;
  return `<!doctype html>
<html lang="${d.lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer">
<title>${esc(t.title)} · ${esc(d.name)}</title>
<style>
:root{--bg:#0D1B26;--s:#12232F;--s2:#1B2F3D;--l:#21384A;--t:#E4ECF2;--m:#8FA3B4;--a:#E8B04B;--ai:#1D1404;--ok:#4CC79A;--f:#F0766B;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#EEF3F6;--s:#fff;--s2:#E5EDF2;--l:#CCD9E2;--t:#0F2230;--m:#4A6070;--a:#8A5800;--ai:#fff;--ok:#0E7A50;--f:#B8322A;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:720px;margin:0 auto;padding:24px 16px 48px;display:flex;flex-direction:column;gap:16px}
.c{background:var(--s);border:1px solid var(--l);border-radius:14px;padding:18px 20px}
h1{font-size:24px;margin:0;font-weight:600}h2{font-size:15px;margin:0 0 10px;font-weight:600}
.k{color:var(--m);font-size:13px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.tag{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;background:var(--s2)}
.tag.ok{color:var(--ok)}.tag.f{color:var(--f)}.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.hero{display:grid;grid-template-columns:200px 1fr;gap:20px;align-items:center}@media (max-width:560px){.hero{grid-template-columns:1fr}.qr{max-width:240px;margin:0 auto}}
.qr{background:#fff;border-radius:12px;padding:6px;aspect-ratio:1}.qr svg{width:100%;height:100%;display:block}
.url{font:12px/1.4 ui-monospace,monospace;color:var(--m);word-break:break-all;background:var(--bg);border:1px solid var(--l);border-radius:8px;padding:8px 10px}
.b{font:inherit;font-size:13px;font-weight:500;min-height:34px;padding:0 12px;border-radius:8px;border:1px solid var(--l);background:var(--s2);color:var(--t);cursor:pointer;text-decoration:none;display:inline-flex;align-items:center}
.b.p{background:var(--a);border-color:var(--a);color:var(--ai)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.facts b{display:block;font-size:18px;font-weight:600;margin-top:2px}
.bar{height:6px;border-radius:999px;background:var(--s2);overflow:hidden;margin-top:8px}.bar span{display:block;height:100%;background:var(--a)}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{padding:5px 11px;border-radius:999px;background:var(--s2);font-size:13px}
.lk{border-top:1px solid var(--l);padding:10px 0}.lk:first-of-type{border-top:0}.lk-h{display:flex;gap:10px;align-items:center;justify-content:space-between}
.lk b{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}details summary{list-style:none;cursor:pointer}details summary::-webkit-details-marker{display:none}
.lk .qr{width:200px;margin-top:10px}
</style></head><body><main>
<section class="c"><div class="row" style="justify-content:space-between"><h1>${esc(d.name)}</h1>
<span class="tag ${d.active ? 'ok' : 'f'}"><span class="dot"></span>${d.active ? t.active : t.off}</span></div></section>
<section class="c hero"><div class="qr">${qrSvg(d.subUrl)}</div><div style="display:flex;flex-direction:column;gap:10px">
<h2 style="margin:0">${t.add}</h2><span class="k">${t.scan}</span>
<div class="row">${importButtons(d.subUrl, d.name).map(([n, h]) => `<a class="b p" href="${esc(h)}">${esc(n)}</a>`).join('')}</div>
<div class="url">${esc(d.subUrl)}</div><div>${btn(d.subUrl)}</div></div></section>
<section class="c facts">
<div><span class="k">${t.until}</span><b>${d.expireAt ? esc(d.expireAt.slice(0, 10)) : t.forever}</b>${days !== null ? `<span class="k">${t.daysLeft(days)}</span>` : ''}</div>
<div><span class="k">${t.traffic}</span><b>${gb(d.usedBytes)} ${t.gb}${d.limitGb ? ` <span class="k">${t.of} ${d.limitGb} ${t.gb}</span>` : ''}</b>${d.limitGb ? `<div class="bar"><span style="width:${pct}%"></span></div>` : `<span class="k">${t.unlimited}</span>`}</div>
<div><span class="k">${t.devices}</span><b>${d.devices ?? '∞'}</b></div>
</section>
${d.nodes.length ? `<section class="c"><h2>${t.nodes}</h2><div class="chips">${d.nodes.map((n) => `<span class="chip">${esc(n)}</span>`).join('')}</div></section>` : ''}
${d.links.length ? `<section class="c"><h2>${t.links}</h2><p class="k" style="margin:0 0 6px">${t.linksHint}</p>
${d.links.map((l) => `<div class="lk"><details><summary class="lk-h"><b>${esc(l.name)}</b><span class="row" style="flex:none">${btn(l.uri)}<span class="b">${t.qr}</span></span></summary><div class="qr">${qrSvg(l.uri)}</div></details></div>`).join('')}</section>` : ''}
<p class="k" style="text-align:center">${t.secret}</p>
</main>
<script>
document.addEventListener('click', function (e) {
  var b = e.target.closest('[data-copy]'); if (!b) return; e.preventDefault(); e.stopPropagation();
  var v = b.getAttribute('data-copy'), done = function () { var o = b.textContent; b.textContent = ${JSON.stringify(t.copied)}; setTimeout(function () { b.textContent = o; }, 1500); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(v).then(done);
  else { var x = document.createElement('textarea'); x.value = v; document.body.appendChild(x); x.select(); document.execCommand('copy'); x.remove(); done(); }
});
</script></body></html>`;
}
