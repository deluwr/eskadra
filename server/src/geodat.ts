/**
 * Минимальная работа с базами Xray (geosite.dat / geoip.dat): это protobuf-список
 *   GeoSiteList { repeated GeoSite entry = 1 }  GeoSite { string country_code = 1; repeated Domain domain = 2; … }
 * (у GeoIPList то же устройство: entry = 1, код = 1, CIDR = 2). Записи не разбираются — нужные копируются байт в байт,
 * поэтому формат доменов и их атрибуты остаются такими, как их собрал источник.
 */

function varint(buf: Buffer, pos: number): [number, number] {
  let v = 0, mul = 1, b: number;
  do {
    if (pos >= buf.length) throw new Error('geodat: обрыв varint');
    b = buf[pos++]!;
    v += (b & 0x7f) * mul;
    mul *= 128;
    if (mul > 2 ** 56) throw new Error('geodat: слишком длинный varint');
  } while (b & 0x80);
  return [v, pos];
}

function putVarint(n: number): Buffer {
  const out: number[] = [];
  while (n >= 0x80) { out.push((n % 128) | 0x80); n = Math.floor(n / 128); }
  out.push(n);
  return Buffer.from(out);
}

/** Поля сообщения: номер, тип и (для length-delimited) срез. */
function* fields(buf: Buffer): Generator<{ no: number; wt: number; body?: Buffer }> {
  let pos = 0;
  while (pos < buf.length) {
    let key: number;
    [key, pos] = varint(buf, pos);
    const no = Math.floor(key / 8), wt = key & 7;
    if (wt === 0) { [, pos] = varint(buf, pos); yield { no, wt }; }
    else if (wt === 1) { pos += 8; yield { no, wt }; }
    else if (wt === 5) { pos += 4; yield { no, wt }; }
    else if (wt === 2) {
      let len: number;
      [len, pos] = varint(buf, pos);
      if (pos + len > buf.length) throw new Error('geodat: запись выходит за конец файла');
      yield { no, wt, body: buf.subarray(pos, pos + len) };
      pos += len;
    } else throw new Error(`geodat: неизвестный тип поля ${wt}`);
    if (pos > buf.length) throw new Error('geodat: обрыв записи');
  }
}

export interface GeoEntry { code: string; items: number; raw: Buffer }

/** Записи списка: код (как в файле, обычно в верхнем регистре), число доменов или подсетей, исходные байты. */
export function geoEntries(buf: Buffer): GeoEntry[] {
  const out: GeoEntry[] = [];
  for (const f of fields(buf)) {
    if (f.no !== 1 || !f.body) continue;
    let code = '', items = 0;
    for (const g of fields(f.body)) {
      if (g.no === 1 && g.body) code = g.body.toString('utf8');
      else if (g.no === 2) items++;
    }
    out.push({ code, items, raw: f.body });
  }
  return out;
}

/** Новый список только из записей с этими кодами (без учёта регистра). Нет какого-то кода — ошибка. */
export function pickGeo(buf: Buffer, codes: string[]): { dat: Buffer; counts: Record<string, number> } {
  const want = new Map(codes.map((c) => [c.toUpperCase(), c]));
  const got = new Map<string, GeoEntry>();
  for (const e of geoEntries(buf)) if (want.has(e.code.toUpperCase()) && !got.has(e.code.toUpperCase())) got.set(e.code.toUpperCase(), e);
  const missing = [...want.keys()].filter((c) => !got.has(c));
  if (missing.length) throw new Error(`в базе нет категорий: ${missing.map((c) => want.get(c)).join(', ')}`);
  const parts: Buffer[] = [];
  const counts: Record<string, number> = {};
  for (const [up, orig] of want) {
    const e = got.get(up)!;
    if (!e.items) throw new Error(`категория ${orig} в базе пустая`);
    counts[orig] = e.items;
    parts.push(Buffer.from([0x0a]), putVarint(e.raw.length), e.raw);
  }
  return { dat: Buffer.concat(parts), counts };
}
