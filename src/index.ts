export type Question = { name: string; type: number; classCode: number };

export interface ResourceRecord {
  name: string | Uint8Array;
  type: number;
  classCode: number;
  ttl: number;
  rdata: Uint8Array;
  /**
   * Complete DNS message containing rdata. Required when rdata still contains
   * DNS compression pointers.
   */
  wire?: Uint8Array;
  /** Absolute owner-name offset in wire; used only when wire is supplied. */
  nameOffset?: number;
  /** Absolute offset of rdata in wire. Defaults to rdata.byteOffset. */
  rdataOffset?: number;
}

export interface CanonicalRRSetOptions {
  /** RRSIG Labels value, used to reconstruct a wildcard owner name. */
  labels?: number;
  /** RRSIG Original TTL used for every RR in the signed RRset. */
  originalTtl?: number;
}

export interface RrsigMetadata {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signerName: string | Uint8Array;
}

export interface DecodedName {
  name: Uint8Array;
  nextOffset: number;
}

export interface TypeBitmapWindow {
  window: number;
  bitmap: Uint8Array;
}

const ROOT = Uint8Array.of(0);
const encoder = new TextEncoder();

export function encodeName(name: string): Uint8Array {
  const out: number[] = [];
  for (const label of name.split('.').filter(Boolean)) {
    const bytes = encoder.encode(label);
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  return Uint8Array.from(out);
}

export function headerCounts(data: Uint8Array) {
  if (data.length < 12) throw new Error('short header');
  return {
    questions: (data[4] << 8) | data[5],
    answers: (data[6] << 8) | data[7],
  };
}

function integer(value: number, name: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new Error(`${name} must be an integer`);
  }
}

function uint(value: number, bits: 8 | 16 | 32, name: string): number {
  integer(value, name);
  const max = bits === 8 ? 0xff : bits === 16 ? 0xffff : 0xffffffff;
  if (value < 0 || value > max) throw new Error(`${name} out of range`);
  return value;
}

function u16(value: number): Uint8Array {
  uint(value, 16, 'value');
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function u32(value: number): Uint8Array {
  uint(value, 32, 'value');
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

function concat(parts: Iterable<Uint8Array>): Uint8Array {
  const list = Array.from(parts);
  const length = list.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of list) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return compareBytes(a, b) === 0;
}

function lowerAscii(bytes: Uint8Array): Uint8Array {
  const out = bytes.slice();
  for (let i = 0; i < out.length; i++) {
    if (out[i] >= 0x41 && out[i] <= 0x5a) out[i] += 0x20;
  }
  return out;
}

function canonicalNameFromString(name: string): Uint8Array {
  if (name === '' || name === '.') return ROOT.slice();

  const labels = name.split('.');
  if (name.endsWith('.')) labels.pop();
  if (labels.some((label) => label.length === 0)) {
    throw new Error('invalid name: empty label');
  }

  const parts: Uint8Array[] = [];
  let length = 1;
  for (const label of labels) {
    const bytes = lowerAscii(encoder.encode(label));
    if (bytes.length === 0 || bytes.length > 63) {
      throw new Error('DNS label must contain 1 through 63 bytes');
    }
    length += 1 + bytes.length;
    if (length > 255) throw new Error('DNS name is too long');
    parts.push(Uint8Array.of(bytes.length), bytes);
  }
  parts.push(ROOT);
  return concat(parts);
}

function canonicalNameFromWire(name: Uint8Array): Uint8Array {
  if (name.length === 0) throw new Error('invalid empty wire name');

  const parts: Uint8Array[] = [];
  let pos = 0;
  let length = 1;

  while (true) {
    if (pos >= name.length) throw new Error('name is not root-terminated');
    const labelLength = name[pos++];

    if (labelLength === 0) {
      if (pos !== name.length) throw new Error('bytes found after root label');
      parts.push(ROOT);
      return concat(parts);
    }

    // 01 and 10 label types are reserved; 11 is compression.
    if (labelLength >= 64) {
      throw new Error(labelLength >= 192 ? 'compressed name is not canonical' : 'reserved label type');
    }
    if (pos + labelLength > name.length) throw new Error('truncated label');

    const label = lowerAscii(name.subarray(pos, pos + labelLength));
    length += 1 + labelLength;
    if (length > 255) throw new Error('DNS name is too long');
    parts.push(Uint8Array.of(labelLength), label);
    pos += labelLength;
  }
}

export function canonicalName(name: string | Uint8Array): Uint8Array {
  return typeof name === 'string' ? canonicalNameFromString(name) : canonicalNameFromWire(name);
}

export function decodeName(
  wire: Uint8Array,
  offset: number,
  end: number = wire.length,
): DecodedName {
  if (!(wire instanceof Uint8Array)) throw new Error('wire must be a Uint8Array');
  integer(offset, 'offset');
  integer(end, 'end');
  if (offset < 0 || offset >= end) throw new Error('name offset out of range');

  const parts: Uint8Array[] = [];
  const seenPointers = new Set<number>();
  let pos = offset;
  let bound = end;
  let nextOffset = -1;
  let jumps = 0;
  let labelBytes = 0;

  while (true) {
    if (pos < 0 || pos >= bound) throw new Error('truncated name');
    const labelLength = wire[pos];

    if (labelLength === 0) {
      if (nextOffset === -1) nextOffset = pos + 1;
      return { name: concat([...parts, ROOT]), nextOffset };
    }

    if (labelLength >= 192) {
      if (pos + 1 >= bound) throw new Error('truncated compression pointer');
      const pointer = ((labelLength & 0x3f) << 8) | wire[pos + 1];
      if (nextOffset === -1) nextOffset = pos + 2;
      if (seenPointers.has(pointer)) throw new Error('compression pointer loop');
      seenPointers.add(pointer);
      if (++jumps > 127) throw new Error('too many compression pointers');
      pos = pointer;
      bound = wire.length;
      continue;
    }

    if (labelLength >= 64) throw new Error('reserved label type');
    if (pos + 1 + labelLength > bound) throw new Error('truncated label');

    parts.push(wire.subarray(pos, pos + 1 + labelLength));
    labelBytes += 1 + labelLength;
    if (labelBytes + 1 > 255) throw new Error('DNS name is too long');
    pos += 1 + labelLength;
  }
}

function countLabels(name: Uint8Array): number {
  let pos = 0;
  let count = 0;
  while (name[pos] !== 0) {
    const length = name[pos];
    count++;
    pos += 1 + length;
  }
  return count;
}

function nameSegments(name: Uint8Array): Uint8Array[] {
  const segments: Uint8Array[] = [];
  let pos = 0;
  while (name[pos] !== 0) {
    const length = name[pos];
    segments.push(name.subarray(pos, pos + 1 + length));
    pos += 1 + length;
  }
  return segments;
}

function applyWildcardLabels(name: Uint8Array, labels: number | undefined): Uint8Array {
  if (labels === undefined) return name;
  uint(labels, 8, 'RRSIG labels');

  const ownerLabels = countLabels(name);
  if (labels === ownerLabels) return name;
  if (labels > ownerLabels) throw new Error('RRSIG labels exceeds owner name labels');
  if (labels === 0) throw new Error('wildcard owner must contain at least one suffix label');

  const suffix = nameSegments(name).slice(ownerLabels - labels);
  return concat([Uint8Array.of(1, 0x2a), ...suffix, ROOT]);
}

function readCanonicalName(
  rr: ResourceRecord,
  pos: number,
): { name: Uint8Array; next: number } {
  const rdata = rr.rdata;
  let decoded: DecodedName;
  let base = 0;

  if (rr.wire) {
    base = rr.rdataOffset ?? rdata.byteOffset;
    decoded = decodeName(rr.wire, base + pos, rr.wire.length);
  } else {
    decoded = decodeName(rdata, pos, rdata.length);
  }

  const next = decoded.nextOffset - base;
  if (!Number.isSafeInteger(next) || next < 0 || next > rdata.length) {
    throw new Error('name in RDATA extends past RDATA');
  }
  return { name: canonicalName(decoded.name), next };
}

function requireBytes(rdata: Uint8Array, pos: number, length: number): Uint8Array {
  if (pos + length > rdata.length) throw new Error('truncated RDATA');
  return rdata.subarray(pos, pos + length);
}

function singleNameRdata(rr: ResourceRecord): Uint8Array {
  const name = readCanonicalName(rr, 0);
  if (name.next !== rr.rdata.length) throw new Error('trailing bytes after name in RDATA');
  return name.name;
}

function prefixedNameRdata(rr: ResourceRecord, prefixLength: number): Uint8Array {
  const prefix = requireBytes(rr.rdata, 0, prefixLength);
  const name = readCanonicalName(rr, prefixLength);
  if (name.next !== rr.rdata.length) throw new Error('trailing bytes after name in RDATA');
  return concat([prefix, name.name]);
}

function twoNameRdata(rr: ResourceRecord): Uint8Array {
  const first = readCanonicalName(rr, 0);
  const second = readCanonicalName(rr, first.next);
  if (second.next !== rr.rdata.length) throw new Error('trailing bytes after second name in RDATA');
  return concat([first.name, second.name]);
}

function canonicalNaptrRdata(rr: ResourceRecord): Uint8Array {
  const rdata = rr.rdata;
  const parts = [requireBytes(rdata, 0, 4)];
  let pos = 4;

  for (let i = 0; i < 3; i++) {
    if (pos >= rdata.length) throw new Error('truncated NAPTR character string');
    const length = rdata[pos++];
    if (pos + length > rdata.length) throw new Error('truncated NAPTR character string');
    parts.push(Uint8Array.of(length), rdata.subarray(pos, pos + length));
    pos += length;
  }

  const replacement = readCanonicalName(rr, pos);
  if (replacement.next !== rdata.length) throw new Error('trailing bytes after NAPTR replacement');
  parts.push(replacement.name);
  return concat(parts);
}

function canonicalSignatureRdata(rr: ResourceRecord, fixedLength: number): Uint8Array {
  const fixed = requireBytes(rr.rdata, 0, fixedLength);
  const signer = readCanonicalName(rr, fixedLength);
  return concat([fixed, signer.name, rr.rdata.subarray(signer.next)]);
}

function canonicalNsecRdata(rr: ResourceRecord): Uint8Array {
  const nextName = readCanonicalName(rr, 0);
  const bitmap = rr.rdata.subarray(nextName.next);
  return concat([nextName.name, encodeTypeBitmap(parseTypeBitmap(bitmap))]);
}

export function canonicalRdata(rr: ResourceRecord): Uint8Array {
  const rdata = rr.rdata;
  if (!(rdata instanceof Uint8Array)) throw new Error('rdata must be a Uint8Array');

  switch (rr.type) {
    // One domain name.
    case 2: // NS
    case 5: // CNAME
    case 12: // PTR
    case 39: // DNAME
      return singleNameRdata(rr);

    // Two domain names.
    case 14: // MINFO
    case 17: // RP
      return twoNameRdata(rr);

    // 16-bit prefix followed by a domain name.
    case 15: // MX
    case 21: // RT
    case 36: // KX
    case 107: // LP
      return prefixedNameRdata(rr, 2);

    case 18: // AFSDB
      return prefixedNameRdata(rr, 2);

    case 6: { // SOA
      const mname = readCanonicalName(rr, 0);
      const rname = readCanonicalName(rr, mname.next);
      const fixed = requireBytes(rdata, rname.next, 20);
      if (rname.next + 20 !== rdata.length) throw new Error('invalid SOA RDATA length');
      return concat([mname.name, rname.name, fixed]);
    }

    case 26: { // PX
      const preference = requireBytes(rdata, 0, 2);
      const map822 = readCanonicalName(rr, 2);
      const mapx400 = readCanonicalName(rr, map822.next);
      if (mapx400.next !== rdata.length) throw new Error('trailing bytes in PX RDATA');
      return concat([preference, map822.name, mapx400.name]);
    }

    case 24: // SIG
    case 46: // RRSIG
      return canonicalSignatureRdata(rr, 18);

    case 30: { // NXT: a name followed by the legacy 256-bit bitmap.
      const next = readCanonicalName(rr, 0);
      const bitmap = requireBytes(rdata, next.next, 32);
      if (next.next + 32 !== rdata.length) throw new Error('invalid NXT RDATA length');
      return concat([next.name, bitmap]);
    }

    case 33: { // SRV
      const prefix = requireBytes(rdata, 0, 6);
      const target = readCanonicalName(rr, 6);
      if (target.next !== rdata.length) throw new Error('trailing bytes after SRV target');
      return concat([prefix, target.name]);
    }

    case 35: // NAPTR
      return canonicalNaptrRdata(rr);

    case 47: // NSEC
      return canonicalNsecRdata(rr);

    default:
      // Unknown RR types are opaque: preserve their original RDATA exactly.
      return rdata.slice();
  }
}

interface CanonicalRecord {
  owner: Uint8Array;
  type: number;
  classCode: number;
  ttl: number;
  rdata: Uint8Array;
}

function canonicalOwnerName(rr: ResourceRecord): Uint8Array {
  if (rr.wire instanceof Uint8Array && rr.nameOffset !== undefined) {
    return canonicalName(decodeName(rr.wire, rr.nameOffset).name);
  }
  return canonicalName(rr.name);
}

function toCanonicalRecord(rr: ResourceRecord, options: CanonicalRRSetOptions = {}): CanonicalRecord {
  const type = uint(rr.type, 16, 'type');
  const classCode = uint(rr.classCode, 16, 'classCode');
  const ttl =
    options.originalTtl === undefined
      ? uint(rr.ttl, 32, 'TTL')
      : uint(options.originalTtl, 32, 'originalTtl');
  const owner = applyWildcardLabels(canonicalOwnerName(rr), options.labels);
  const data = canonicalRdata(rr);
  if (data.length > 0xffff) throw new Error('canonical RDATA is too long');
  return { owner, type, classCode, ttl, rdata: data };
}

function compareCanonicalRecords(a: CanonicalRecord, b: CanonicalRecord): number {
  return (
    compareBytes(a.owner, b.owner) ||
    a.type - b.type ||
    a.classCode - b.classCode ||
    a.ttl - b.ttl ||
    compareBytes(a.rdata, b.rdata)
  );
}

function sameRecord(a: CanonicalRecord, b: CanonicalRecord): boolean {
  return (
    a.type === b.type &&
    a.classCode === b.classCode &&
    a.ttl === b.ttl &&
    equalBytes(a.owner, b.owner) &&
    equalBytes(a.rdata, b.rdata)
  );
}

function encodeCanonicalRecords(records: CanonicalRecord[]): Uint8Array {
  return concat(
    records.flatMap((rr) => [
      rr.owner,
      u16(rr.type),
      u16(rr.classCode),
      u32(rr.ttl),
      u16(rr.rdata.length),
      rr.rdata,
    ]),
  );
}

export function encodeCanonicalRRSet(
  records: Iterable<ResourceRecord>,
  options: CanonicalRRSetOptions = {},
): Uint8Array {
  const canonical = Array.from(records, (rr) => toCanonicalRecord(rr, options));
  canonical.sort(compareCanonicalRecords);

  const unique: CanonicalRecord[] = [];
  for (const rr of canonical) {
    if (unique.length === 0 || !sameRecord(unique[unique.length - 1], rr)) unique.push(rr);
  }

  return encodeCanonicalRecords(unique);
}

export function encodeDnssecSignatureInput(
  metadata: RrsigMetadata,
  records: Iterable<ResourceRecord>,
): Uint8Array {
  const prefix = concat([
    u16(uint(metadata.typeCovered, 16, 'typeCovered')),
    Uint8Array.of(
      uint(metadata.algorithm, 8, 'algorithm'),
      uint(metadata.labels, 8, 'labels'),
    ),
    u32(uint(metadata.originalTtl, 32, 'originalTtl')),
    u32(uint(metadata.expiration, 32, 'expiration')),
    u32(uint(metadata.inception, 32, 'inception')),
    u16(uint(metadata.keyTag, 16, 'keyTag')),
    canonicalName(metadata.signerName),
  ]);

  return concat([
    prefix,
    encodeCanonicalRRSet(records, {
      labels: metadata.labels,
      originalTtl: metadata.originalTtl,
    }),
  ]);
}

export function parseTypeBitmapWindows(data: Uint8Array): TypeBitmapWindow[] {
  if (!(data instanceof Uint8Array)) throw new Error('bitmap must be a Uint8Array');

  const windows: TypeBitmapWindow[] = [];
  let pos = 0;
  let previousWindow = -1;

  while (pos < data.length) {
    const window = data[pos++];
    if (pos >= data.length) throw new Error('truncated type bitmap window length');
    const bitmapLength = data[pos++];

    if (bitmapLength === 0) throw new Error('type bitmap window must not be empty');
    if (bitmapLength > 32) throw new Error('type bitmap window cannot exceed 32 bytes');
    if (pos + bitmapLength > data.length) throw new Error('truncated type bitmap window');
    if (window <= previousWindow) throw new Error('type bitmap windows must be unique and ascending');

    windows.push({
      window,
      bitmap: data.slice(pos, pos + bitmapLength),
    });
    previousWindow = window;
    pos += bitmapLength;
  }

  return windows;
}

export function parseTypeBitmap(data: Uint8Array): number[] {
  const types: number[] = [];
  for (const { window, bitmap } of parseTypeBitmapWindows(data)) {
    for (let byteIndex = 0; byteIndex < bitmap.length; byteIndex++) {
      const byte = bitmap[byteIndex];
      for (let bit = 0; bit < 8; bit++) {
        if ((byte & (0x80 >>> bit)) !== 0) {
          types.push(window * 256 + byteIndex * 8 + bit);
        }
      }
    }
  }
  return types;
}

export function encodeTypeBitmapWindows(windows: Iterable<TypeBitmapWindow>): Uint8Array {
  const parts: Uint8Array[] = [];
  let previousWindow = -1;

  for (const entry of windows) {
    const window = uint(entry.window, 8, 'type bitmap window');
    if (!(entry.bitmap instanceof Uint8Array)) throw new Error('bitmap must be a Uint8Array');
    if (entry.bitmap.length > 32) throw new Error('type bitmap window cannot exceed 32 bytes');
    if (window <= previousWindow) {
      throw new Error('type bitmap windows must be unique and ascending');
    }
    previousWindow = window;

    let length = entry.bitmap.length;
    while (length > 0 && entry.bitmap[length - 1] === 0) length--;
    if (length === 0) continue;

    parts.push(Uint8Array.of(window, length), entry.bitmap.subarray(0, length));
  }

  return concat(parts);
}

export function encodeTypeBitmap(types: Iterable<number>): Uint8Array {
  const sorted = Array.from(types, (type) => uint(type, 16, 'DNS type')).sort((a, b) => a - b);
  const windows = new Map<number, Uint8Array>();

  for (let i = 0; i < sorted.length; i++) {
    const type = sorted[i];
    if (i > 0 && type === sorted[i - 1]) continue;

    const window = type >>> 8;
    const bit = type & 0xff;
    let bitmap = windows.get(window);
    if (!bitmap) {
      bitmap = new Uint8Array(32);
      windows.set(window, bitmap);
    }
    bitmap[bit >>> 3] |= 0x80 >>> (bit & 7);
  }

  return encodeTypeBitmapWindows(
    Array.from(windows, ([window, bitmap]) => ({ window, bitmap })).sort(
      (a, b) => a.window - b.window,
    ),
  );
}

export function encodeNsecRdata(
  nextName: string | Uint8Array,
  types: Iterable<number>,
): Uint8Array {
  return concat([canonicalName(nextName), encodeTypeBitmap(types)]);
}

export const encodeNsecBitmap = encodeTypeBitmap;
export const parseNsecBitmap = parseTypeBitmap;
export const encodeNsecBitmapWindows = encodeTypeBitmapWindows;
export const parseNsecBitmapWindows = parseTypeBitmapWindows;
