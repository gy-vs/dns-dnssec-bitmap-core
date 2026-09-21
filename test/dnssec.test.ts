import { describe, expect, it } from 'vitest';
import {
  encodeCanonicalRRSet,
  encodeDnssecSignatureInput,
  encodeName,
  encodeNsecRdata,
  encodeTypeBitmap,
  encodeTypeBitmapWindows,
  parseTypeBitmap,
  parseTypeBitmapWindows,
  type ResourceRecord,
} from '../src/index.js';

const bytes = (...values: number[]) => Uint8Array.from(values);
const dword = (value: number) => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
};
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');

const rr = (
  name: ResourceRecord['name'],
  type: number,
  rdata: Uint8Array,
  rest: Partial<ResourceRecord> = {},
): ResourceRecord => ({
  name,
  type,
  classCode: rest.classCode ?? 1,
  ttl: rest.ttl ?? 3600,
  rdata,
  ...rest,
});

const recordBytes = (
  name: string,
  type: number,
  classCode: number,
  ttl: number,
  rdata: Uint8Array,
) => {
  const owner = encodeName(name);
  return Uint8Array.from([
    ...owner,
    (type >> 8) & 0xff,
    type & 0xff,
    (classCode >> 8) & 0xff,
    classCode & 0xff,
    ...dword(ttl),
    (rdata.length >> 8) & 0xff,
    rdata.length & 0xff,
    ...rdata,
  ]);
};

describe('canonical RRsets', () => {
  it('lowercases names and canonicalizes names inside RDATA', () => {
    const cname = encodeName('A.Test.');
    const result = encodeCanonicalRRSet([
      rr('B.Example.', 5, cname),
    ]);

    expect(hex(result)).toBe(
      hex(Uint8Array.from([
        ...recordBytes('b.example', 5, 1, 3600, encodeName('a.test')),
      ])),
    );
  });

  it('resolves compression in both owner names and RDATA', () => {
    const header = new Uint8Array(12);
    const ownerAt = 12;
    const compressedName = bytes(1, 65, 4, 84, 101, 115, 116, 0); // A.Test
    const gap = new Uint8Array(10);
    const rrOffset = 30;
    const rdataOffset = 42;
    const fixedRr = bytes(
      0xc0, 0x0c, // owner compression pointer
      0x00, 0x05, // CNAME
      0x00, 0x01, // IN
      ...dword(3600),
      0x00, 0x02, // RDLENGTH
      0xc0, 0x0c, // RDATA compression pointer
    );
    const wire = concat(header, compressedName, gap, fixedRr);

    expect(rrOffset + fixedRr.length).toBe(44);
    expect(rdataOffset).toBe(rrOffset + 12);

    const result = encodeCanonicalRRSet([
      {
        name: bytes(0xc0, 0x0c),
        nameOffset: rrOffset,
        wire,
        rdata: wire.subarray(rdataOffset, rdataOffset + 2),
        rdataOffset,
        type: 5,
        classCode: 1,
        ttl: 3600,
      },
    ]);

    expect(result).toEqual(recordBytes('a.test', 5, 1, 3600, encodeName('a.test')));
  });

  it('resolves compression in NSEC next names', () => {
    const owner = bytes(1, 120, 0); // x
    const target = bytes(1, 78, 6, 115, 97, 109, 112, 108, 101, 0); // N.sample
    const bitmap = bytes(0x00, 0x01, 0x80);
    const rdata = concat(bytes(0xc0, owner.length), bitmap);
    const fixed = concat(
      owner,
      bytes(0x00, 0x2f, 0x00, 0x01),
      dword(3600),
      bytes((rdata.length >> 8) & 0xff, rdata.length & 0xff),
    );
    const wire = concat(owner, target, fixed, rdata);
    const rdataOffset = owner.length + target.length + fixed.length;

    const result = encodeCanonicalRRSet([
      {
        name: owner,
        type: 47,
        classCode: 1,
        ttl: 3600,
        rdata: wire.subarray(rdataOffset, rdataOffset + rdata.length),
        rdataOffset,
        wire,
      },
    ]);

    expect(result).toEqual(
      recordBytes(
        'x',
        47,
        1,
        3600,
        concat(encodeName('n.sample'), bytes(0x00, 0x01, 0x80)),
      ),
    );
  });

  it('removes exact canonical duplicates', () => {
    const one = rr('A.Test.', 5, encodeName('B.Example.'));
    const duplicate = rr('a.test.', 5, encodeName('b.example.'), {
      ttl: 3600,
      classCode: 1,
    });

    expect(encodeCanonicalRRSet([one, duplicate])).toEqual(
      recordBytes('a.test', 5, 1, 3600, encodeName('b.example')),
    );
    expect(encodeCanonicalRRSet([duplicate, one])).toEqual(
      encodeCanonicalRRSet([one, duplicate]),
    );
  });

  it('preserves unknown RR RDATA byte-for-byte', () => {
    const raw = bytes(0xc0, 0x00, 0x00, 0xff);
    const result = encodeCanonicalRRSet([rr('Mixed.Case.', 65280, raw)]);
    expect(result).toEqual(recordBytes('mixed.case', 65280, 1, 3600, raw));
  });

  it('sorts independently of input order', () => {
    const records = [
      rr('b.test.', 99, bytes(2)),
      rr('a.test.', 99, bytes(1), { classCode: 3 }),
      rr('a.test.', 28, bytes(3)),
      rr('a.test.', 16, bytes(4)),
      rr('a.test.', 99, bytes(5), { ttl: 20 }),
      rr('a.test.', 99, bytes(5), { ttl: 10 }),
      rr('a.test.', 99, bytes(1), { classCode: 1 }),
    ];

    const expected = concat(
      recordBytes('a.test', 16, 1, 3600, bytes(4)),
      recordBytes('a.test', 28, 1, 3600, bytes(3)),
      recordBytes('a.test', 99, 1, 10, bytes(5)),
      recordBytes('a.test', 99, 1, 20, bytes(5)),
      recordBytes('a.test', 99, 1, 3600, bytes(1)),
      recordBytes('a.test', 99, 3, 3600, bytes(1)),
      recordBytes('b.test', 99, 1, 3600, bytes(2)),
    );

    expect(encodeCanonicalRRSet(records)).toEqual(expected);
    expect(encodeCanonicalRRSet([...records].reverse())).toEqual(expected);
  });

  it('applies the RRSIG Labels metadata to construct wildcard owners', () => {
    const records = [
      rr('a.b.example.', 16, bytes(1)),
      rr('z.b.example.', 16, bytes(1)),
    ];

    const expected = recordBytes('*.b.example', 16, 1, 3600, bytes(1));
    expect(encodeCanonicalRRSet(records, { labels: 2 })).toEqual(expected);
    expect(encodeCanonicalRRSet([...records].reverse(), { labels: 2 })).toEqual(expected);

    expect(
      encodeCanonicalRRSet([rr('*.b.example.', 16, bytes(1))], { labels: 2 }),
    ).toEqual(expected);
    expect(
      encodeCanonicalRRSet([rr('a.b.example.', 16, bytes(1))], { labels: 1 }),
    ).toEqual(recordBytes('*.example', 16, 1, 3600, bytes(1)));
    expect(() => encodeCanonicalRRSet(records, { labels: 4 })).toThrow(
      'RRSIG labels exceeds owner name labels',
    );
  });
});

describe('NSEC type bitmaps', () => {
  it('parses grouped windows and round-trips types', () => {
    const bitmap = bytes(
      0x00, 0x02, 0x40, 0x01, // A and MX
      0x01, 0x01, 0x01, // type 263
    );

    expect(parseTypeBitmap(bitmap)).toEqual([1, 15, 263]);
    expect(parseTypeBitmapWindows(bitmap)).toEqual([
      { window: 0, bitmap: bytes(0x40, 0x01) },
      { window: 1, bitmap: bytes(0x01) },
    ]);
    expect(encodeTypeBitmap([263, 15, 1])).toEqual(bitmap);
  });

  it('supports an empty bitmap and the highest type number', () => {
    expect(encodeTypeBitmap([])).toEqual(new Uint8Array());
    expect(parseTypeBitmap(new Uint8Array())).toEqual([]);

    const highest = encodeTypeBitmap([65535]);
    expect(highest.slice(0, 2)).toEqual(bytes(255, 32));
    expect(highest[highest.length - 1]).toBe(1);
    expect(parseTypeBitmap(highest)).toEqual([65535]);
    expect(encodeTypeBitmap([15, 1, 15, 1])).toEqual(
      encodeTypeBitmap([1, 15]),
    );
  });

  it('removes trailing zero bytes and empty windows', () => {
    expect(
      encodeTypeBitmapWindows([
        { window: 0, bitmap: bytes(0x80, 0x00) },
        { window: 2, bitmap: bytes(0x00, 0x00) },
      ]),
    ).toEqual(bytes(0x00, 0x01, 0x80));

    const nsec = rr('x.test.', 47, concat(encodeName('N.Example.'), bytes(0, 2, 0x80, 0)));
    expect(encodeCanonicalRRSet([nsec])).toEqual(
      recordBytes(
        'x.test',
        47,
        1,
        3600,
        concat(encodeName('n.example'), bytes(0, 1, 0x80)),
      ),
    );
  });

  it('rejects duplicate, unordered, malformed, and oversized windows', () => {
    expect(() => parseTypeBitmapWindows(bytes(0, 1, 0x80, 0, 1, 0x40))).toThrow(
      'unique and ascending',
    );
    expect(() => parseTypeBitmapWindows(bytes(1, 1, 0x80, 0, 1, 0x40))).toThrow(
      'unique and ascending',
    );
    expect(() => parseTypeBitmapWindows(bytes(0, 0))).toThrow('must not be empty');
    expect(() => parseTypeBitmapWindows(bytes(0, 33, ...new Uint8Array(33)))).toThrow(
      'cannot exceed 32 bytes',
    );
    expect(() => parseTypeBitmapWindows(bytes(0, 2, 0x80))).toThrow('truncated');
    expect(() =>
      encodeTypeBitmapWindows([
        { window: 1, bitmap: bytes(0x80) },
        { window: 0, bitmap: bytes(0x80) },
      ]),
    ).toThrow('unique and ascending');
  });

  it('creates canonical NSEC RDATA', () => {
    expect(encodeNsecRdata('Next.Example.', [15, 1])).toEqual(
      concat(encodeName('next.example'), bytes(0, 2, 0x40, 0x01)),
    );
  });
});

describe('DNSSEC signing input', () => {
  it('writes the RRSIG prefix followed by the canonical RRset', () => {
    const records = [rr('a.b.example.', 16, bytes(7), { ttl: 120 })];
    const metadata = {
      typeCovered: 16,
      algorithm: 8,
      labels: 2,
      originalTtl: 3600,
      expiration: 4102444800,
      inception: 1700000000,
      keyTag: 12345,
      signerName: 'NS.Example.',
    };

    const prefix = concat(
      bytes(0x00, 0x10, 0x08, 0x02),
      dword(3600),
      dword(4102444800),
      dword(1700000000),
      bytes(0x30, 0x39),
      encodeName('ns.example'),
    );
    const expected = concat(
      prefix,
      encodeCanonicalRRSet(records, { labels: 2, originalTtl: 3600 }),
    );

    expect(encodeDnssecSignatureInput(metadata, records)).toEqual(expected);
    expect(encodeDnssecSignatureInput(metadata, [...records].reverse())).toEqual(expected);
  });
});

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
