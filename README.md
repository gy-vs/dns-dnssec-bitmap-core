# DNS codec core

TypeScript library for DNS message processing.

Run `npm install`, then `npm test` and `npm run build`.

## DNSSEC canonical data

- `encodeCanonicalRRSet(records, options?)`: emits canonical wire RR records for signing. Owner and relevant RDATA names are lower-cased and uncompressed, records are sorted canonically, and exact canonical duplicates are removed.
- `encodeDnssecSignatureInput(metadata, records)`: emits the RRSIG signing input (`RRSIG RDATA` prefix plus canonical RRset) without performing signing or key management.
- `parseTypeBitmap*` and `encodeTypeBitmap*`: parse and generate NSEC type bitmaps. Encoding groups types by ascending window and removes trailing zero bytes/windows; parsing rejects duplicate, unordered, truncated, or oversized windows.
- Unknown RR types keep their RDATA bytes unchanged.

For records copied from a compressed DNS message, pass the original message as `wire`, along with `nameOffset` and/or `rdataOffset`. Set `labels` (and `originalTtl`) from the RRSIG metadata when wildcard reconstruction or signing input is required.
