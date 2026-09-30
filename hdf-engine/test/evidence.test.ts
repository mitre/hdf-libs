import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'node:crypto';
import {
  parseEvidencePackage,
  verifyChecksums,
  plannedBaselineRefs,
  coveredBaselineNames,
  coveredBaselinesInPackage,
  agentOverridesInPackage,
  completeness,
  checksumHex,
  type EvidenceContent,
  type FetchFn,
} from '../src/evidence.js';

// Shared cross-language fixtures (also read by go/evidence_parity_test.go), so
// both evidence-verify cores run the same input.
const evidenceDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'evidence');
const readText = (name: string): string => readFileSync(join(evidenceDir, name), 'utf-8');
const readBytes = (name: string): Uint8Array => readFileSync(join(evidenceDir, name));
const fetch: FetchFn = (uri) => readBytes(uri);
const sha256Hex = (data: Uint8Array): string => createHash('sha256').update(data).digest('hex');

describe('evidence-verify engine — parity with go/evidence.go', () => {
  it('extracts planned baseline refs from the plan (deduped, in order)', () => {
    expect(plannedBaselineRefs(readText('plan.json'))).toEqual(['RHEL9-STIG', 'PostgreSQL-STIG']);
  });

  it('extracts covered baseline names from results', () => {
    expect(coveredBaselineNames(readText('rhel-results.json'))).toEqual(['RHEL9-STIG']);
  });

  it('computes completeness with a sorted missing list', () => {
    const comp = completeness(['RHEL9-STIG', 'PostgreSQL-STIG'], ['RHEL9-STIG']);
    expect(comp.complete).toBe(false);
    expect(comp.missing).toEqual(['PostgreSQL-STIG']);
  });

  it('aggregates covered baselines and agent overrides across the package (same as Go)', () => {
    const { contents } = parseEvidencePackage(readText('package.json'));
    expect(coveredBaselinesInPackage(contents, fetch)).toEqual(['RHEL9-STIG', 'PostgreSQL-STIG', 'RHEL9-STIG']);
    expect(agentOverridesInPackage(contents, fetch)).toBe(2);
  });

  it('classifies checksums: match, mismatch, skipped (same as Go)', () => {
    const goodHash = sha256Hex(readBytes('rhel-results.json'));
    const contents: EvidenceContent[] = [
      { uri: 'rhel-results.json', type: 'hdf-results', checksum: goodHash },
      { uri: 'plan.json', type: 'hdf-plan', checksum: '0'.repeat(64) },
      { uri: 'rhel-results.json', type: 'hdf-results', checksum: '' },
    ];
    const got = verifyChecksums(contents, fetch);
    expect(got.map((r) => r.status)).toEqual(['match', 'mismatch', 'skipped']);
    expect(got[1]?.expected).toBeTruthy();
    expect(got[1]?.actual).toBeTruthy();
  });

  // The checksum-algorithm contract, pinned on the SHARED package fixture so both
  // languages read the same recorded algorithms rather than two hand-kept copies.
  // go/evidence_parity_test.go asserts these same four outcomes over the same file.
  it('honours each entry\u2019s recorded checksum algorithm (same as Go)', () => {
    const { contents } = parseEvidencePackage(readText('package.json'));
    expect(contents.map((c) => c.checksumAlgorithm)).toEqual(['sha512', 'sha384', 'sha256', 'blake3']);

    // The sha512 and sha384 entries record CORRECT hashes, so guessing sha256
    // would report them as mismatches \u2014 the defect this card fixes. blake3 is in
    // the schema's enum but not computable here, so it is UNSUPPORTED — never a
    // mismatch (which would say the evidence changed) and never an error (the bytes
    // may be intact) — and is reported without ever reading the (absent) file.
    const got = verifyChecksums(contents, fetch);
    expect(got.map((r) => r.status)).toEqual(['match', 'match', 'match', 'unsupported']);
    expect(got[3]?.error).toContain('unsupported checksum algorithm "blake3"');
    expect(got[3]?.actual).toBeUndefined();
  });
});

describe('evidence-verify engine — unit', () => {

  // The schema's Checksum requires an algorithm, so no VALID package omits one.
  // The engine still parses raw JSON, so an omitted algorithm must mean sha256
  // rather than being refused as unsupported \u2014 defensive handling, pinned here
  // because a schema-valid fixture cannot express it. Go asserts the same.
  it('treats an omitted algorithm as sha256', () => {
    const data = readBytes('rhel-results.json');
    const sha256 = createHash('sha256').update(data).digest('hex');
    const fetchOne: FetchFn = () => data;
    // Both the '' the parse yields and an entry built without the field at all.
    const stated: EvidenceContent = { uri: 'x', type: 'hdf-results', checksum: sha256, checksumAlgorithm: '' };
    const omitted: EvidenceContent = { uri: 'x', type: 'hdf-results', checksum: sha256 };
    expect(verifyChecksums([stated, omitted], fetchOne).map((r) => r.status)).toEqual(['match', 'match']);
    expect(checksumHex('', data)).toBe(sha256);
    expect(checksumHex(undefined, data)).toBe(sha256);
  });

  // A skipped entry has no checksum VALUE to verify: no checksum at all, or one
  // whose value is blank (schema-valid — Checksum.value has no minLength) which may
  // still name an algorithm. Nothing was hashed either way. Go asserts the same.
  it('reports no algorithm for an entry it never hashed', () => {
    const got = verifyChecksums(
      [
        { uri: 'none.json', type: 'bom', checksum: '' },
        { uri: 'empty.json', type: 'bom', checksum: '', checksumAlgorithm: 'sha512', checksumRecorded: true },
      ],
      () => new Uint8Array([1]),
    );
    expect(got.map((r) => r.status)).toEqual(['skipped', 'skipped']);
    expect(got.map((r) => r.algorithm)).toEqual([undefined, undefined]);
  });

  it('refuses an algorithm it cannot compute rather than guessing', () => {
    expect(() => checksumHex('blake3', new Uint8Array([1]))).toThrow(/unsupported checksum algorithm "blake3"/);
    expect(() => checksumHex('md5', new Uint8Array([1]))).toThrow(/unsupported checksum algorithm "md5"/);
  });
  it('parses planRef and contents (checksum value or empty)', () => {
    const pkg = JSON.stringify({
      planRef: 'plan.json',
      contents: [
        { type: 'hdf-plan', uri: 'plan.json', checksum: { algorithm: 'sha256', value: 'aa' } },
        { type: 'hdf-results', uri: 'r.json' },
      ],
    });
    const { planRef, contents } = parseEvidencePackage(pkg);
    expect(planRef).toBe('plan.json');
    expect(contents).toHaveLength(2);
    expect(contents[0]?.checksum).toBe('aa');
    expect(contents[1]?.checksum).toBe('');
  });

  it('classifies a fetch failure as error', () => {
    const throwing: FetchFn = () => {
      throw new Error('no such file: x');
    };
    const got = verifyChecksums([{ uri: 'x', type: 'hdf-results', checksum: 'abc' }], throwing);
    expect(got[0]?.status).toBe('error');
    expect(got[0]?.error).toContain('no such file');
  });

  it('throws on malformed input', () => {
    expect(() => parseEvidencePackage('not json')).toThrow();
    expect(() => plannedBaselineRefs('x')).toThrow();
    expect(() => coveredBaselineNames('x')).toThrow();
  });

  // Go decodes into a typed struct, so a JSON null document leaves zero values
  // and a wrong-typed field is a decode error. The TS peer must not TypeError
  // where Go returns a value or a message.
  it('tolerates a null document, as Go does', () => {
    expect(parseEvidencePackage('null')).toEqual({ planRef: '', contents: [] });
    expect(plannedBaselineRefs('null')).toEqual([]);
    expect(coveredBaselineNames('null')).toEqual([]);
  });

  it('tolerates a null content entry, as Go does', () => {
    const { contents } = parseEvidencePackage(JSON.stringify({ contents: [null, { uri: 'a' }] }));
    expect(contents).toEqual([
      { uri: '', type: '', checksum: '', checksumAlgorithm: '', checksumRecorded: false },
      { uri: 'a', type: '', checksum: '', checksumAlgorithm: '', checksumRecorded: false },
    ]);
    expect(plannedBaselineRefs(JSON.stringify({ assessments: [null, { baselineRef: 'A' }] }))).toEqual(['A']);
    expect(coveredBaselineNames(JSON.stringify({ baselines: [null, { name: 'X' }] }))).toEqual(['X']);
  });

  it('reports a wrong-typed field as an error, as Go does', () => {
    expect(() => parseEvidencePackage('[]')).toThrow(/parse evidence package/);
    expect(() => parseEvidencePackage('"x"')).toThrow(/parse evidence package/);
    expect(() => parseEvidencePackage(JSON.stringify({ contents: 'x' }))).toThrow(/parse evidence package/);
    expect(() => parseEvidencePackage(JSON.stringify({ contents: ['x'] }))).toThrow(/parse evidence package/);
    expect(() => plannedBaselineRefs(JSON.stringify({ assessments: 'x' }))).toThrow(/parse plan/);
    expect(() => coveredBaselineNames(JSON.stringify({ baselines: 'x' }))).toThrow(/parse results/);
  });

  it('reports complete when every planned baseline is covered', () => {
    const comp = completeness(['A'], ['A', 'extra']);
    expect(comp.complete).toBe(true);
    expect(comp.missing).toEqual([]);
  });

  it('tolerates absent optional arrays and fields', () => {
    expect(parseEvidencePackage('{}')).toEqual({ planRef: '', contents: [] });
    // Content present but uri/type absent and a checksum object carrying neither a
    // value nor an algorithm: both read as '', never as a fabricated default.
    const { contents } = parseEvidencePackage(JSON.stringify({ contents: [{ checksum: {} }] }));
    // checksumRecorded is true here: the entry DOES carry a checksum object, it is
    // simply empty — the distinction `checksum: ''` alone cannot express.
    expect(contents[0]).toEqual({ uri: '', type: '', checksum: '', checksumAlgorithm: '', checksumRecorded: true });
    expect(plannedBaselineRefs('{}')).toEqual([]);
    expect(coveredBaselineNames('{}')).toEqual([]);
  });

  it('drops assessment/baseline entries missing the field (?? fallback)', () => {
    // An assessment/baseline object present but with baselineRef/name absent must
    // fall back to '' and be filtered out — exercises the nullish-default branch.
    expect(plannedBaselineRefs(JSON.stringify({ assessments: [{ baselineRef: 'A' }, {}] }))).toEqual(['A']);
    expect(coveredBaselineNames(JSON.stringify({ baselines: [{ name: 'X' }, {}] }))).toEqual(['X']);
  });

  it('package aggregators consult only hdf-results entries with a uri and skip unreadable or unparseable ones', () => {
    const agent = new TextEncoder().encode(
      '{"baselines":[{"name":"A","requirements":[{"statusOverrides":[{"appliedBy":{"type":"agent"}}]}]}]}'
    );
    const files: Record<string, Uint8Array> = { 'a.json': agent, 'b.json': new TextEncoder().encode('not json'), 'base.json': agent };
    const mem: FetchFn = (uri) => {
      const data = files[uri];
      if (data === undefined) throw new Error('no such file: ' + uri);
      return data;
    };
    const contents: EvidenceContent[] = [
      { uri: 'a.json', type: 'hdf-results', checksum: '' },
      { uri: 'b.json', type: 'hdf-results', checksum: '' },
      { uri: 'missing.json', type: 'hdf-results', checksum: '' },
      { uri: '', type: 'hdf-results', checksum: '' },
      { uri: 'base.json', type: 'hdf-baseline', checksum: '' },
    ];
    expect(coveredBaselinesInPackage(contents, mem)).toEqual(['A']);
    expect(agentOverridesInPackage(contents, mem)).toBe(1);
    expect(coveredBaselinesInPackage([], mem)).toEqual([]);
  });

  // Go's typed decode rejects a zone-less startTime outright, so this input is
  // the one that pulled the two languages apart. Both must count it.
  it('counts a document whose result timestamps carry no zone', () => {
    const zoneless = JSON.stringify({
      baselines: [
        {
          name: 'A',
          requirements: [
            {
              statusOverrides: [{ appliedBy: { type: 'agent' } }],
              results: [{ status: 'passed', startTime: '2024-01-01T00:00:00' }],
            },
          ],
        },
      ],
    });
    const mem: FetchFn = (uri) => {
      if (uri !== 'z.json') throw new Error('no such file: ' + uri);
      return new TextEncoder().encode(zoneless);
    };
    expect(agentOverridesInPackage([{ uri: 'z.json', type: 'hdf-results', checksum: '' }], mem)).toBe(1);
  });

  it('classifies a non-Error throw as error with the stringified value', () => {
    const throwing: FetchFn = () => {
      throw 'plain string failure';
    };
    const got = verifyChecksums([{ uri: 'x', type: 'hdf-results', checksum: 'abc' }], throwing);
    expect(got[0]?.status).toBe('error');
    expect(got[0]?.error).toBe('plain string failure');
  });
});
