import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'node:crypto';
import {
  parseEvidencePackage,
  parseExternalEvidence,
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

  it('parses externalEvidence preserving all three checksum distinctions (same as Go)', () => {
    const entries = parseExternalEvidence(readText('package.json'));
    expect(entries).toHaveLength(4);
    // The last entry has an EMPTY uri, which is schema-valid (uri is required but has
    // no minLength) and must SURVIVE the parse rather than be dropped, so a caller can
    // report an entry that names nothing to carry.
    expect(entries.map((e) => [e.uri, e.format])).toEqual([
      ['rhel-results.json', 'raw-log'],
      ['agent-results.json', 'ecs'],
      ['plan.json', 'ocsf'],
      ['', 'spdx'],
    ]);
    // A recorded checksum, a recorded-but-BLANK value, and no checksum object: a blank
    // value is unverifiable, an absent one is not a claim at all.
    expect(entries.map((e) => [e.checksum, e.checksumRecorded])).toEqual([
      ['128300c53536f190fe8f9f1161d55965142e7621de9223fe49ce7fe082b77282', true],
      ['', true],
      ['', false],
      ['', false],
    ]);
    // type belongs to contents[]; an external entry must not borrow it.
    expect(entries.map((e) => e.type)).toEqual(['', '', '', '']);
    // And the SAME verifier runs on them — one implementation of the hashing.
    const verified = verifyChecksums(entries, fetch);
    expect(verified.map((r) => r.status)).toEqual(['match', 'skipped', 'skipped', 'skipped']);
    // Carried through, not dropped: a caller reporting the result needs to know what
    // the artifact is without reading `type`'s vocabulary onto it.
    expect(verified.map((r) => r.format)).toEqual(['raw-log', 'ecs', 'ocsf', 'spdx']);
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

    // Every entry records a CORRECT hash under its own algorithm, so guessing sha256 for
    // any of them would report a mismatch. Entries [0] and [3] name the SAME file under
    // sha512 and blake3: one set of bytes, two algorithms, both of which must match, which
    // is what pins this language's blake3 against Go's over one real document. It is the
    // PLAN rather than a results document deliberately: a second hdf-results entry for one
    // file would be counted twice by the aggregation helpers.
    const got = verifyChecksums(contents, fetch);
    expect(got.map((r) => r.status)).toEqual(['match', 'match', 'match', 'match']);
    expect(got[3]?.algorithm).toBe('blake3');
    // Only a mismatch carries expected+actual, so a match reports no actual hash.
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
    // Every algorithm Hash_Algorithm admits is computable now, so the refusal is reachable
    // only from OUTSIDE the enum — a document this tooling did not write.
    // The WHOLE message, list included: go/evidence_test.go asserts this identical string,
    // which is what keeps one refusal from drifting into two spellings across languages.
    expect(() => checksumHex('md5', new Uint8Array([1]))).toThrow(
      'unsupported checksum algorithm "md5": this build computes sha256, sha384, sha512 and blake3',
    );
    expect(() => checksumHex('sha1', new Uint8Array([1]))).toThrow(/unsupported checksum algorithm "sha1"/);
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

// The committed subset of the BLAKE3 reference implementation's own test_vectors.json
// (testdata/blake3-vectors.json records its provenance), read by go/evidence_test.go too.
// The expected digests come from the specification's authors, so a shared misreading by
// the two libraries this repo depends on cannot pass — which agreeing with each other
// alone would allow.
interface Blake3Vectors {
  cases: { input_len: number; hash: string }[];
}
const blake3Vectors = (): Blake3Vectors =>
  JSON.parse(
    readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'blake3-vectors.json'), 'utf-8'),
  ) as Blake3Vectors;

// The input the vector file specifies: the first n bytes of the repeating 251-byte
// sequence 0, 1, 2, ..., 250, 0, 1, ... Generated rather than committed, so the rule is
// stated in code in both languages.
const blake3VectorInput = (n: number): Uint8Array =>
  Uint8Array.from({ length: n }, (_, i) => i % 251);

describe('checksumHex — blake3, against the reference vectors', () => {
  it('matches every committed BLAKE3 reference vector', () => {
    const { cases } = blake3Vectors();
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      // The vector's hash is an extended output; a default-length digest is its first
      // 32 bytes, which is what the upstream file directs implementations to check.
      expect(checksumHex('blake3', blake3VectorInput(c.input_len))).toBe(c.hash.slice(0, 64));
    }
  });

  // Named explicitly so a vector file that lost its multi-chunk cases fails here rather
  // than silently narrowing coverage to inputs below one chunk.
  it('exercises the empty input and a multi-chunk input', () => {
    const lens = blake3Vectors().cases.map((c) => c.input_len);
    expect(lens).toContain(0);
    expect(lens.some((n) => n > 1024)).toBe(true);
  });

  // No schema-valid document can carry an off-schema algorithm, but the refusal exists
  // for documents this tooling did not write.
  it('still refuses an off-schema algorithm', () => {
    expect(() => checksumHex('md5', new Uint8Array([1]))).toThrow();
  });
});
