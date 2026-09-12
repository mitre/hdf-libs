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
});

describe('evidence-verify engine — unit', () => {
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
      { uri: '', type: '', checksum: '' },
      { uri: 'a', type: '', checksum: '' },
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
    // Content present but uri/type absent and checksum object present without a value.
    const { contents } = parseEvidencePackage(JSON.stringify({ contents: [{ checksum: {} }] }));
    expect(contents[0]).toEqual({ uri: '', type: '', checksum: '' });
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
