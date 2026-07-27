import { describe, it, expect } from 'vitest';
import { validateResults, validateBaseline, validateAmendments } from './index.js';

const validRef = [{ sourceName: 'cve', externalId: 'CVE-2021-44228' }];
const badRef = [{ externalId: 'no-source' }];

// Wrap an externalReferences fragment into an otherwise-valid HDF Results doc so
// the test isolates External_Reference validation. Mirrors the Go parity test
// (hdf-validators/go/external_reference_test.go).
function resultsWithExtRefs(externalReferences: unknown): unknown {
  return {
    baselines: [
      {
        name: 'Test Baseline',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        requirements: [
          {
            id: 'REQ-001',
            descriptions: [{ label: 'default', data: 'd' }],
            impact: 0.5,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'ok', startTime: '2025-01-01T00:00:00Z' }],
          },
        ],
      },
    ],
    components: [],
    statistics: {},
    externalReferences,
  };
}

describe('External_Reference validation (HDF Results)', () => {
  it('accepts a by-identity ref (sourceName + externalId)', () => {
    const r = validateResults(resultsWithExtRefs([{ sourceName: 'cve', externalId: 'CVE-2021-44228' }]));
    expect(r.valid, r.getErrorMessage?.() ?? '').toBe(true);
  });

  it('accepts a by-locator ref (sourceName + href with #fragment)', () => {
    const r = validateResults(resultsWithExtRefs([{ sourceName: 'stix', href: '#bundle--1' }]));
    expect(r.valid).toBe(true);
  });

  it('accepts id AND href together (anyOf, not oneOf)', () => {
    const r = validateResults(
      resultsWithExtRefs([
        {
          sourceName: 'cve',
          externalId: 'CVE-2021-44228',
          href: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
          rel: 'definition',
        },
      ]),
    );
    expect(r.valid).toBe(true);
  });

  it('rejects a ref with no sourceName', () => {
    const r = validateResults(resultsWithExtRefs([{ externalId: 'CVE-2021-44228' }]));
    expect(r.valid).toBe(false);
  });

  it('rejects a ref with sourceName but none of externalId/href/description', () => {
    const r = validateResults(resultsWithExtRefs([{ sourceName: 'cve' }]));
    expect(r.valid).toBe(false);
  });
});

// Enrichment envelope (Phase 1b): a reference may embed a lossless copy of the
// referent in `document` and classify the payload with an open `kind`.
describe('External_Reference enrichment envelope (document + kind)', () => {
  it('accepts an embedded document + kind', () => {
    const r = validateResults(
      resultsWithExtRefs([
        {
          sourceName: 'stix',
          externalId: 'threat-actor--9b7e',
          kind: 'threat-intel',
          document: { type: 'threat-actor', id: 'threat-actor--9b7e', name: 'APT-X', spec_version: '2.1' },
        },
      ]),
    );
    expect(r.valid, r.getErrorMessage?.() ?? '').toBe(true);
  });

  it('accepts document composed with href + externalId (envelope + pointer together)', () => {
    const r = validateResults(
      resultsWithExtRefs([
        {
          sourceName: 'stix',
          externalId: 'vulnerability--1',
          href: 'https://cti.example.org/bundles/log4shell.json#vulnerability--1',
          kind: 'threat-intel',
          document: { type: 'vulnerability', id: 'vulnerability--1', name: 'CVE-2021-44228' },
        },
      ]),
    );
    expect(r.valid, r.getErrorMessage?.() ?? '').toBe(true);
  });

  it('accepts an open kind value not in the starter vocabulary', () => {
    const r = validateResults(
      resultsWithExtRefs([{ sourceName: 'acme-feed', externalId: 'x1', kind: 'x-vendor-custom' }]),
    );
    expect(r.valid).toBe(true);
  });

  it('still rejects an embedded document with no sourceName', () => {
    const r = validateResults(resultsWithExtRefs([{ kind: 'threat-intel', document: { type: 'x' } }]));
    expect(r.valid).toBe(false);
  });
});

// DRY-inheritance carriers: externalReferences reaches baseline root + baseline
// requirement (via Baseline_Metadata / Requirement_Core), Evaluated_Baseline +
// Evaluated_Requirement, and Standalone_Override — and enforces the rule there.
describe('External_Reference on inherited carriers', () => {
  const baseline = (rootRefs: unknown, reqRefs: unknown) => ({
    name: 'B', title: 'T', version: '1.0.0',
    checksum: { algorithm: 'sha256', value: 'abc' },
    externalReferences: rootRefs,
    requirements: [{ id: 'R1', title: 't', descriptions: [{ label: 'default', data: 'd' }], impact: 0.5, tags: {}, externalReferences: reqRefs }],
  });
  const resultsSub = (blRefs: unknown, reqRefs: unknown) => ({
    baselines: [{
      name: 'B', checksum: { algorithm: 'sha256', value: 'abc' },
      externalReferences: blRefs,
      requirements: [{ id: 'R1', descriptions: [{ label: 'default', data: 'd' }], impact: 0.5, tags: {}, externalReferences: reqRefs, results: [{ status: 'passed', codeDesc: 'ok', startTime: '2025-01-01T00:00:00Z' }] }],
    }],
    components: [], statistics: {},
  });
  const amendments = (refs: unknown) => ({
    name: 'A',
    overrides: [{
      type: 'riskAdjustment', requirementId: 'CVE-2021-44228', baselineRef: 'B',
      impact: { value: 0.5 }, reason: 'r',
      appliedBy: { type: 'email', identifier: 'a@b.gov' },
      appliedAt: '2026-04-14T10:00:00Z', expiresAt: '2026-10-14T00:00:00Z',
      externalReferences: refs,
    }],
  });
  // Inline Status_Override on Evaluated_Requirement.overrides[] — the carrier the
  // enrich pass's E:A riskAdjustment writes; gains externalReferences[] in 1b.
  const resultsInlineOverride = (refs: unknown) => ({
    baselines: [{
      name: 'B', checksum: { algorithm: 'sha256', value: 'abc' },
      requirements: [{
        id: 'CVE-2021-44228', descriptions: [{ label: 'default', data: 'd' }], impact: 0.5, tags: {},
        results: [{ status: 'failed', codeDesc: 'x', startTime: '2025-01-01T00:00:00Z' }],
        statusOverrides: [{
          type: 'riskAdjustment', reason: 'exploited in the wild (STIX)',
          impact: { value: 0.9 },
          appliedBy: { type: 'email', identifier: 'a@b.gov' },
          appliedAt: '2026-04-14T10:00:00Z', expiresAt: '2026-10-14T00:00:00Z',
          externalReferences: refs,
        }],
      }],
    }],
    components: [], statistics: {},
  });

  it('baseline root + Requirement_Core accept valid, reject malformed', () => {
    expect(validateBaseline(baseline(validRef, validRef)).valid).toBe(true);
    expect(validateBaseline(baseline(badRef, validRef)).valid).toBe(false);
    expect(validateBaseline(baseline(validRef, badRef)).valid).toBe(false);
  });
  it('Evaluated_Baseline + Evaluated_Requirement accept valid, reject malformed', () => {
    expect(validateResults(resultsSub(validRef, validRef)).valid).toBe(true);
    expect(validateResults(resultsSub(badRef, validRef)).valid).toBe(false);
    expect(validateResults(resultsSub(validRef, badRef)).valid).toBe(false);
  });
  it('Standalone_Override accepts valid, rejects malformed', () => {
    expect(validateAmendments(amendments(validRef)).valid).toBe(true);
    expect(validateAmendments(amendments(badRef)).valid).toBe(false);
  });
  it('inline Status_Override accepts valid, rejects malformed', () => {
    expect(validateResults(resultsInlineOverride(validRef)).valid).toBe(true);
    expect(validateResults(resultsInlineOverride(badRef)).valid).toBe(false);
  });
});
