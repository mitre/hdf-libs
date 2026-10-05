import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

import { describe, it, expect } from 'vitest';
import type { EvaluatedRequirement, Severity } from '@mitre/hdf-schema';

import { rollUpRequirements } from './rollup.js';
import { UNRATED_SEVERITY_TAG, UNRATED_SEVERITY_VALUE } from './converterutil.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Mirrors the two committed grype golden entries for Grype/CVE-2022-48174
 * (busybox@1.31.1-r9 and ssl_client@1.31.1-r9 in
 * converters/grype-to-hdf/fixtures/expected/anchore_grype.json.hdf.json): one
 * CVE reported against two packages, emitted today as two requirements.
 */
function grypeDuplicatePair(): EvaluatedRequirement[] {
  const mk = (pkg: string, purl: string, codeDesc: string): EvaluatedRequirement => ({
    id: 'Grype/CVE-2022-48174',
    impact: 0.9,
    tags: {},
    descriptions: [
      {
        label: 'default',
        data: 'There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35.',
      },
    ],
    affectedPackages: [{ name: pkg, version: '1.31.1-r9', purl }],
    results: [{ codeDesc, status: 'failed', startTime: '2024-07-23T12:42:03.544Z' }],
  });
  return [
    mk(
      'busybox',
      'pkg:apk/alpine/busybox@1.31.1-r9?arch=aarch64&distro=alpine-3.11.3',
      'Package: busybox@1.31.1-r9 | Type: apk | Location: /lib/apk/db/installed | Match Type: cpe-match',
    ),
    mk(
      'ssl_client',
      'pkg:apk/alpine/ssl_client@1.31.1-r9?arch=aarch64&upstream=busybox&distro=alpine-3.11.3',
      'Package: ssl_client@1.31.1-r9 | Type: apk | Location: /lib/apk/db/installed | Match Type: cpe-match',
    ),
  ];
}

// ADR-0017 §6: results concatenate in source order; affectedPackages union,
// de-duplicated on purl where present.
describe('rollUpRequirements', () => {
  it('concatenates results and unions affectedPackages for two entries sharing an id', () => {
    const got = rollUpRequirements(grypeDuplicatePair());

    expect(got).toHaveLength(1);
    expect(got[0].id).toBe('Grype/CVE-2022-48174');

    expect(got[0].results).toHaveLength(2);
    expect(got[0].results[0].codeDesc).toContain('busybox@1.31.1-r9');
    expect(got[0].results[1].codeDesc).toContain('ssl_client@1.31.1-r9');

    expect(got[0].affectedPackages?.map((p) => p.name)).toEqual(['busybox', 'ssl_client']);
  });
});

// ---------------------------------------------------------------------------
// The shared case table — the same file shared/go/rollup_test.go runs, so a rule
// cannot be implemented one way in Go and another in TypeScript.
// ---------------------------------------------------------------------------

interface RollupCase {
  name: string;
  source: string;
  adrRules: string[];
  note: string;
  input: EvaluatedRequirement[];
  expected: unknown;
}

const rollupCases = (
  JSON.parse(readFileSync(join(__dirname, '..', 'rollup-cases.json'), 'utf-8')) as {
    cases: RollupCase[];
  }
).cases;

describe('rollUpRequirements: shared Go/TypeScript case table', () => {
  it.each(rollupCases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const got: unknown = JSON.parse(JSON.stringify(rollUpRequirements(c.input)));
    expect(got, `${c.note}\nsource: ${c.source}`).toEqual(c.expected);
  });

  it('exercises every field ADR-0017 §6 states a rule for', () => {
    const covered = new Set(rollupCases.flatMap((c) => c.adrRules));
    for (const field of Object.keys(FIELD_RULES)) {
      expect(covered.has(field), `no shared case exercises ADR-0017 §6's rule for "${field}"`).toBe(
        true,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// The ADR §6 table itself. The Record type documents the intent, but it is NOT
// a gate: hdf-converters/tsconfig.json excludes **/*.test.ts, so `tsc --noEmit`
// never reads this file. The load-bearing coverage guard is the reflection test
// in shared/go/rollup_test.go; the assertion below only pins this map to the
// shared JSON, so a new schema field fails in Go first.
// ---------------------------------------------------------------------------

type RuleName = 'mergeKey' | 'concat' | 'union' | 'tagsPerKey' | 'worstWins' | 'firstWins' | 'derived';

const FIELD_RULES: Record<keyof EvaluatedRequirement, RuleName> = {
  id: 'mergeKey',
  results: 'concat',
  affectedPackages: 'union',
  code: 'firstWins',
  cwe: 'union',
  refs: 'union',
  externalReferences: 'union',
  evidence: 'union',
  statusOverrides: 'union',
  poams: 'union',
  tags: 'tagsPerKey',
  impact: 'worstWins',
  severity: 'worstWins',
  effectiveImpact: 'worstWins',
  title: 'firstWins',
  descriptions: 'firstWins',
  sourceLocation: 'firstWins',
  controlType: 'firstWins',
  verificationMethod: 'firstWins',
  applicability: 'firstWins',
  cvss: 'firstWins',
  epss: 'firstWins',
  kev: 'firstWins',
  effectiveStatus: 'derived',
  disposition: 'derived',
  effectiveChecksum: 'derived',
};

describe('rollup-field-rules.json', () => {
  const doc = JSON.parse(readFileSync(join(__dirname, '..', 'rollup-field-rules.json'), 'utf-8')) as {
    rules: Record<string, string>;
    fields: Array<{ field: string; rule: string; identity?: string; adrRule: string }>;
  };

  it('matches the rule each field is merged by, so Go and TypeScript cannot drift', () => {
    const fromFile = Object.fromEntries(doc.fields.map((f) => [f.field, f.rule]));
    expect(fromFile).toEqual(FIELD_RULES);
  });

  it('quotes an ADR-0017 §6 row for every field and names only defined rules', () => {
    for (const f of doc.fields) {
      expect(f.adrRule, `field "${f.field}" quotes no ADR row`).not.toBe('');
      expect(Object.keys(doc.rules), `field "${f.field}" names an undefined rule`).toContain(f.rule);
    }
  });
});

// ---------------------------------------------------------------------------
// Scope: one baseline's slice, never a document.
// ---------------------------------------------------------------------------

/**
 * prisma's golden carries 16 baselines, 94 entries, 53 distinct ids and 92
 * distinct (baseline, id) pairs. The id below really does appear in baselines 0,
 * 1, 4 and 9 of prismacloud_sample.csv.hdf.json — different hosts, same
 * compliance check. A document-wide merge would collapse them; the helper takes
 * one baseline's slice and so cannot be asked to.
 */
describe('rollUpRequirements: baseline scope', () => {
  const id = '60522-redhat-RHEL7-high';
  const entry = (host: string): EvaluatedRequirement => ({
    id,
    impact: 0.7,
    tags: {},
    descriptions: [
      {
        label: 'default',
        data: '(CIS_Linux_2.0.0 - 5.2.2) Ensure permissions on SSH private host key files are configured',
      },
    ],
    results: [
      {
        codeDesc: 'Configuration check for redhat-RHEL7',
        status: 'failed',
        startTime: '2026-07-12T22:56:41.753624Z',
      },
    ],
    code: host,
  });

  it('never merges across baselines — the shared id survives in each', () => {
    const baselineZero = rollUpRequirements([entry('my-fake-host-1.somewhere.cloud')]);
    const baselineOne = rollUpRequirements([entry('my-fake-host-2.somewhere.cloud')]);

    expect(baselineZero).toHaveLength(1);
    expect(baselineOne).toHaveLength(1);
    expect(baselineZero[0].id).toBe(id);
    expect(baselineOne[0].id).toBe(id);
    expect(baselineZero[0].code).not.toBe(baselineOne[0].code);
  });
});

// ---------------------------------------------------------------------------
// Ordering, identity and non-mutation.
// ---------------------------------------------------------------------------

describe('rollUpRequirements: ordering and non-mutation', () => {
  const mk = (id: string, codeDesc: string): EvaluatedRequirement => ({
    id,
    impact: 0.1,
    tags: {},
    descriptions: [{ label: 'default', data: id }],
    results: [{ codeDesc, status: 'failed', startTime: '2024-01-01T00:00:00Z' }],
  });

  it('returns a non-duplicate input unchanged', () => {
    const input = [mk('V-1', 'a'), mk('V-2', 'b'), mk('V-3', 'c')];
    expect(rollUpRequirements(input)).toEqual(input);
  });

  it('leaves the survivor at the position of its first member', () => {
    const got = rollUpRequirements([mk('V-1', 'a'), mk('V-2', 'b'), mk('V-3', 'c'), mk('V-2', 'd')]);
    expect(got.map((r) => r.id)).toEqual(['V-1', 'V-2', 'V-3']);
    expect(got[1].results.map((r) => r.codeDesc)).toEqual(['b', 'd']);
  });

  it('does not mutate its input, before or after the caller edits the result', () => {
    const input = grypeDuplicatePair();
    const before = JSON.stringify(input);

    const got = rollUpRequirements(input);
    got[0].results.push({ codeDesc: 'appended by the caller', status: 'failed', startTime: 'x' });
    got[0].affectedPackages?.push({ name: 'late' });

    expect(JSON.stringify(input)).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// The documented divergences from heimdall2's collapseDuplicates
// (libs/hdf-converters/src/base-converter.ts:111-160).
// ---------------------------------------------------------------------------

describe('rollUpRequirements: divergences from heimdall2 collapseDuplicates', () => {
  /**
   * heimdall2 keeps the first control whole and discards every later control's
   * requirement-level fields. ADR-0017 §6 deliberately diverges on
   * affectedPackages and the array-valued tags, which conflict in 64 of our 68
   * real groups.
   */
  it("keeps a later member's packages and array tags", () => {
    const mk = (pkg: string, nist: string): EvaluatedRequirement => ({
      id: 'CVE-2024-0001',
      impact: 0.5,
      tags: { nist: [nist], gid: 'G-1' },
      descriptions: [{ label: 'default', data: 'd' }],
      affectedPackages: [{ purl: `pkg:npm/${pkg}@1.0.0` }],
      results: [{ codeDesc: pkg, status: 'failed', startTime: '2024-01-01T00:00:00Z' }],
    });
    const got = rollUpRequirements([mk('left', 'AC-1'), mk('right', 'AC-2')]);

    expect(got).toHaveLength(1);
    expect(got[0].affectedPackages).toHaveLength(2);
    expect(got[0].tags.nist).toEqual(['AC-1', 'AC-2']);
    expect(got[0].tags.gid).toBe('G-1');
  });

  /**
   * base-converter.ts:120-123 drops an item outright when its key value is not a
   * string, with no else branch. id is schema-required in HDF, so an entry
   * without one is malformed input rather than a control to discard: it passes
   * through, and two such entries are never fused with each other.
   */
  it('keeps entries whose id is empty and never merges them together', () => {
    const blank = (codeDesc: string): EvaluatedRequirement => ({
      id: '',
      impact: 0.5,
      tags: {},
      descriptions: [{ label: 'default', data: 'd' }],
      results: [{ codeDesc, status: 'failed', startTime: '2024-01-01T00:00:00Z' }],
    });
    const named: EvaluatedRequirement = { ...blank('named'), id: 'V-1' };
    const got = rollUpRequirements([blank('first'), named, blank('second')]);

    expect(got).toHaveLength(3);
    expect(got[0].results[0].codeDesc).toBe('first');
    expect(got[1].id).toBe('V-1');
    expect(got[2].results[0].codeDesc).toBe('second');
  });

  /**
   * heimdall2's collapseResults flag (base-converter.ts:167, set by four upstream
   * mappers) skips a later result whose first code_desc is already present.
   * ADR-0017 §6 says concatenate, full stop: each result is one source finding,
   * and dropping one is exactly the under-extraction the result-count anchor
   * exists to catch.
   */
  it('never de-duplicates results', () => {
    const same = { codeDesc: 'identical', status: 'failed' as const, startTime: '2024-01-01T00:00:00Z' };
    const req = (): EvaluatedRequirement => ({
      id: 'V-1',
      impact: 0.5,
      tags: {},
      descriptions: [{ label: 'default', data: 'd' }],
      results: [same],
    });
    const got = rollUpRequirements([req(), req()]);
    expect(got).toHaveLength(1);
    expect(got[0].results).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Worst-wins, where the enum ladder has no case-table expression.
// ---------------------------------------------------------------------------

describe('rollUpRequirements: worst-wins', () => {
  const req = (over: Partial<EvaluatedRequirement>): EvaluatedRequirement => ({
    id: 'V-1',
    impact: 0.5,
    tags: {},
    descriptions: [{ label: 'default', data: 'd' }],
    results: [{ codeDesc: 'c', status: 'failed', startTime: '2024-01-01T00:00:00Z' }],
    ...over,
  });

  it('ranks the whole severity ladder', () => {
    const ladder: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
    ladder.forEach((lower, i) => {
      for (const higher of ladder.slice(i + 1)) {
        const got = rollUpRequirements([req({ severity: lower }), req({ severity: higher })]);
        expect(got[0].severity, `${higher} is worse than ${lower}`).toBe(higher);
      }
    });
  });

  it('treats an absent value as losing to a present one, whichever comes first', () => {
    const present = req({ severity: 'low', effectiveImpact: 0.2 });
    const absent = req({});

    const first = rollUpRequirements([present, absent]);
    expect(first[0].severity).toBe('low');
    expect(first[0].effectiveImpact).toBe(0.2);

    const second = rollUpRequirements([absent, present]);
    expect(second[0].severity).toBe('low');
    expect(second[0].effectiveImpact).toBe(0.2);

    const neither = rollUpRequirements([absent, req({})]);
    expect(neither[0].severity).toBeUndefined();
    expect(neither[0].effectiveImpact).toBeUndefined();
  });

  it('ranks a value outside the enum below every known severity', () => {
    const bogus = 'bogus' as Severity;
    const got = rollUpRequirements([req({ severity: bogus }), req({ severity: 'informational' })]);
    expect(got[0].severity).toBe('informational');

    const both = rollUpRequirements([req({ severity: bogus }), req({ severity: 'other' as Severity })]);
    expect(both[0].severity, 'two unrecognised values fall back to first-wins').toBe(bogus);
  });
});

describe('rollUpRequirements: the unrated-severity marker is derived', () => {
  const req = (over: Partial<EvaluatedRequirement>): EvaluatedRequirement => ({
    id: 'V-1',
    impact: 0.5,
    tags: {},
    descriptions: [{ label: 'default', data: 'd' }],
    results: [{ codeDesc: 'c', status: 'failed', startTime: '2024-01-01T00:00:00Z' }],
    ...over,
  });
  const unrated = () => req({ tags: { severity_rating: 'unrated' } });
  const rated = () => req({ severity: 'high', impact: 0.7 });

  // rollup.ts declares the marker locally to avoid an import cycle with
  // converterutil.ts, which re-exports rollUpRequirements. This pins the copy.
  it('uses the same marker constants converterutil exports', () => {
    expect(UNRATED_SEVERITY_TAG).toBe('severity_rating');
    expect(UNRATED_SEVERITY_VALUE).toBe('unrated');
  });

  it('keeps the marker when every member is unrated', () => {
    const got = rollUpRequirements([unrated(), unrated()]);
    expect(got[0].tags?.[UNRATED_SEVERITY_TAG]).toBe(UNRATED_SEVERITY_VALUE);
  });

  // Kept from the first member it would claim no rating was made beside a
  // genuine worst-wins severity — a self-contradictory requirement.
  it('drops the marker when a later member was rated', () => {
    const got = rollUpRequirements([unrated(), rated()]);
    expect(got[0].tags).not.toHaveProperty(UNRATED_SEVERITY_TAG);
    expect(got[0].severity).toBe('high');
  });

  // The mirror: under the later-only-key rule a plain scalar tag would be ADDED.
  it('does not add the marker from a later member alone', () => {
    const got = rollUpRequirements([rated(), unrated()]);
    expect(got[0].tags).not.toHaveProperty(UNRATED_SEVERITY_TAG);
  });

  it('drops the marker across three members if any one is rated', () => {
    const got = rollUpRequirements([unrated(), unrated(), rated()]);
    expect(got).toHaveLength(1);
    expect(got[0].tags).not.toHaveProperty(UNRATED_SEVERITY_TAG);
  });

  // mergeTags hands back the caller's own object when the later member carries
  // no tags, so dropping in place would reach into the input requirement.
  it('does not mutate the caller when dropping the marker', () => {
    const first = req({ tags: { severity_rating: 'unrated', nist: ['AC-2'] } });
    const second = req({ tags: undefined });
    const input = [first, second];

    const got = rollUpRequirements(input);

    expect(got[0].tags).not.toHaveProperty(UNRATED_SEVERITY_TAG);
    expect(input[0]!.tags?.[UNRATED_SEVERITY_TAG]).toBe(UNRATED_SEVERITY_VALUE);
  });
});

describe('rollUpRequirements: severity_rating carrying a non-marker value', () => {
  // The marker is identified by its value, not just its key: severity_rating
  // carrying anything else is an ordinary scalar tag and first-wins.
  it('first-wins like any other scalar tag', () => {
    const base: EvaluatedRequirement = {
      id: 'V-1',
      impact: 0.5,
      tags: { [UNRATED_SEVERITY_TAG]: 'vendor-specific' },
      descriptions: [{ label: 'default', data: 'd' }],
      results: [{ codeDesc: 'c', status: 'failed', startTime: '2024-01-01T00:00:00Z' }],
    };
    const second: EvaluatedRequirement = { ...base, tags: undefined };

    const got = rollUpRequirements([base, second]);

    expect(got[0].tags?.[UNRATED_SEVERITY_TAG]).toBe('vendor-specific');
  });
});
