import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { results as sharedResults } from '@mitre/hdf-fixtures';
import {
  filter,
  parseImpactFilter,
  compareImpact,
  tagContains,
  tagMatchesGlob,
  matchesGlob,
  validPoamFilter,
  labelMatchesGlob,
  validBaselineLabel,
  validDisposition,
  DISPOSITION_VALUES,
  POAM_VALID,
  POAM_NONE_VALID,
  type FilterOptions,
  type Match,
} from '../src/query.js';
import { globToRegex, safeGlobMatch } from '../src/safematch.js';
import { computeEffectiveStatus } from '@mitre/hdf-utilities';
import {
  validStatus,
  validSeverity,
  normalizeFilterValue,
  STATUS_VALUES,
  SEVERITY_VALUES,
  filterAliases,
  advertisedFilterValues,
  type FilterAlias,
} from '../src/vocabulary.js';

// Shared cross-language fixture at hdf-engine/testdata (also read by
// go/filter_test.go), so both filter implementations run the same input.
const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'query-fixture.json');
const results = JSON.parse(readFileSync(fixturePath, 'utf-8')) as HDFResults;

// Injected status resolver — maps a requirement's stored result status to the
// CLI's display convention. Mirrors testStatusOf in go/filter_test.go.
function testStatusOf(c: EvaluatedRequirement): string {
  const s = c.results?.[0]?.status as string | undefined;
  switch (s) {
    case 'passed':
      return 'passed';
    case 'failed':
      return 'failed';
    case 'error':
      return 'error';
    case 'notApplicable':
      return 'not_applicable';
    case 'notReviewed':
      return 'not_reviewed';
    default:
      return '';
  }
}

function ids(matches: Match[]): string[] {
  return matches.map((m) => m.id).sort();
}

describe('hdf-engine filter — cross-language parity with go/filter.go', () => {
  // Same case table as go/filter_test.go TestFilter_AllNineFilters.
  const cases: { name: string; opts: FilterOptions; want: string[] }[] = [
    { name: 'no filters', opts: {}, want: ['SV-100001', 'SV-100002', 'SV-230221', 'SV-230222', 'SV-230223'] },
    { name: 'status single', opts: { status: ['failed'] }, want: ['SV-230221'] },
    // testStatusOf returns the CLI's display vocabulary (not_applicable), while a
    // spec names the schema's (notApplicable). Both sides of the comparison
    // canonicalize, which is what reconciles them; without the actual-side half
    // this selects nothing.
    {
      name: 'status canonical against a display-vocabulary resolver',
      opts: { status: ['notApplicable'] },
      want: ['SV-230223'],
    },
    { name: 'status OR', opts: { status: ['failed', 'passed'] }, want: ['SV-230221', 'SV-230222'] },
    { name: 'severity single', opts: { severity: ['critical'] }, want: ['SV-230221'] },
    { name: 'severity OR', opts: { severity: ['high', 'medium'] }, want: ['SV-230222', 'SV-230223'] },
    { name: 'impact >=0.7', opts: { impact: '>=0.7' }, want: ['SV-230221', 'SV-230222'] },
    { name: 'impact <0.5', opts: { impact: '<0.5' }, want: ['SV-100001', 'SV-100002'] },
    { name: 'cci', opts: { cci: ['CCI-000366'] }, want: ['SV-230222'] },
    { name: 'nist exact', opts: { nist: ['AC-2'] }, want: ['SV-230221'] },
    { name: 'nist glob', opts: { nist: ['CM-6*'] }, want: ['SV-230222'] },
    { name: 'id req-id', opts: { id: 'SV-230221' }, want: ['SV-230221'] },
    { name: 'id stig_id', opts: { id: 'RHEL-09-212010' }, want: ['SV-230222'] },
    { name: 'id gid', opts: { id: 'V-230221' }, want: ['SV-230221'] },
    { name: 'tag generic', opts: { tag: ['nist:AU-12'] }, want: ['SV-230223'] },
    { name: 'search', opts: { search: 'auditing' }, want: ['SV-230222'] },
    { name: 'baseline exact', opts: { baseline: 'web-hardening' }, want: ['SV-100001', 'SV-100002'] },
    { name: 'baseline glob', opts: { baseline: 'RHEL9*' }, want: ['SV-230221', 'SV-230222', 'SV-230223'] },
    { name: 'AND status+baseline', opts: { status: ['passed'], baseline: 'RHEL9-STIG' }, want: ['SV-230222'] },
    { name: 'limit 2', opts: { limit: 2 }, want: ['SV-230221', 'SV-230222'] },
  ];

  for (const c of cases) {
    it(`filters: ${c.name}`, () => {
      expect(ids(filter(results, { ...c.opts, statusOf: testStatusOf }))).toEqual(c.want);
    });
  }

  it('is pure/re-entrant — different options do not cross-contaminate', () => {
    const failed = ids(filter(results, { status: ['failed'], statusOf: testStatusOf }));
    const high = ids(filter(results, { severity: ['high'], statusOf: testStatusOf }));
    expect(failed).toEqual(['SV-230221']);
    expect(high).toEqual(['SV-230222']);
  });

  // Parity with go/filter_test.go TestFilter_SeverityHonorsExplicitTag.
  it('severity honors the explicit STIG tag over impact-derived', () => {
    const doc = testhdf.results(testhdf.req('X', { severity: 'high' }));
    expect(ids(filter(doc, { severity: ['high'], statusOf: testStatusOf }))).toEqual(['X']);
    expect(filter(doc, { severity: ['none'], statusOf: testStatusOf })).toHaveLength(0);
    expect(filter(doc, { statusOf: testStatusOf })[0].severity).toBe('high');
  });

  it('nil resolver → empty status; non-status filters still work', () => {
    expect(filter(results, { status: ['failed'] })).toHaveLength(0);
    expect(ids(filter(results, { severity: ['critical'] }))).toEqual(['SV-230221']);
  });

  // Parity with go/filter_test.go TestFilter_StatusCaseInsensitive: a resolver
  // emitting the canonical camelCase schema status is matched case-insensitively.
  it('status match is case-insensitive on both sides', () => {
    const schemaStatusOf = (c: EvaluatedRequirement): string =>
      (c.results?.[0]?.status as string | undefined) ?? 'notReviewed';
    const camel = ids(filter(results, { status: ['notApplicable'], statusOf: schemaStatusOf }));
    const lower = ids(filter(results, { status: ['notapplicable'], statusOf: schemaStatusOf }));
    expect(camel).toEqual(['SV-230223']);
    expect(lower).toEqual(camel);
  });

  it('a --tag value without a colon adds no tag filter', () => {
    const all = ids(filter(results, { statusOf: testStatusOf }));
    expect(ids(filter(results, { tag: ['nocolonhere'], statusOf: testStatusOf }))).toEqual(all);
  });
});

describe('hdf-engine filter helpers — parity with the Go helper unit tests', () => {
  it('parseImpactFilter', () => {
    expect(parseImpactFilter('>0.5')).toEqual(['>', 0.5]);
    expect(parseImpactFilter('>=0.7')).toEqual(['>=', 0.7]);
    expect(parseImpactFilter('<0.4')).toEqual(['<', 0.4]);
    expect(parseImpactFilter('<=0.3')).toEqual(['<=', 0.3]);
    expect(parseImpactFilter('=0.5')).toEqual(['=', 0.5]);
    expect(parseImpactFilter('0.5')).toEqual(['=', 0.5]);
    expect(parseImpactFilter('> 0.5')).toEqual(['>', 0.5]);
    expect(parseImpactFilter('0')).toEqual(['=', 0]);
    // An invalid operand safe-degrades to match NOTHING (val NaN), mirroring the
    // Go engine's `return ok && compareImpact(...)`. It must NOT coerce to
    // ('=', 0), which silently returns confidently-wrong impact==0 rows.
    for (const bad of ['>abc', 'notanumber']) {
      const [, val] = parseImpactFilter(bad);
      expect(Number.isNaN(val)).toBe(true);
    }
  });

  // The impact-filter operand is a plain-decimal grammar kept in lockstep with
  // the Go engine (bead 4908.15). JS Number() is more liberal than the shared
  // grammar (0x1f→31, 0b101→5, 0o17→15, Infinity→Infinity); Go strconv.ParseFloat
  // is liberal in other directions (1_000, 0x1p-2, Inf/NaN). Both engines reject
  // the identical set so a filter behaves the same in Go and TS.
  it('parseImpactFilter enforces the strict-decimal grammar (Go/TS parity)', () => {
    for (const good of ['0.5', '.5', '5.', '+0.5', '-0.5', '1e-2', '1E2', '017', '0', '1', '>=0.7', '<0.5', '  0.5  ', '  >0.5', '> 0.5']) {
      const [, val] = parseImpactFilter(good);
      expect(Number.isNaN(val)).toBe(false);
    }
    for (const bad of ['0x1f', '0X1F', '0b101', '0o17', '1_000', '1_0', '0x1p-2',
      '0x1.8p1', 'Inf', 'inf', 'Infinity', 'NaN', 'nan', '1e400', '>1_000', '>=Inf']) {
      const [, val] = parseImpactFilter(bad);
      expect(Number.isNaN(val)).toBe(true);
    }
  });

  it('compareImpact', () => {
    expect(compareImpact(0.7, '>', 0.5)).toBe(true);
    expect(compareImpact(0.5, '>', 0.5)).toBe(false);
    expect(compareImpact(0.5, '>=', 0.5)).toBe(true);
    expect(compareImpact(0.3, '<', 0.5)).toBe(true);
    expect(compareImpact(0.5, '<=', 0.5)).toBe(true);
    expect(compareImpact(0.5, '=', 0.5)).toBe(true);
    expect(compareImpact(0.5, '~', 0.5)).toBe(false);
  });

  it('tagContains', () => {
    expect(tagContains({}, 'cci', 'CCI-1')).toBe(false);
    expect(tagContains({ nist: 'AC-2' }, 'cci', 'CCI-1')).toBe(false);
    expect(tagContains({ cci: 'CCI-000366' }, 'cci', 'CCI-000366')).toBe(true);
    expect(tagContains({ cci: 'cci-000366' }, 'cci', 'CCI-000366')).toBe(true);
    expect(tagContains({ cci: ['CCI-000365', 'CCI-000366'] }, 'cci', 'CCI-000366')).toBe(true);
    expect(tagContains({ cci: ['CCI-000365'] }, 'cci', 'CCI-000366')).toBe(false);
  });

  it('tagMatchesGlob', () => {
    expect(tagMatchesGlob({ nist: ['AC-2', 'CM-6'] }, 'nist', 'AC-*')).toBe(true);
    expect(tagMatchesGlob({ nist: ['AC-2', 'CM-6'] }, 'nist', 'AU-*')).toBe(false);
    expect(tagMatchesGlob({ severity: 'high' }, 'severity', 'high')).toBe(true);
    expect(tagMatchesGlob({}, 'nist', 'AC-2')).toBe(false);
    expect(tagMatchesGlob({ nist: 'AC-2' }, 'cci', 'CCI-*')).toBe(false);
    expect(tagMatchesGlob({ count: 42 }, 'count', '42')).toBe(false);
  });

  it('globToRegex + matchesGlob + safeGlobMatch', () => {
    expect(globToRegex('AC-2')).toBe('^AC-2$');
    expect(globToRegex('AC-*')).toBe('^AC-.*$');
    expect(globToRegex('AC-?')).toBe('^AC-.$');
    // Each metacharacter escaped exactly once — parity with go/filter_test.go TestGlobToRegex.
    expect(globToRegex('test.json')).toBe('^test\\.json$');
    expect(globToRegex('a\\b')).toBe('^a\\\\b$');
    expect(matchesGlob('AC-2', 'ac-2')).toBe(true);
    expect(matchesGlob('profile-name-v123', 'profile-*-v???')).toBe(true);
    expect(safeGlobMatch('test', 'x'.repeat(257))).toBe(false);
    // Dotted patterns must match — regression guard for the doubled-backslash bug.
    expect(safeGlobMatch('test.json', 'test.json')).toBe(true);
    expect(safeGlobMatch('testXjson', 'test.json')).toBe(false);
    expect(safeGlobMatch('v1.2.3-base', 'v1.2*')).toBe(true);
  });

  it('length caps match Go (byte length + expanded regex) — parity fork fixed', () => {
    // Subject == pattern so a MISSING cap would MATCH (return true); the cap is
    // what makes these false. This is the discriminating check: pre-fix TS (a
    // UTF-16 .length cap, no expanded cap) returned true for both.
    // (i) 200 accented chars: UTF-16 length 200 (<256) but 400 UTF-8 bytes —
    // trips the glob byte cap (matching Go's len(pattern)).
    expect(safeGlobMatch('é'.repeat(200), 'é'.repeat(200))).toBe(false);
    // (ii) 200 dots: a 200-byte glob that expands to a 402-byte regex — trips
    // the expanded-regex cap (matching Go's compileSafeRegex).
    expect(safeGlobMatch('.'.repeat(200), '.'.repeat(200))).toBe(false);
    // A short ASCII pattern with an expansion under the cap still matches.
    expect(safeGlobMatch('AC-2', 'AC-*')).toBe(true);
  });
});

describe('match indices — parity with go/filter_test.go TestFilter_MatchCarriesIndices', () => {
  it('every match names its baseline and requirement by position', () => {
    const matches = filter(results, { statusOf: testStatusOf });
    expect(matches).toHaveLength(5);
    for (const m of matches) {
      const b = results.baselines[m.baselineIndex];
      expect(b).toBeDefined();
      expect(b.name).toBe(m.baseline);
      expect(b.requirements[m.index].id).toBe(m.id);
    }
    const byId = Object.fromEntries(matches.map((m) => [m.id, m]));
    expect(byId['SV-230223'].baselineIndex).toBe(0);
    expect(byId['SV-230223'].index).toBe(2);
    expect(byId['SV-100002'].baselineIndex).toBe(1);
    expect(byId['SV-100002'].index).toBe(1);
  });

  it('indices are unique where (baseline name, id) is not — real Prisma output', () => {
    const dup = JSON.parse(sharedResults.duplicateBaselines.read()) as HDFResults;
    const matches = filter(dup, { statusOf: testStatusOf });
    expect(matches).toHaveLength(94);
    const positions = new Set(matches.map((m) => `${m.baselineIndex}:${m.index}`));
    expect(positions.size).toBe(94);
    const repeated = matches.filter((m) => m.baseline === 'Prisma Cloud Scan' && m.id === '60522-redhat-RHEL7-high');
    expect(repeated).toHaveLength(6);
  });
});

// The shared cross-language contract for the amendment filters. go/filter_test.go
// reads the SAME file and runs the SAME cases, so disposition and poams cannot
// drift between the two implementations. The reference clock lives in the file,
// which is what keeps "expired" a property of the fixture rather than of the day
// the suite runs.
interface AmendmentCases {
  now: string;
  dispositionValues: string[];
  fixture: HDFResults;
  cases: {
    name: string;
    // Declared explicitly rather than relying on the spread of an untyped parse:
    // Go's struct forces an edit when the table gains an option, and without
    // this the TS side would silently drop it — the exact drift the shared table
    // exists to prevent. Parity: amendmentCases in go/filter_test.go.
    options: {
      status?: string[];
      disposition?: string[];
      poams?: string;
      id?: string;
      impact?: string;
      rawImpact?: string;
    };
    effectiveStatus?: boolean;
    expect: string[];
  }[];
}

const amendmentPath = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'testdata',
  'amendment-filter-cases.json'
);
const amendments = JSON.parse(readFileSync(amendmentPath, 'utf-8')) as AmendmentCases;

// A governing waiver has to move a requirement off 'failed' before a status
// filter sees it, or a policy keyed on status blames findings somebody already
// adjudicated. Mirrors effectiveStatusOf in go/compliance_test.go.
function amendmentEffectiveStatusOf(req: EvaluatedRequirement): string {
  return computeEffectiveStatus({
    impact: req.impact,
    overrides: (req.statusOverrides ?? []).map((o) => ({
      appliedAt: o.appliedAt,
      expiresAt: o.expiresAt,
      status: o.status as string | undefined,
    })),
    resultStatuses: (req.results ?? []).map((r) => String(r.status)),
  });
}

describe('amendment filters — disposition and poams (parity with go/filter.go)', () => {
  it('has cases to run', () => {
    expect(amendments.cases.length).toBeGreaterThan(0);
  });

  for (const c of amendments.cases) {
    it(c.name, () => {
      const got = ids(
        filter(amendments.fixture, {
          ...c.options,
          now: amendments.now,
          statusOf: c.effectiveStatus ? amendmentEffectiveStatusOf : testStatusOf,
        })
      );
      expect(got.slice().sort()).toEqual(c.expect.slice().sort());
    });
  }
});

describe('amendment vocabularies match the shared table', () => {
  it('disposition values are the schema enum, in both languages', () => {
    expect(amendments.dispositionValues.length).toBeGreaterThan(0);
    expect([...DISPOSITION_VALUES].sort()).toEqual(amendments.dispositionValues.slice().sort());
    for (const value of amendments.dispositionValues) {
      expect(validDisposition(value)).toBe(true);
    }
  });

  it('refuses a typo rather than letting it match nothing', () => {
    for (const bad of ['', 'waver', 'riskadjustmnet', 'suppressed', 'none']) {
      expect(validDisposition(bad)).toBe(false);
    }
  });
});

describe('validPoamFilter', () => {
  it('accepts only the two values the filter understands', () => {
    for (const ok of ['valid', 'none-valid', '  NONE-VALID  ']) {
      expect(validPoamFilter(ok)).toBe(true);
    }
    // 'absent' and 'present' are deliberately absent: collapsing presence and
    // expiry into one concept is the point, so a presence-only spelling would
    // exist only to be chosen by mistake.
    for (const bad of ['', 'absent', 'present', 'expired', 'none']) {
      expect(validPoamFilter(bad)).toBe(false);
    }
  });
});

// The closed vocabularies and their aliases, read from the same file
// go/vocabulary_test.go reads, so the two languages cannot disagree about a legal
// value or about which forms name the same thing.
interface VocabularyCases {
  statusValues: string[];
  severityValues: string[];
  dispositionValues: string[];
  poamsValues: string[];
  aliases: { field: string; form: string; means: string }[];
  rejected: { field: string; form: string }[];
  advertised: Record<string, string[]>;
}

const vocabPath = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'testdata',
  'filter-vocabulary-cases.json'
);
const vocab = JSON.parse(readFileSync(vocabPath, 'utf-8')) as VocabularyCases;

function validatorFor(field: string): ((s: string) => boolean) | undefined {
  return { status: validStatus, severity: validSeverity, disposition: validDisposition, poams: validPoamFilter }[
    field
  ];
}

describe('filter vocabularies (parity with go/vocabulary.go)', () => {
  it('accepts every value the shared table lists', () => {
    const byField: Record<string, string[]> = {
      status: vocab.statusValues,
      severity: vocab.severityValues,
      disposition: vocab.dispositionValues,
      poams: vocab.poamsValues,
    };
    const declared: Record<string, readonly string[]> = {
      status: STATUS_VALUES,
      severity: SEVERITY_VALUES,
      disposition: DISPOSITION_VALUES,
      poams: [POAM_VALID, POAM_NONE_VALID],
    };
    for (const [field, values] of Object.entries(byField)) {
      expect(values.length).toBeGreaterThan(0);
      const valid = validatorFor(field)!;
      for (const value of values) expect(valid(value), `${field}: ${value}`).toBe(true);
      // Compared BOTH ways: iterating the table only proves the validator
      // accepts what is listed, so an extra or renamed member in the language's
      // own list would be invisible.
      expect([...declared[field]!].sort(), field).toEqual(values.slice().sort());
    }
  });

  it('normalizes every alias onto the value it names', () => {
    expect(vocab.aliases.length).toBeGreaterThan(0);
    for (const alias of vocab.aliases) {
      expect(validatorFor(alias.field)!(alias.form), alias.form).toBe(true);
      expect(normalizeFilterValue(alias.field, alias.form)).toBe(alias.means);
    }
  });

  it('refuses a value outside the vocabulary', () => {
    for (const bad of vocab.rejected) {
      expect(validatorFor(bad.field)!(bad.form), bad.form).toBe(false);
    }
  });

  // The point is not that a validator accepts an alias but that the FILTER
  // selects the same requirements for it.
  it('an alias selects exactly what its canonical form selects', () => {
    const schemaStatus = (c: EvaluatedRequirement) =>
      c.results && c.results.length > 0 ? String(c.results[0]!.status) : 'notReviewed';
    for (const alias of vocab.aliases) {
      // Disposition needs a document carrying a governing override, which the
      // query fixture has none of; the amendment fixture exists for that.
      const subject = alias.field === 'disposition' ? amendments.fixture : results;
      const aliasIds = ids(
        filter(subject, { [alias.field]: [alias.form], statusOf: schemaStatus })
      );
      const canonIds = ids(filter(subject, { [alias.field]: [alias.means], statusOf: schemaStatus }));
      expect(canonIds.length, `${alias.means} must select something`).toBeGreaterThan(0);
      expect(aliasIds, `${alias.form} vs ${alias.means}`).toEqual(canonIds);
    }
  });
});

// The shared vulnerability-field contract, read by go/filter_test.go too so the
// two implementations cannot drift. The decisions each case pins are recorded in
// the table's own $comment.
interface VulnerabilityCases {
  fixture: HDFResults;
  cases: {
    name: string;
    options: { cvss?: string; epss?: string; kev?: string; cwe?: string[] };
    expect: string[];
  }[];
}

const vulnPath = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'testdata',
  'vulnerability-filter-cases.json'
);
const vulnerabilities = JSON.parse(readFileSync(vulnPath, 'utf-8')) as VulnerabilityCases;

describe('vulnerability filters — cvss, epss, kev, cwe (parity with go/filter.go)', () => {
  it('has cases to run', () => {
    expect(vulnerabilities.cases.length).toBeGreaterThan(0);
  });

  for (const c of vulnerabilities.cases) {
    it(c.name, () => {
      const got = ids(filter(vulnerabilities.fixture, { ...c.options, statusOf: testStatusOf }));
      expect(got.slice().sort()).toEqual(c.expect.slice().sort());
    });
  }
});

// Which forms help text should TEACH is a property of the alias entry, not of
// whichever string literal a command holds. Parity: Go
// TestFilterAliasesCarryWhetherToAdvertise / TestAdvertisedFilterValues.
describe('advertised vs merely accepted filter forms', () => {
  it('a separator variant is taught; a retired name is accepted and never taught', () => {
    const byForm = new Map<string, FilterAlias>();
    for (const field of ['status', 'severity', 'disposition']) {
      for (const a of filterAliases(field) ?? []) byForm.set(a.form, a);
    }

    for (const taught of ['not_applicable', 'not_reviewed', 'false_positive']) {
      expect(byForm.get(taught)?.advertise, taught).toBe(true);
    }
    expect(byForm.get('none')?.advertise, 'a retired name must never be advertised').toBe(false);
    expect(byForm.get('none')?.means).toBe('informational');
  });

  it('every alias is accepted whether or not it is advertised', () => {
    const validators: Record<string, (s: string) => boolean> = {
      status: validStatus,
      severity: validSeverity,
      disposition: validDisposition,
    };
    for (const [field, valid] of Object.entries(validators)) {
      for (const a of filterAliases(field) ?? []) {
        expect(valid(a.form), `${field} alias ${a.form}`).toBe(true);
        expect(normalizeFilterValue(field, a.form)).toBe(a.means);
      }
    }
  });

  // The shared table is the pinned authority in BOTH directions. Checking only
  // table -> engine let the ACCEPTED set grow in silence: an alias added with
  // advertise false appeared in no advertised set, so nothing compared it.
  // Parity: Go TestEveryEngineAliasIsListedInTheSharedTable.
  it('every alias the engine accepts is listed in the shared table', () => {
    const listed = new Map<string, string>();
    for (const a of vocab.aliases) listed.set(`${a.field}/${a.form}`, a.means);

    for (const field of ['status', 'severity', 'disposition']) {
      for (const a of filterAliases(field) ?? []) {
        const key = `${field}/${a.form}`;
        expect(
          listed.has(key),
          `engine accepts ${key} but the shared table does not list it — add it to ` +
            `testdata/filter-vocabulary-cases.json so both languages record the decision`,
        ).toBe(true);
        expect(listed.get(key)).toBe(a.means);
      }
    }
  });

  // Read from the shared table so Go cannot advertise a different set. Parity:
  // Go TestAdvertisedFilterValues.
  it('advertisedFilterValues matches the shared table for every field', () => {
    expect(Object.keys(vocab.advertised).length).toBeGreaterThan(0);
    for (const [field, want] of Object.entries(vocab.advertised)) {
      expect(advertisedFilterValues(field), field).toEqual(want);
    }
    expect(advertisedFilterValues('severity')).not.toContain('none');
    expect(validSeverity('none'), 'the retired name must still be accepted').toBe(true);
    expect(advertisedFilterValues('nist')).toBeUndefined();
  });
});

// Parity: go/filter_test.go TestFilterByBaselineLabel and its two siblings. The
// shared fixture labels its FIRST baseline and deliberately leaves the second
// unlabelled, which is what makes "an unlabelled baseline matches nothing"
// assertable rather than assumed.
interface BaselineLabelCases {
  fixtureFile: string;
  unfilteredCount: number;
  unlabelledBaselineIDs: string[];
  cases: { name: string; labels: string[]; expect: string[] }[];
  validity: { value: string; valid: boolean }[];
}

// The same table go/filter_test.go reads, so a case cannot be added or changed
// in one language only.
const labelTable = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'baseline-label-filter-cases.json'),
    'utf-8'
  )
) as BaselineLabelCases;

describe('filter by the baseline s labels', () => {
  // Load through the name the table gives, so the field is followed rather than
  // documenting a path the test hardcodes separately. Parity: loadResultsFixture
  // in go/filter_test.go.
  const labelResults = JSON.parse(
    readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', labelTable.fixtureFile),
      'utf-8'
    )
  ) as HDFResults;

  for (const c of labelTable.cases) {
    it(c.name, () => {
      const got = ids(filter(labelResults, { baselineLabel: c.labels, statusOf: testStatusOf }));
      expect(got).toEqual(c.expect);
    });
  }

  it('the table describes the fixture actually loaded', () => {
    expect(ids(filter(labelResults, { statusOf: testStatusOf }))).toHaveLength(labelTable.unfilteredCount);
  });

  // A colonless value names no key, so it can never match any document.
  // Selecting nothing and being ignored are the same forever-green gate under a
  // max bound, which is why the CLI refuses one rather than relying on silence.
  it.each(labelTable.validity)('validBaselineLabel($value) is $valid', ({ value, valid }) => {
    expect(validBaselineLabel(value)).toBe(valid);
  });

  it('an unlabelled baseline matches nothing', () => {
    const unfiltered = ids(filter(labelResults, { statusOf: testStatusOf }));
    for (const id of labelTable.unlabelledBaselineIDs) {
      expect(unfiltered, 'precondition: reachable without the predicate').toContain(id);
    }

    const got = ids(filter(labelResults, { baselineLabel: ['environment:production'], statusOf: testStatusOf }));
    for (const id of labelTable.unlabelledBaselineIDs) {
      expect(got, 'an unlabelled baseline must not match').not.toContain(id);
    }
    expect(got.length, 'and the labelled one must still match, or this proves nothing').toBeGreaterThan(0);
  });

  it('labelMatchesGlob: an absent key matches nothing, including against *', () => {
    const labels = { environment: 'production', team: 'platform-sre' };
    expect(labelMatchesGlob(labels, 'environment', 'production')).toBe(true);
    expect(labelMatchesGlob(labels, 'environment', 'prod*')).toBe(true);
    expect(labelMatchesGlob(labels, 'team', 'platform-*')).toBe(true);
    expect(labelMatchesGlob(labels, 'environment', 'staging')).toBe(false);
    expect(labelMatchesGlob(labels, 'region', '*')).toBe(false);
    expect(labelMatchesGlob(undefined, 'environment', '*')).toBe(false);
  });
});
