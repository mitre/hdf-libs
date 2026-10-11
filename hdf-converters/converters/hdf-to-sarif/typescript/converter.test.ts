import { describe, expect, it } from 'vitest';
import { convertHdfToSarif, SARIF_SCHEMA_URI, SARIF_VERSION } from './converter.js';

/** Matches the Go peer's testVersion so the same behaviour is asserted either side. */
const TEST_VERSION = '0.0.0';

/**
 * Far-future, never derived from the clock: a test whose verdict depends on when
 * it runs is broken.
 */
const FAR_FUTURE = '2099-12-31T00:00:00Z';
/** For the cases that assert EXPIRED behaviour. */
const LONG_PAST = '2020-01-01T00:00:00Z';

type Json = Record<string, any>;

/** A schema-valid single-requirement document, with overrides applied on top. */
function doc(req: Json, extra: Json = {}): string {
  return JSON.stringify({
    baselines: [{ name: 'test', requirements: [req] }],
    ...extra,
  });
}

function requirement(over: Json = {}): Json {
  return {
    id: 'V-1',
    impact: 0.5,
    tags: {},
    descriptions: [{ label: 'default', data: 'the default text' }],
    results: [{ status: 'failed', codeDesc: 'a check ran', startTime: LONG_PAST }],
    ...over,
  };
}

function convert(input: string): Json {
  return JSON.parse(convertHdfToSarif(input, TEST_VERSION)) as Json;
}

const run0 = (log: Json): Json => log.runs[0] as Json;
const rules0 = (log: Json): Json[] => (run0(log).tool.driver.rules ?? []) as Json[];
const rule0 = (log: Json): Json => rules0(log)[0] as Json;
const results0 = (log: Json): Json[] => (run0(log).results ?? []) as Json[];
const result0 = (log: Json): Json => results0(log)[0] as Json;

describe('convertHdfToSarif', () => {
  it('declares the format', () => {
    const log = convert(doc(requirement()));
    expect(log.version).toBe('2.1.0');
    expect(log.$schema).toContain('sarif-schema-2.1.0.json');
  });

  // One run per baseline is the modelling decision; a document with several
  // baselines must not collapse into one run, which would merge rules that were
  // never evaluated together and lose every baseline's identity.
  it('emits one run per baseline, each identifying its baseline', () => {
    const input = JSON.stringify({
      baselines: [
        { name: 'first', requirements: [requirement()] },
        { name: 'second', requirements: [requirement({ id: 'V-2' })] },
      ],
    });
    const log = convert(input);
    expect(log.runs).toHaveLength(2);
    expect(log.runs[0].automationDetails.id).toBe('first');
    expect(log.runs[1].automationDetails.id).toBe('second');
  });

  it('converts a document that evaluated nothing into an empty run set', () => {
    expect(convert('{"baselines":[]}').runs).toEqual([]);
  });

  // A clean scan is a run that found nothing, not an error and not an empty file.
  it('still produces a run for a clean document', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'test',
          requirements: [
            requirement({ results: [{ status: 'passed', codeDesc: 'ok', startTime: LONG_PAST }] }),
            requirement({ id: 'V-2', results: [{ status: 'passed', codeDesc: 'ok', startTime: LONG_PAST }] }),
          ],
        },
      ],
    });
    const log = convert(input);
    expect(log.runs).toHaveLength(1);
    expect(results0(log)).toHaveLength(2);
    for (const r of results0(log)) {
      expect(r.kind).toBe('pass');
      expect(r).not.toHaveProperty('level');
    }
  });

  it('falls back to a documented constant for the required driver name', () => {
    expect(run0(convert(doc(requirement()))).tool.driver.name).toBe('HDF Assessment Tool');
    const named = convert(doc(requirement(), { tool: { name: 'Flawfinder', version: '2.0.15' } }));
    expect(run0(named).tool.driver.name).toBe('Flawfinder');
    expect(run0(named).tool.driver.version).toBe('2.0.15');
  });

  // kind and level are orthogonal axes (§3.27.9/§3.27.10): every HDF status maps
  // to its own kind, and the severity stays on the rule where a non-failing
  // result cannot carry it.
  it.each([
    ['passed', 'pass'],
    ['failed', 'fail'],
    ['notApplicable', 'notApplicable'],
    ['notReviewed', 'review'],
    ['error', 'open'],
  ])('maps status %s to kind %s without collapsing level', (status, kind) => {
    const log = convert(
      doc(requirement({ impact: 0.7, results: [{ status, codeDesc: 'c', startTime: LONG_PAST }] })),
    );
    expect(result0(log).kind).toBe(kind);
    expect(rule0(log).defaultConfiguration.level).toBe('error');
    if (kind === 'fail') expect(result0(log).level).toBe('error');
    else expect(result0(log)).not.toHaveProperty('level');
  });

  it.each([
    [0.9, 'error'],
    [0.7, 'error'],
    [0.5, 'warning'],
    [0.4, 'warning'],
    [0.3, 'note'],
    [0.1, 'note'],
    [0, 'none'],
  ])('derives level %s from impact %s', (impact, level) => {
    const log = convert(doc(requirement({ impact })));
    expect(rule0(log).defaultConfiguration.level).toBe(level);
  });

  // Impact 0.0 means no impact, not ungraded, so it cannot produce level "none"
  // by itself — but a severity tag written by sarif-to-hdf holds the source level
  // verbatim and is the one thing that can restore it.
  it('restores the source level from a carried severity tag', () => {
    const none = convert(doc(requirement({ impact: 0.9, tags: { severity: 'none' } })));
    expect(rule0(none).defaultConfiguration.level).toBe('none');
    const hdfWord = convert(doc(requirement({ impact: 0.9, tags: { severity: 'critical' } })));
    expect(rule0(hdfWord).defaultConfiguration.level).toBe('error');
  });

  it('restores collapsed kinds from a carried kind tag, but never against the status', () => {
    const open = convert(doc(requirement({ tags: { kind: 'open' } })));
    expect(result0(open).kind).toBe('open');

    const informational = convert(
      doc(
        requirement({
          tags: { kind: 'informational' },
          results: [{ status: 'notApplicable', codeDesc: 'c', startTime: LONG_PAST }],
        }),
      ),
    );
    expect(result0(informational).kind).toBe('informational');

    const contradictory = convert(
      doc(
        requirement({
          tags: { kind: 'fail' },
          results: [{ status: 'passed', codeDesc: 'c', startTime: LONG_PAST }],
        }),
      ),
    );
    expect(result0(contradictory).kind).toBe('pass');
  });

  it('sends each description to its inverse field', () => {
    const log = convert(
      doc(
        requirement({
          title: 'A title',
          descriptions: [
            { label: 'default', data: 'the default text' },
            { label: 'check', data: 'how to check it' },
            { label: 'rationale', data: 'why it matters' },
            { label: 'fix', data: 'how to fix it' },
          ],
        }),
      ),
    );
    const rule = rule0(log);
    expect(rule.shortDescription.text).toBe('A title');
    expect(rule.fullDescription.text).toBe('why it matters');
    expect(rule.help.text).toBe('how to check it');
    // SARIF's fix object requires an artifactChange with a replacement region,
    // which HDF fix PROSE cannot supply, so the text is carried rather than
    // dressed up as a code change.
    expect(rule).not.toHaveProperty('fixes');
    expect(rule.properties.hdf.descriptions).toHaveLength(4);
  });

  it('builds the tags array and the helpUri', () => {
    const log = convert(
      doc(
        requirement({
          cwe: ['CWE-120', 'CWE-20'],
          tags: {
            nist: ['SI-10'],
            cci: ['CCI-000366'],
            helpUri: 'https://cwe.mitre.org/data/definitions/120.html',
          },
        }),
      ),
    );
    expect(rule0(log).helpUri).toBe('https://cwe.mitre.org/data/definitions/120.html');
    expect(rule0(log).properties.tags).toEqual([
      'cci/CCI-000366',
      'external/cwe/cwe-120',
      'external/cwe/cwe-20',
      'nist/SI-10',
    ]);
  });

  // helpUri carries format uri, so free text would make the document invalid.
  it('drops a helpUri that is not an absolute URI, keeping the raw value', () => {
    const log = convert(doc(requirement({ tags: { helpUri: 'see the vendor advisory' } })));
    expect(rule0(log)).not.toHaveProperty('helpUri');
    expect(rule0(log).properties.hdf.tags.helpUri).toBe('see the vendor advisory');
  });

  // security-severity is SARIF's CVSS convention, so it appears only where the
  // requirement actually carries CVSS.
  it('emits security-severity only with CVSS', () => {
    expect(rule0(convert(doc(requirement({ impact: 0.7 })))).properties).not.toHaveProperty(
      'security-severity',
    );
    const scored = convert(doc(requirement({ cvss: [{ version: '3.1', baseScore: 8.6 }] })));
    expect(rule0(scored).properties['security-severity']).toBe('8.6');
  });

  // SARIF 2.1.0 carries no CVSS field at all, and none for EPSS or KEV.
  it('carries the scoring data SARIF cannot hold', () => {
    const log = convert(
      doc(
        requirement({
          cvss: [{ version: '3.1', baseScore: 9.8 }],
          epss: { date: '2026-01-01', percentile: 0.99, score: 0.97532 },
          kev: { inKev: true, dateAdded: '2024-01-01', dueDate: '2024-01-15' },
        }),
      ),
    );
    const block = rule0(log).properties.hdf as Json;
    expect(block.cvss).toBeTruthy();
    expect(block.epss).toBeTruthy();
    expect(block.kev).toBeTruthy();
  });

  const waiver = (status: string, expiresAt: string): Json => ({
    type: 'waiver',
    status,
    reason: 'accepted risk, documented in the SSP',
    appliedAt: LONG_PAST,
    expiresAt,
    appliedBy: { type: 'simple', identifier: 'isso@example.gov' },
  });

  it('maps a governing override onto an external, accepted suppression', () => {
    const log = convert(
      doc(requirement({ impact: 0.7, statusOverrides: [waiver('notApplicable', FAR_FUTURE)] })),
    );
    const supps = result0(log).suppressions as Json[];
    expect(supps).toHaveLength(1);
    expect(supps[0]?.kind).toBe('external');
    expect(supps[0]?.status).toBe('accepted');
    expect(supps[0]?.justification).toBe('accepted risk, documented in the SSP');
    // The override members SARIF's suppression has no field for.
    const block = supps[0]?.properties.hdf as Json;
    for (const key of ['appliedBy', 'appliedAt', 'expiresAt', 'type']) {
      expect(block).toHaveProperty(key);
    }
  });

  it('does not fake a suppression for an override that leaves the finding failing', () => {
    const log = convert(
      doc(
        requirement({
          impact: 0.7,
          statusOverrides: [{ ...waiver('failed', FAR_FUTURE), type: 'riskAdjustment' }],
        }),
      ),
    );
    expect(result0(log)).not.toHaveProperty('suppressions');
    expect(result0(log).kind).toBe('fail');
  });

  it('suppresses nothing for an expired override', () => {
    const log = convert(
      doc(requirement({ impact: 0.7, statusOverrides: [waiver('notApplicable', '2021-01-01T00:00:00Z')] })),
    );
    expect(result0(log)).not.toHaveProperty('suppressions');
  });

  // The tag sarif-to-hdf writes holds EVERY source suppression, including the
  // rejected and under-review ones an HDF override cannot represent at all.
  it('prefers the carried suppressions tag', () => {
    const log = convert(
      doc(
        requirement({
          tags: {
            suppressions: [
              { kind: 'inSource', status: 'rejected', justification: 'reviewer disagreed' },
              { kind: 'external', status: 'underReview' },
              { kind: 'not-a-kind' },
            ],
          },
        }),
      ),
    );
    const supps = result0(log).suppressions as Json[];
    expect(supps).toHaveLength(2);
    expect(supps[0]).toEqual({
      kind: 'inSource',
      status: 'rejected',
      justification: 'reviewer disagreed',
    });
    expect(supps[1]).toEqual({ kind: 'external', status: 'underReview' });
  });

  it('builds a location from sourceLocation alone', () => {
    const log = convert(
      doc(requirement({ sourceLocation: { ref: 'test/test-patched.c', line: 36 } })),
    );
    const phys = (result0(log).locations as Json[])[0]?.physicalLocation as Json;
    expect(phys.artifactLocation.uri).toBe('test/test-patched.c');
    expect(phys.region.startLine).toBe(36);
    expect(phys.region).not.toHaveProperty('startColumn');
  });

  // The documented tag convention is where region precision lives: Source_Location
  // is {ref, line} and closed, so column and end positions have no schema field.
  it('takes region precision from the sarif-region tag', () => {
    const log = convert(
      doc(
        requirement({
          sourceLocation: { ref: 'test/test-patched.c' },
          tags: {
            'sarif-region': {
              startLine: 36,
              startColumn: 2,
              endColumn: 10,
              endLine: 37,
              charOffset: 1024,
              sourceLanguage: 'c',
              snippet: { text: ' gets(f);' },
              startRow: 99,
            },
          },
        }),
      ),
    );
    const region = (result0(log).locations as Json[])[0]?.physicalLocation.region as Json;
    expect(region).toEqual({
      startLine: 36,
      startColumn: 2,
      endColumn: 10,
      endLine: 37,
      charOffset: 1024,
      sourceLanguage: 'c',
      snippet: { text: ' gets(f);' },
    });
  });

  it('drops region values that are not positions', () => {
    const log = convert(
      doc(
        requirement({
          sourceLocation: { ref: 'a.c' },
          tags: { 'sarif-region': { startLine: 0, startColumn: 2.5, endLine: -3, endColumn: 4 } },
        }),
      ),
    );
    const region = (result0(log).locations as Json[])[0]?.physicalLocation.region as Json;
    expect(region).toEqual({ endColumn: 4 });
  });

  it('restores the fingerprints tag, keeping only values SARIF admits', () => {
    const log = convert(
      doc(
        requirement({
          tags: {
            fingerprints: {
              fingerprints: { 'contextHash/v1': '6a5bb3' },
              partialFingerprints: { primaryLocationLineHash: 'ab12', bad: 7 },
            },
          },
        }),
      ),
    );
    expect(result0(log).fingerprints).toEqual({ 'contextHash/v1': '6a5bb3' });
    expect(result0(log).partialFingerprints).toEqual({ primaryLocationLineHash: 'ab12' });
  });

  // HDF re-reports a requirement id freely while the schema puts uniqueItems on
  // the rules array, so rules dedupe and the later occurrence keeps its own data.
  it('shares one rule between duplicate requirement ids', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'test',
          requirements: [
            requirement({ title: 'first layer', impact: 0.7 }),
            requirement({ title: 'second layer', impact: 0.3 }),
          ],
        },
      ],
    });
    const log = convert(input);
    expect(rules0(log)).toHaveLength(1);
    const res = results0(log);
    expect(res).toHaveLength(2);
    expect(res[1]?.ruleIndex).toBe(0);
    expect(res[1]?.properties.hdf.requirement.impact).toBe(0.3);
    expect(res[0]?.properties.hdf).not.toHaveProperty('requirement');
  });

  it('emits only a rule for a requirement with no results', () => {
    const log = convert(doc(requirement({ results: [] })));
    expect(rules0(log)).toHaveLength(1);
    expect(results0(log)).toHaveLength(0);
    expect(rule0(log).properties).toHaveProperty('hdf');
  });

  it('names this exporter in the conversion object and carries the HDF generator', () => {
    const log = convert(doc(requirement(), { generator: { name: 'sarif-to-hdf', version: '3.7.2' } }));
    expect(run0(log).conversion.tool.driver).toEqual({ name: 'hdf-to-sarif', version: TEST_VERSION });
    expect(run0(log).properties.hdf.generator.name).toBe('sarif-to-hdf');
  });

  it.each([
    ['empty', ''],
    ['top-level array', '[]'],
    ['no baselines', '{"generator":{"name":"t","version":"1"}}'],
  ])('rejects %s, naming the converter', (_name, input) => {
    expect(() => convertHdfToSarif(input, TEST_VERSION)).toThrow(/hdf-to-sarif/);
  });

  // Both languages reject unparseable input (the corpus goldens pin that), but
  // the TypeScript message comes from hdf-utilities parseJSON and carries no
  // converter prefix where Go's does. That asymmetry is in the shared guard, not
  // here, so this asserts only the rejection.
  it('rejects input that is not JSON', () => {
    expect(() => convertHdfToSarif('not json', TEST_VERSION)).toThrow(/Invalid JSON/);
  });
});

describe('version and schema URI cannot drift apart', () => {
  // The URI embeds the version three times in a path that is NOT derivable from the
  // version string, so the two constants cannot be generated from one another and
  // would otherwise drift in silence when the version is repointed. This is what
  // makes deferring --to sarif@<version> safe: repointing is two edits per language,
  // and this fails if only one is made. Mirrors Go's TestSARIFSchemaURIContainsTheVersion.
  it('the schema URI names the version the converter emits', () => {
    expect(SARIF_SCHEMA_URI).toContain(SARIF_VERSION);
    expect(SARIF_VERSION).not.toBe('');
    expect(SARIF_SCHEMA_URI.startsWith('https://')).toBe(true);
  });
});
