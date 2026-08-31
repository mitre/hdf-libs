import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { convertHdfToOscalSar, aggregateStatus } from './converter.js';
import { nistTagToControlId as nistTagToControlID, impactToSeverity } from '../../oscal-to-hdf/typescript/shared.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// The conversion moment lands in these keys; every other date in the output is
// input-derived and must stay asserted.
// Only last-modified is genuinely volatile: it is when the document was written.
// result.start and observation.collected are assessment times derived from the
// input, so the golden asserts them rather than masking them away.
const SAR_VOLATILE_KEYS = ['last-modified'];

/**
 * Returns a minimal valid HDF Results JSON string with one baseline,
 * one requirement, and one result.
 */
function minimalHDFResults(status: string): string {
  return JSON.stringify(
    testhdf.doc(
      testhdf.baseline(
        'test-baseline',
        testhdf.req('AC-1', {
          impact: 0.5,
          tags: { nist: ['AC-1'] },
          desc: 'Test requirement description',
          status,
          codeDesc: 'Test code description',
        }),
      ),
    ),
  );
}

describe('convertHdfToOscalSar', () => {
  it('should reject empty input', async () => {
    await expect(convertHdfToOscalSar('')).rejects.toThrow('empty input');
  });

  it('should reject invalid JSON', async () => {
    await expect(convertHdfToOscalSar('{invalid')).rejects.toThrow('failed to parse HDF JSON');
  });

  it('should reject missing baselines', async () => {
    await expect(convertHdfToOscalSar('{}')).rejects.toThrow('missing baselines');
  });

  // descriptions/results are optional on a requirement; the Go converter ranges
  // nil slices safely, so TS must too rather than throwing "not iterable".
  it('converts a requirement with no descriptions or results (Go/TS parity)', async () => {
    const input = JSON.stringify({
      baselines: [{ name: 'b', requirements: [{ id: 'AC-3', impact: 0.5, tags: { nist: ['AC-3'] } }] }],
    });
    const result = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0];
    expect(result.findings).toHaveLength(1);
    // no default description → falls back to the requirement id/title
    expect(result.findings[0].description).toBe('AC-3');
    // no results → no observation emitted
    expect(result.observations ?? []).toHaveLength(0);
  });

  it('should map code, check/fix/rationale, cci, classification, and refs onto the finding', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'SV-1', impact: 0.7, title: 'req',
          tags: { nist: ['AC-2'], cci: ['CCI-000012'] },
          descriptions: [
            { label: 'default', data: 'default desc' },
            { label: 'check', data: 'check text' },
            { label: 'fix', data: 'fix text' },
            { label: 'rationale', data: 'rationale text' },
          ],
          code: "control 'SV-1' do end",
          controlType: 'technical', verificationMethod: 'automated', applicability: 'required',
          refs: [{ url: 'https://example.gov/a' }, { uri: 'https://example.gov/b' }, { ref: 'Handbook 3' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
        }],
      }],
    });
    const doc = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'];
    const finding = doc.results[0].findings[0];
    const propVal = (name: string) => finding.props.find((p: { name: string; value: string }) => p.name === name)?.value;
    expect(propVal('cci')).toBe('CCI-000012');
    // Single-line prose keeps its full text as the prop value (no remarks needed).
    expect(propVal('check')).toBe('check text');
    expect(propVal('rationale')).toBe('rationale text');
    expect(propVal('control-type')).toBe('technical');
    expect(propVal('verification-method')).toBe('automated');
    expect(propVal('applicability')).toBe('required');
    expect(propVal('reference')).toBe('Handbook 3');

    // impact > 0: fix text's home is the risk remediation, not a finding prop.
    expect(propVal('fix')).toBeUndefined();
    expect(doc.results[0].risks[0].remediations[0].description).toBe('fix text');

    // code is an embedded back-matter resource linked from the finding, not a prop.
    expect(propVal('code')).toBeUndefined();
    const codeLink = finding.links.find((l: { rel?: string }) => l.rel === 'code');
    expect(codeLink).toBeDefined();
    const referenceHrefs = finding.links
      .filter((l: { rel?: string }) => l.rel !== 'code')
      .map((l: { href: string }) => l.href);
    expect(referenceHrefs).toEqual(['https://example.gov/a', 'https://example.gov/b']);
    const resource = doc['back-matter'].resources[0];
    expect(codeLink.href).toBe(`#${resource.uuid}`);
    expect(Buffer.from(resource.base64.value, 'base64').toString('utf-8')).toContain("control 'SV-1'");
    // url/uri refs are also emitted as observation relevant-evidence so they
    // round-trip through the reverse importer (which ignores finding.links).
    const obs = doc.results[0].observations[0];
    expect(obs['relevant-evidence'].map((e: { href: string }) => e.href)).toEqual([
      'https://example.gov/a',
      'https://example.gov/b',
    ]);
  });

  // a1: finding state reflects effectiveStatus (post-override posture), not the
  // raw failing result; disposition + override provenance land in the remarks.
  it('derives finding state from effectiveStatus and surfaces override provenance', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.7, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
          effectiveStatus: 'passed',
          disposition: 'falsePositive',
          statusOverrides: [{
            type: 'falsePositive', status: 'passed', reason: 'scanner mis-detection',
            appliedBy: { type: 'simple', identifier: 'jdoe' },
            appliedAt: '2026-01-02T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
          }],
        }],
      }],
    });
    const result = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0];
    const status = result.findings[0].target.status;
    expect(status.state).toBe('satisfied');
    expect(status.remarks).toContain('Disposition: falsePositive');
    expect(status.remarks).toContain('Reason: scanner mis-detection');
    expect(status.remarks).toContain('Applied by: jdoe');
    expect(status.remarks).toContain('Expires at: 2099-12-31T00:00:00Z');
    // Raw failed result preserved in the observation.
    expect(result.observations[0].description).toContain('[failed]');
    // Governing override expiry becomes the risk deadline + accepted remediation.
    expect(result.risks[0].deadline).toBe('2099-12-31T00:00:00Z');
    const accepted = result.risks[0].remediations.find((r: { lifecycle: string }) => r.lifecycle === 'accepted');
    expect(accepted.title).toBe('falsePositive');
    expect(accepted.description).toBe('scanner mis-detection');
  });

  it('maps effectiveStatus notApplicable to not-satisfied / not-applicable', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.5, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'passed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
          effectiveStatus: 'notApplicable',
        }],
      }],
    });
    const status = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0].findings[0].target.status;
    expect(status.state).toBe('not-satisfied');
    expect(status.reason).toBe('not-applicable');
  });

  // a3: explicit severity drives the risk facet; cwe/epss/kev/cvss become props.
  it('surfaces severity, cwe, epss, kev, and cvss enrichment', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.3, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
          severity: 'critical',
          cwe: ['CWE-79', 'CWE-89'],
          epss: { date: '2026-01-01', score: 0.97532, percentile: 0.999 },
          kev: { inKev: true, dateAdded: '2025-01-01', dueDate: '2025-02-01' },
          cvss: [{ version: '3.1', baseScore: 9.8, baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
        }],
      }],
    });
    const result = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0];
    const props = result.findings[0].props as Array<{ name: string; value: string }>;
    const vals = (name: string) => props.filter((p) => p.name === name).map((p) => p.value);
    expect(vals('cwe')).toEqual(['CWE-79', 'CWE-89']);
    expect(vals('epss-score')).toEqual(['0.97532']);
    expect(vals('kev')).toEqual(['true']);
    expect(vals('kev-due-date')).toEqual(['2025-02-01']);
    expect(vals('cvss-base-score')).toEqual(['9.8']);
    expect(result.risks[0].characterizations[0].facets[0].value).toBe('critical');
  });

  // a4/a5: refs, evidence, and sourceLocation land in relevant-evidence.
  it('emits refs, evidence, and source location as relevant-evidence', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.5, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
          refs: [{ url: 'https://example.gov/evidence' }],
          evidence: [{ type: 'log', data: 'saw the thing', description: 'log excerpt' }],
          sourceLocation: { ref: 'controls/ac-1.rb', line: 42 },
        }],
      }],
    });
    const ev = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0].observations[0]['relevant-evidence'] as Array<{ href?: string; description: string }>;
    expect(ev.filter((e) => e.href).map((e) => e.href)).toEqual(['https://example.gov/evidence']);
    expect(ev.map((e) => e.description)).toContain('log excerpt');
    expect(ev.map((e) => e.description)).toContain('Source location: controls/ac-1.rb:42');
  });

  // a6: fix description becomes a risk remediation.
  it('emits the fix description as a risk remediation', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.5, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }, { label: 'fix', data: 'apply the patch' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
        }],
      }],
    });
    const rems = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0].risks[0].remediations;
    expect(rems[0].lifecycle).toBe('recommendation');
    expect(rems[0].description).toBe('apply the patch');
  });

  // a7: externalReferences with an href become finding links.
  it('emits externalReferences as finding links', async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.5, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
          externalReferences: [{ sourceName: 'cve', href: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }],
        }],
      }],
    });
    const links = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0].findings[0].links as Array<{ href: string }>;
    expect(links.map((l) => l.href)).toContain('https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
  });

  // a2/a8: minimal fixture carries a component and baseline version.
  it('surfaces components as subjects and baseline version as a result prop', async () => {
    const result = JSON.parse(await convertHdfToOscalSar(results.minimal.read()))['assessment-results'].results[0];
    const props = result.props as Array<{ name: string; value: string }>;
    expect(props.find((p) => p.name === 'baseline-version')?.value).toBe('1.0.0');
    const subj = result.observations[0].subjects[0];
    expect(subj.title).toBe('web-server-01');
    expect(subj.type).toBe('host');
    expect(subj['subject-uuid']).toBeTruthy();
  });

  it('should convert minimal passed HDF to valid OSCAL SAR', async () => {
    const input = minimalHDFResults('passed');
    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc).toHaveProperty('assessment-results');
    const sar = doc['assessment-results'];

    expect(sar.uuid).toBeTruthy();
    expect(sar.metadata.title).toBe('HDF Assessment Results Export');
    expect(sar.metadata['oscal-version']).toBe('1.1.2');
    expect(sar['import-ap']).toBeDefined();
    expect(sar['import-ap'].href).toBe('#');

    expect(sar.results).toHaveLength(1);
    const result = sar.results[0];
    expect(result.uuid).toBeTruthy();
    expect(result.title).toBe('test-baseline');
    expect(result.start).toBeTruthy();

    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding.uuid).toBeTruthy();
    expect(finding.target['target-id']).toBe('ac-1');
    expect(finding.target.type).toBe('objective-id');
    expect(finding.target.status.state).toBe('satisfied');
    expect(finding.target.status.reason).toBeUndefined();

    // Should have observation
    expect(result.observations).toHaveLength(1);
    expect(result.observations[0].uuid).toBeTruthy();
    expect(result.observations[0].description).toContain('passed');

    // Should have risk (impact > 0)
    expect(result.risks).toHaveLength(1);
    expect(result.risks[0].status).toBe('closed');
  });

  it('should convert minimal failed HDF correctly', async () => {
    const input = minimalHDFResults('failed');
    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    const finding = doc['assessment-results'].results[0].findings[0];
    expect(finding.target.status.state).toBe('not-satisfied');

    const risk = doc['assessment-results'].results[0].risks[0];
    expect(risk.status).toBe('open');
  });

  it('should map all HDF statuses correctly', async () => {
    const tests = [
      { hdfStatus: 'passed', expectedState: 'satisfied', expectedOpen: 'closed' },
      { hdfStatus: 'failed', expectedState: 'not-satisfied', expectedOpen: 'open' },
      { hdfStatus: 'error', expectedState: 'not-satisfied', expectedOpen: 'open' },
      { hdfStatus: 'notReviewed', expectedState: 'not-satisfied', expectedOpen: 'open' },
      { hdfStatus: 'notApplicable', expectedState: 'not-satisfied', expectedOpen: 'open' },
    ];

    for (const tc of tests) {
      const input = minimalHDFResults(tc.hdfStatus);
      const output = await convertHdfToOscalSar(input);
      const doc = JSON.parse(output);

      const finding = doc['assessment-results'].results[0].findings[0];
      expect(finding.target.status.state).toBe(tc.expectedState);

      const risk = doc['assessment-results'].results[0].risks[0];
      expect(risk.status).toBe(tc.expectedOpen);
    }
  });

  it('should handle enhanced control IDs', async () => {
    const input = JSON.stringify(testhdf.doc(testhdf.baseline('test',
      testhdf.req('AC-2 (3)', {
        impact: 0.7,
        tags: { nist: ['AC-2 (3)'] },
        desc: 'Enhanced control',
        status: 'passed',
        codeDesc: 'test',
      }))));

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    const finding = doc['assessment-results'].results[0].findings[0];
    expect(finding.target['target-id']).toBe('ac-2.3');
  });

  it('should generate unique UUIDs', async () => {
    const input = minimalHDFResults('failed');
    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    const uuids = new Set<string>();
    uuids.add(doc['assessment-results'].uuid);

    for (const result of doc['assessment-results'].results) {
      expect(uuids.has(result.uuid)).toBe(false);
      uuids.add(result.uuid);

      for (const f of result.findings) {
        expect(uuids.has(f.uuid)).toBe(false);
        uuids.add(f.uuid);
      }
      for (const o of result.observations || []) {
        expect(uuids.has(o.uuid)).toBe(false);
        uuids.add(o.uuid);
      }
      for (const r of result.risks || []) {
        expect(uuids.has(r.uuid)).toBe(false);
        uuids.add(r.uuid);
      }
    }
  });

  it('should use planRef when provided', async () => {
    const planRef = 'https://example.com/assessment-plan';
    const input = JSON.stringify({
      ...testhdf.doc(testhdf.baseline('test',
        testhdf.req('AC-1', {
          impact: 0.5,
          tags: { nist: ['AC-1'] },
          desc: 'desc',
          status: 'passed',
          codeDesc: 'test',
        }))),
      planRef,
    });

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results']['import-ap'].href).toBe(planRef);
  });

  it('should output valid JSON with assessment-results root key', async () => {
    const input = minimalHDFResults('passed');
    const output = await convertHdfToOscalSar(input);
    const raw = JSON.parse(output);
    expect(raw).toHaveProperty('assessment-results');
  });

  it('should handle empty baselines array', async () => {
    const input = JSON.stringify({ baselines: [] });
    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results'].results).toHaveLength(0);
  });

  it('should handle multiple requirements', async () => {
    const input = JSON.stringify(testhdf.doc(testhdf.baseline('multi-test',
      testhdf.req('AC-1', {
        impact: 0.5,
        tags: { nist: ['AC-1'] },
        desc: 'first',
        status: 'passed',
        codeDesc: 'test1',
      }),
      testhdf.req('AC-2', {
        impact: 0.7,
        tags: { nist: ['AC-2'] },
        desc: 'second',
        status: 'failed',
        codeDesc: 'test2',
      }))));

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results'].results).toHaveLength(1);
    expect(doc['assessment-results'].results[0].findings).toHaveLength(2);
    expect(doc['assessment-results'].results[0].observations).toHaveLength(2);
    expect(doc['assessment-results'].results[0].risks).toHaveLength(2);
  });

  it('should use baseline title when provided', async () => {
    const base = {
      ...testhdf.baseline('test',
        testhdf.req('AC-1', {
          impact: 0.5,
          tags: { nist: ['AC-1'] },
          desc: 'desc',
          status: 'passed',
          codeDesc: 'test',
        })),
      title: 'My Custom Baseline Title',
    };
    const input = JSON.stringify(testhdf.doc(base));

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results'].results[0].title).toBe('My Custom Baseline Title');
  });

  it('should not produce a risk for zero impact', async () => {
    const input = JSON.stringify(testhdf.doc(testhdf.baseline('test',
      testhdf.req('AC-1', {
        impact: 0.0,
        tags: { nist: ['AC-1'] },
        desc: 'desc',
        status: 'passed',
        codeDesc: 'test',
      }))));

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results'].results[0].risks).toHaveLength(0);
    expect(doc['assessment-results'].results[0].findings[0]['related-risks']).toBeUndefined();
  });
});

describe('nistTagToControlID', () => {
  it.each([
    ['AC-1', 'ac-1'],
    ['AC-2 (3)', 'ac-2.3'],
    ['SI-7 (1)', 'si-7.1'],
    ['CM-6', 'cm-6'],
  ])('should convert %s to %s', (tag, expected) => {
    expect(nistTagToControlID(tag)).toBe(expected);
  });
});

describe('impactToSeverity', () => {
  it.each([
    [0.9, 'critical'],
    [0.7, 'high'],
    [0.5, 'moderate'],
    [0.3, 'low'],
    [0.0, 'info'],
  ])('should map impact %f to %s', (impact, severity) => {
    expect(impactToSeverity(impact)).toBe(severity);
  });
});

describe('aggregateStatus', () => {
  it('should return not-satisfied/other for empty results', () => {
    expect(aggregateStatus([])).toEqual({ state: 'not-satisfied', reason: 'other' });
  });

  it('should return satisfied for all passed', () => {
    const results = [
      { status: 'passed', codeDesc: 'test', startTime: new Date() },
    ] as any[];
    expect(aggregateStatus(results).state).toBe('satisfied');
  });

  it('should return not-satisfied for failed', () => {
    const results = [
      { status: 'failed', codeDesc: 'test', startTime: new Date() },
    ] as any[];
    expect(aggregateStatus(results).state).toBe('not-satisfied');
  });
});

// Whole-output equality with the SAME golden the Go TestGoldenParity asserts.
// Fresh UUIDs and the conversion timestamp are masked (see golden-mask.ts) —
// the UUID reference graph survives masking, so wiring differences still fail.
describe('hdf-to-oscal-sar golden parity', () => {
  it('matches the minimal golden (TS↔Go parity)', async () => {
    const out = await convertHdfToOscalSar(results.minimal.read());
    const golden = readFileSync(
      join(__dirname, '..', 'fixtures', 'expected', 'minimal.oscal-sar.json'),
      'utf-8',
    );

    expect(maskVolatileJson(JSON.parse(out), SAR_VOLATILE_KEYS)).toEqual(
      maskVolatileJson(JSON.parse(golden), SAR_VOLATILE_KEYS),
    );
  });
});

describe('result.start is the assessment time', () => {
  // OSCAL result.start means when the ASSESSMENT ran. HDF carries that on each
  // requirement result (startTime); the document-level timestamp is when the HDF
  // file was produced. Stamping the document timestamp into result.start reports
  // the conversion time and drops the real assessment time.
  const hdf = (startTimes: string[]) => JSON.stringify({
    timestamp: '2026-07-13T09:00:00Z',
    baselines: [{
      name: 'b1',
      requirements: [{
        id: 'AC-1',
        impact: 0.5,
        descriptions: [{ label: 'default', data: 'd' }],
        tags: { nist: ['AC-1'] },
        results: startTimes.map(startTime => ({
          status: 'passed', codeDesc: 'c', startTime,
        })),
      }],
    }],
  });

  it('uses the earliest result startTime, not the document timestamp', async () => {
    const out = JSON.parse(await convertHdfToOscalSar(
      hdf(['2026-03-01T09:45:00Z', '2026-03-01T08:15:00Z'])));
    const result = out['assessment-results'].results[0];

    expect(result.start).toBe('2026-03-01T08:15:00Z');
    expect(result.start, 'must not be the conversion time').not.toBe('2026-07-13T09:00:00Z');
  });

  // Go formats with time.RFC3339 (UTC, no fraction). TS must match, or the two
  // implementations emit different strings for the same instant.
  it('normalises to UTC at seconds precision, matching Go', async () => {
    const out = JSON.parse(await convertHdfToOscalSar(
      hdf(['2026-03-01T03:15:00.123-05:00'])));
    expect(out['assessment-results'].results[0].start).toBe('2026-03-01T08:15:00Z');
  });

  // Real HDF carries zone-less startTimes (InSpec emits them). They must read as
  // UTC, matching Go — never as host-local, which would make output depend on the
  // machine's timezone.
  it('reads a zone-less startTime as UTC, not host-local', async () => {
    const out = JSON.parse(await convertHdfToOscalSar(hdf(['2026-03-01T08:15:00'])));
    expect(out['assessment-results'].results[0].start).toBe('2026-03-01T08:15:00Z');
  });

  it('falls back to the document timestamp when no result carries a startTime', async () => {
    const input = JSON.stringify({
      timestamp: '2026-07-13T09:00:00Z',
      baselines: [{
        name: 'b1',
        requirements: [{
          id: 'AC-1', impact: 0.5,
          descriptions: [{ label: 'default', data: 'd' }],
          tags: { nist: ['AC-1'] },
          results: [{ status: 'passed', codeDesc: 'c' }],
        }],
      }],
    });
    const out = JSON.parse(await convertHdfToOscalSar(input));
    // OSCAL requires start, so something valid must still be emitted.
    expect(out['assessment-results'].results[0].start).toBe('2026-07-13T09:00:00Z');
  });
});

describe('observation.collected is the assessment time', () => {
  it('uses the requirement scan time, not the conversion time', async () => {
    const input = JSON.stringify({
      timestamp: '2026-07-13T09:00:00Z',
      baselines: [{
        name: 'b1',
        requirements: [{
          id: 'AC-1', impact: 0.5,
          descriptions: [{ label: 'default', data: 'd' }],
          tags: { nist: ['AC-1'] },
          results: [
            { status: 'passed', codeDesc: 'c', startTime: '2026-03-01T09:45:00Z' },
            { status: 'failed', codeDesc: 'c', startTime: '2026-03-01T08:15:00Z' },
          ],
        }],
      }],
    });
    const out = JSON.parse(await convertHdfToOscalSar(input));
    const observation = out['assessment-results'].results[0].observations[0];

    expect(observation.collected).toBe('2026-03-01T08:15:00Z');
    expect(observation.collected, 'must not be the conversion time').not.toBe('2026-07-13T09:00:00Z');
  });
});
