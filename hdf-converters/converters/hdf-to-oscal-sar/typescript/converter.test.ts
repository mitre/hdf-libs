import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { convertHdfToOscalSar } from './converter.js';
import { nistTagToControlId as nistTagToControlID, impactToSeverity } from '../../oscal-to-hdf/typescript/shared.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';
import { loadSchemaValidator, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import { convertOscalSarToHdf } from '../../oscal-to-hdf/typescript/converter-sar.js';

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
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // The package's runtime path must not depend on Node globals: browser
  // bundles have no Buffer, and the code resource is the only base64 emitter.
  it('embeds the code resource without the Node Buffer global', async () => {
    vi.stubGlobal('Buffer', undefined);
    const input = JSON.stringify({
      baselines: [{
        name: 'b',
        requirements: [{ id: 'SV-1', impact: 0.7, tags: { nist: ['AC-2'] }, code: "control 'SV-1' do\n  # \u00e9\nend" }],
      }],
    });
    const doc = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'];
    expect(doc['back-matter'].resources[0].base64.value).toBe('Y29udHJvbCAnU1YtMScgZG8KICAjIMOpCmVuZA==');
  });

  it('should reject empty input', async () => {
    await expect(convertHdfToOscalSar('')).rejects.toThrow('empty input');
  });

  it('should reject invalid JSON', async () => {
    await expect(convertHdfToOscalSar('{invalid')).rejects.toThrow('Invalid JSON');
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

  it('should map code, cci, classification, and refs onto the finding', async () => {
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
    expect(obs['relevant-evidence'].slice(0, 2).map((e: { href: string }) => e.href)).toEqual([
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

  it('maps a governing notApplicable waiver to not-satisfied / not-applicable', async () => {
    // A governing waiver drives the finding state; a bare stored
    // effectiveStatus would be ignored (output cache).
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.5, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'passed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
          statusOverrides: [{
            type: 'waiver', status: 'notApplicable', reason: 'scoped out',
            appliedBy: { type: 'simple', identifier: 'jdoe' },
            appliedAt: '2026-01-02T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
          }],
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

  // FedRAMP owns the impact facet, and its rev5 SAR template and extensions
  // registry name the system https://fedramp.gov, so that URI is kept deliberately.
  it("names the impact facet in FedRAMP's system", async () => {
    const input = JSON.stringify({
      baselines: [{
        name: 'b', requirements: [{
          id: 'AC-1', impact: 0.7, tags: { nist: ['AC-1'] },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
        }],
      }],
    });
    const result = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0];
    expect(result.risks[0].characterizations[0].facets).toStrictEqual([{ name: 'impact', system: 'https://fedramp.gov', value: 'high' }]);
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
    const output = await convertHdfToOscalSar(input);
    const rems = JSON.parse(output)['assessment-results'].results[0].risks[0].remediations;
    expect(rems[0].lifecycle).toBe('recommendation');
    expect(rems[0].description).toBe('apply the patch');

    const back = JSON.parse(await convertOscalSarToHdf(output));
    expect(hdfDescription(back.baselines[0].requirements[0], 'fix')).toBe('apply the patch');
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

  // This test previously asserted that an empty baselines array converted
  // successfully to a document with no results. That was the defect: OSCAL
  // Assessment Results puts minItems 1 on results, so the emitted document
  // failed the schema the converter declares conformance to, while resolving
  // successfully.
  it('rejects an empty baselines array', async () => {
    const input = JSON.stringify({ baselines: [] });
    await expect(convertHdfToOscalSar(input)).rejects.toThrow(/at least one result/);
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

    // risks is omitted rather than emitted empty, matching Go's omitempty:
    // OSCAL puts minItems 1 on it, so [] would be invalid where absence is fine.
    expect(doc['assessment-results'].results[0].risks).toBeUndefined();
    expect(doc['assessment-results'].results[0].findings[0]['related-risks']).toBeUndefined();
  });
});

interface OscalProp { name: string; value: string; ns?: string; remarks?: string }
interface OscalEvidence { href?: string; description: string; props?: OscalProp[]; remarks?: string }
interface OscalRemediation { lifecycle: string; description: string; props?: OscalProp[] }

const HDF_NS = 'https://mitre.github.io/hdf-libs/ns/oscal';
const MULTILINE_RATIONALE = 'Without session locks, an unattended session\n  can be used by anyone.\n\nThis matters for shared terminals.\n';
const MULTILINE_CHECK = '\n  Verify the setting:\n\n  $ sudo grep lock /etc/dconf/db/local.d/*\n\n  If it is missing, this is a finding.\n';
const MULTILINE_FIX = 'Configure the lock:\n\n  $ sudo dconf update\n';

function proseRequirementInput(impact: number): string {
  return JSON.stringify({
    baselines: [{
      name: 'b', requirements: [{
        id: 'AC-11', impact, tags: { nist: ['AC-11'] },
        descriptions: [
          { label: 'default', data: 'd' },
          { label: 'rationale', data: MULTILINE_RATIONALE },
          { label: 'check', data: MULTILINE_CHECK },
          { label: 'fix', data: MULTILINE_FIX },
        ],
        results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
      }],
    }],
  });
}

const sarResult = async (input: string) => JSON.parse(await convertHdfToOscalSar(input))['assessment-results'];

const propsNamed = (props: OscalProp[] | undefined, name: string): OscalProp[] =>
  (props ?? []).filter((p) => p.name === name);

const labelledEvidence = (obs: { 'relevant-evidence'?: OscalEvidence[] }, label: string): OscalEvidence[] =>
  (obs['relevant-evidence'] ?? []).filter((e) =>
    (e.props ?? []).some((p) => p.name === 'description-label' && p.ns === HDF_NS && p.value === label));

const hdfDescription = (req: { descriptions?: Array<{ label: string; data: string }> }, label: string): string | undefined =>
  req.descriptions?.find((d) => d.label === label)?.data;

describe('prose carriage', () => {
  it('carries rationale in full as finding.target.description', async () => {
    const f = (await sarResult(proseRequirementInput(0.5))).results[0].findings[0];
    expect(f.target.description).toBe(MULTILINE_RATIONALE);
    expect(propsNamed(f.props, 'rationale')).toEqual([]);
  });

  it('leaves target.description absent without a rationale', async () => {
    const f = (await sarResult(minimalHDFResults('failed'))).results[0].findings[0];
    expect(f.target).not.toHaveProperty('description');
  });

  it('carries check as labelled relevant-evidence on the related observation', async () => {
    const result = (await sarResult(proseRequirementInput(0.5))).results[0];
    const f = result.findings[0];
    expect(propsNamed(f.props, 'check')).toEqual([]);
    expect(result.observations).toHaveLength(1);
    const obs = result.observations[0];
    expect(f['related-observations']).toEqual([{ 'observation-uuid': obs.uuid }]);

    const checks = labelledEvidence(obs, 'check');
    expect(checks).toEqual([{
      description: 'Verify the setting:',
      props: [{ name: 'description-label', ns: HDF_NS, value: 'check' }],
      remarks: MULTILINE_CHECK,
    }]);
  });

  it('truncates a long check preview but keeps the full text in remarks', async () => {
    const long = 'abcdefghij'.repeat(20);
    const input = JSON.stringify({ baselines: [{ name: 'b', requirements: [{
      id: 'AC-1', impact: 0.5, descriptions: [{ label: 'check', data: long }],
      results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
    }] }] });
    const checks = labelledEvidence((await sarResult(input)).results[0].observations[0], 'check');
    expect(checks).toHaveLength(1);
    expect(checks[0]!.description).toBe(`${long.slice(0, 117)}...`);
    expect(checks[0]!.remarks).toBe(long);
  });

  it('omits a whitespace-only check', async () => {
    const input = JSON.stringify({ baselines: [{ name: 'b', requirements: [{
      id: 'AC-1', impact: 0.5, descriptions: [{ label: 'check', data: '  \n ' }],
      results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
    }] }] });
    expect((await sarResult(input)).results[0].observations[0]).not.toHaveProperty('relevant-evidence');
  });

  it('carries an impact-0 fix as labelled relevant-evidence', async () => {
    const result = (await sarResult(proseRequirementInput(0))).results[0];
    expect(propsNamed(result.findings[0].props, 'fix')).toEqual([]);
    expect(result).not.toHaveProperty('risks');
    expect(labelledEvidence(result.observations[0], 'fix')).toEqual([{
      description: 'Configure the lock:',
      props: [{ name: 'description-label', ns: HDF_NS, value: 'fix' }],
      remarks: MULTILINE_FIX,
    }]);
  });

  it('labels the impact > 0 fix remediation', async () => {
    const result = (await sarResult(proseRequirementInput(0.5))).results[0];
    expect(propsNamed(result.findings[0].props, 'fix')).toEqual([]);
    expect(labelledEvidence(result.observations[0], 'fix')).toEqual([]);
    const rems = result.risks[0].remediations as OscalRemediation[];
    expect(rems).toHaveLength(1);
    expect(rems[0]!.lifecycle).toBe('recommendation');
    expect(rems[0]!.description).toBe(MULTILINE_FIX);
    expect(rems[0]!.props).toEqual([{ name: 'description-label', ns: HDF_NS, value: 'fix' }]);
  });

  it('leaves the accepted remediation unlabelled', async () => {
    const input = JSON.stringify({ baselines: [{ name: 'b', requirements: [{
      id: 'AC-1', impact: 0.7, descriptions: [{ label: 'fix', data: 'patch' }],
      results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
      disposition: 'falsePositive',
      statusOverrides: [{ type: 'falsePositive', status: 'passed', reason: 'r',
        appliedBy: { type: 'simple', identifier: 'jdoe' },
        appliedAt: '2026-01-02T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z' }],
    }] }] });
    const rems = (await sarResult(input)).results[0].risks[0].remediations as OscalRemediation[];
    expect(rems).toHaveLength(2);
    expect(rems[1]!.lifecycle).toBe('accepted');
    expect(rems[1]).not.toHaveProperty('props');
  });

  it('types the code resource as NIST evidence and keeps the code link', async () => {
    const input = JSON.stringify({ baselines: [{ name: 'b', requirements: [{
      id: 'AC-1', impact: 0.5, code: "control 'AC-1' do end",
      results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
    }] }] });
    const doc = await sarResult(input);
    const resource = doc['back-matter'].resources[0];
    expect(resource.props).toEqual([{ name: 'type', value: 'evidence' }]);
    expect(doc.results[0].findings[0].links).toEqual([{ href: `#${resource.uuid}`, rel: 'code' }]);
  });

  it('appends labelled prose after the pre-existing evidence entries', async () => {
    const input = JSON.stringify({ baselines: [{ name: 'b', requirements: [{
      id: 'AC-1', impact: 0,
      descriptions: [{ label: 'check', data: 'check it' }, { label: 'fix', data: 'fix it' }],
      refs: [{ url: 'https://example.gov/evidence' }],
      evidence: [{ type: 'log', data: 'saw the thing', description: 'log excerpt' }],
      sourceLocation: { ref: 'controls/ac-1.rb', line: 42 },
      results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
    }] }] });
    expect((await sarResult(input)).results[0].observations[0]['relevant-evidence']).toEqual([
      { href: 'https://example.gov/evidence', description: '' },
      { description: 'log excerpt' },
      { description: 'Source location: controls/ac-1.rb:42' },
      { description: 'check it', props: [{ name: 'description-label', ns: HDF_NS, value: 'check' }], remarks: 'check it' },
      { description: 'fix it', props: [{ name: 'description-label', ns: HDF_NS, value: 'fix' }], remarks: 'fix it' },
    ]);
  });

  describe('warns when prose has no observation to hold it', () => {
    const req = (impact: number, descriptions: Array<{ label: string; data: string }>, withResults = false) =>
      JSON.stringify({ baselines: [{ name: 'b', requirements: [{
        id: 'SV-230221', impact, descriptions,
        ...(withResults ? { results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }] } : {}),
      }] }] });
    const check = { label: 'check', data: 'check it' };
    const fix = { label: 'fix', data: 'fix it' };

    const warnings = async (input: string): Promise<string[]> => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      await convertHdfToOscalSar(input);
      const calls = warn.mock.calls.map((c) => String(c[0]));
      warn.mockRestore();
      return calls;
    };

    it.each([
      ['check only', req(0.5, [check, fix]),
        'WARNING: hdf-to-oscal-sar: requirement "SV-230221" has no results, so no observation holds its check description; it was not carried'],
      ['impact-0 fix only', req(0, [fix]),
        'WARNING: hdf-to-oscal-sar: requirement "SV-230221" has no results, so no observation holds its fix description; it was not carried'],
      ['check and impact-0 fix', req(0, [check, fix]),
        'WARNING: hdf-to-oscal-sar: requirement "SV-230221" has no results, so no observation holds its check and fix descriptions; they were not carried'],
    ])('%s', async (_name, input, want) => {
      expect(await warnings(input)).toEqual([want]);
    });

    it('quotes the requirement id with escapes, matching Go', async () => {
      const input = JSON.stringify({ baselines: [{ name: 'b', requirements: [{ id: 'AC-1 "x"', impact: 0.5, descriptions: [check] }] }] });
      expect((await warnings(input))[0]).toContain('requirement "AC-1 \\"x\\"" has no results');
    });

    it.each([
      ['with results', req(0, [check, fix], true)],
      ['no prose', req(0, [{ label: 'default', data: 'd' }])],
      ['impact > 0 fix only', req(0.5, [fix])],
      ['whitespace-only check', req(0, [{ label: 'check', data: '  \n ' }])],
    ])('stays silent: %s', async (_name, input) => {
      expect(await warnings(input)).toEqual([]);
    });
  });

  it.each([0, 0.5])('round-trips rationale, check and fix exactly (impact %s)', async (impact) => {
    const back = JSON.parse(await convertOscalSarToHdf(await convertHdfToOscalSar(proseRequirementInput(impact))));
    const req = back.baselines[0].requirements[0];
    expect(hdfDescription(req, 'rationale')).toBe(MULTILINE_RATIONALE);
    expect(hdfDescription(req, 'check')).toBe(MULTILINE_CHECK);
    expect(hdfDescription(req, 'fix')).toBe(MULTILINE_FIX);
    expect(hdfDescription(req, 'remediation')).toBeUndefined();
    expect(hdfDescription(req, 'evidence')).toBeUndefined();
  });
});

describe('requirement ids round-trip through OSCAL SAR', () => {
  // A one-baseline HDF Results document whose requirements carry the given ids,
  // each with one result of the given status.
  const hdfRequirementsDoc = (ids: string[], statuses: string[]): string =>
    JSON.stringify({
      baselines: [{
        name: 'b',
        requirements: ids.map((id, i) => ({
          id, impact: 0.5, tags: {},
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: statuses[i], codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
        })),
      }],
    });
  const shapes = (baseline: { requirements: Array<{ id: string; results: unknown[] }> }) =>
    baseline.requirements.map((r) => ({ id: r.id, results: r.results.length }));

  it('keeps distinct scanner rule ids apart, byte-exact', async () => {
    const ids = [
      'SV-230221r858734_rule',
      'SV-230221r991589_rule',
      'xccdf_org.ssgproject.content_rule_accounts_tmout',
      'xccdf_org.ssgproject.content_rule_audit_rules_login_events',
    ];
    const statuses = ['failed', 'passed', 'failed', 'passed'];
    const back = JSON.parse(await convertOscalSarToHdf(await convertHdfToOscalSar(hdfRequirementsDoc(ids, statuses))));
    expect(back.baselines).toHaveLength(1);
    const reqs = back.baselines[0].requirements as Array<{ id: string; results: Array<{ status: string }> }>;
    expect(reqs.map((r) => r.id)).toEqual(ids);
    expect(reqs.map((r) => r.results.map((res) => res.status))).toEqual(statuses.map((st) => [st]));
  });

  it('returns NIST, mixed-case, non-NIST and non-StringDatatype ids exactly', async () => {
    const ids = [
      'AC-2 (3)',
      'ac-2(4)',
      'AC-8 c 1',
      'CM-2 (1)',
      'AC-1',
      'MixedCase_Rule-7',
      'sv-230221r858734_rule',
      'pkg:npm/lodash@4.17.20',
      '1.1.1.1',
      '  leading and trailing  ',
      'line one\nline two',
    ];
    const back = JSON.parse(await convertOscalSarToHdf(await convertHdfToOscalSar(hdfRequirementsDoc(ids, ids.map(() => 'passed')))));
    expect(back.baselines).toHaveLength(1);
    expect(shapes(back.baselines[0])).toEqual(ids.map((id) => ({ id, results: 1 })));
  });

  it('keeps requirement ids and result counts through SAR -> HDF -> SAR -> HDF', async () => {
    const sar = readFileSync(join(__dirname, '..', '..', 'oscal-to-hdf', 'fixtures', 'input', 'sar-fedramp.json'), 'utf-8');
    const hdf = await convertOscalSarToHdf(sar);
    const first = JSON.parse(hdf);
    expect(first.baselines).toHaveLength(1);
    expect(shapes(first.baselines[0])).toEqual([
      { id: 'AC-1', results: 3 }, { id: 'AU-1', results: 1 }, { id: 'RA-5', results: 1 },
      { id: 'CM-2 (1)', results: 1 }, { id: 'AT-2', results: 1 }, { id: 'CA-8 (1)', results: 1 },
    ]);

    const exported = JSON.parse(await convertHdfToOscalSar(hdf))['assessment-results'];
    expect(exported.results).toHaveLength(1);
    expect(exported.results[0].findings).toHaveLength(6);

    const back = JSON.parse(await convertOscalSarToHdf(JSON.stringify({ 'assessment-results': exported })));
    expect(back.baselines).toHaveLength(1);
    expect(shapes(back.baselines[0])).toEqual([
      { id: 'AC-1', results: 1 }, { id: 'AU-1', results: 1 }, { id: 'RA-5', results: 1 },
      { id: 'CM-2 (1)', results: 1 }, { id: 'AT-2', results: 1 }, { id: 'CA-8 (1)', results: 1 },
    ]);
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

// A stale stored effectiveStatus (no overrides) is never read: the finding
// state reflects the ladder's answer (the failing raw roll-up).
describe('stale stored effectiveStatus is ignored', () => {
  it('emits not-satisfied from the raw roll-up', async () => {
    const input = JSON.stringify({
        baselines: [{ name: 'b', requirements: [{
          id: 'SV-9', impact: 0.7, title: 't', tags: {},
          descriptions: [{ label: 'default', data: 'd' }],
          effectiveStatus: 'passed',
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
        }] }],
      });
    const status = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0].findings[0].target.status;
    expect(status.state).toBe('not-satisfied');
    expect(status.reason).toBeUndefined();
  });
});

// Mirrors the Go TestConvertHDFToOSCALSAR_NISTRequirementIDControlReferences.
describe('NIST requirement id control references', () => {
  const ids = [
    'ac-2 (3)', 'AC-2 (3)', 'Ac-2(3)', 'AC-2 (3) (a)',
    'AC-8 c 1', 'AC-8 c 2', 'AC-08 c 01',
    'Si-2', 'SC-7 a', 'SC-7',
    'SV-257778',
  ];
  const input = JSON.stringify({
    baselines: [{
      name: 'b',
      requirements: ids.map((id) => ({
        id,
        impact: 0,
        tags: {},
        descriptions: [{ label: 'default', data: 'd' }],
        results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
      })),
    }],
  });

  it('names the control in reviewed-controls and the control or statement in each finding target', async () => {
    const res = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0];
    expect(res['reviewed-controls']['control-selections']).toHaveLength(1);
    expect(res['reviewed-controls']['control-selections'][0]['include-controls']).toEqual([
      { 'control-id': 'ac-2.3' },
      { 'control-id': 'ac-8', 'statement-ids': ['ac-8_smt.c.1', 'ac-8_smt.c.2'] },
      { 'control-id': 'si-2' },
      { 'control-id': 'sc-7' },
      { 'control-id': 'sv-257778' },
    ]);
    expect(res.findings.map((f: { target: { type: string; 'target-id': string } }) => [f.target.type, f.target['target-id']])).toEqual([
      ['objective-id', 'ac-2.3'], ['objective-id', 'ac-2.3'], ['objective-id', 'ac-2.3'], ['statement-id', 'ac-2.3_smt.a'],
      ['statement-id', 'ac-8_smt.c.1'], ['statement-id', 'ac-8_smt.c.2'], ['statement-id', 'ac-8_smt.c.1'],
      ['objective-id', 'si-2'], ['statement-id', 'sc-7_smt.a'], ['objective-id', 'sc-7'],
      ['objective-id', 'sv-257778'],
    ]);
  });

  it.each(['oscal_assessment-results_schema-v1.1.2.json', 'oscal_assessment-results_schema-v1.2.3.json'])(
    'validates against %s',
    async (file) => {
      const validate = loadSchemaValidator(join(__dirname, '..', 'schemas', file));
      assertSchemaValid(validate, file, JSON.parse(await convertHdfToOscalSar(input)));
    },
  );
});
