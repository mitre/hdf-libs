import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
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
  return JSON.stringify({
    baselines: [
      {
        name: 'test-baseline',
        requirements: [
          {
            id: 'AC-1',
            impact: 0.5,
            tags: { nist: ['AC-1'] },
            descriptions: [
              { label: 'default', data: 'Test requirement description' },
            ],
            results: [
              {
                status,
                codeDesc: 'Test code description',
                startTime: '2026-01-01T00:00:00Z',
              },
            ],
          },
        ],
      },
    ],
  });
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
    const finding = JSON.parse(await convertHdfToOscalSar(input))['assessment-results'].results[0].findings[0];
    const propVal = (name: string) => finding.props.find((p: { name: string; value: string }) => p.name === name)?.value;
    expect(propVal('cci')).toBe('CCI-000012');
    expect(propVal('code')).toContain("control 'SV-1'");
    expect(propVal('check')).toBe('check text');
    expect(propVal('fix')).toBe('fix text');
    expect(propVal('rationale')).toBe('rationale text');
    expect(propVal('control-type')).toBe('technical');
    expect(propVal('verification-method')).toBe('automated');
    expect(propVal('applicability')).toBe('required');
    expect(propVal('reference')).toBe('Handbook 3');
    expect(finding.links.map((l: { href: string }) => l.href)).toEqual(['https://example.gov/a', 'https://example.gov/b']);
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
    const input = JSON.stringify({
      baselines: [
        {
          name: 'test',
          requirements: [
            {
              id: 'AC-2 (3)',
              impact: 0.7,
              tags: { nist: ['AC-2 (3)'] },
              descriptions: [{ label: 'default', data: 'Enhanced control' }],
              results: [
                { status: 'passed', codeDesc: 'test', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
          ],
        },
      ],
    });

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
      baselines: [
        {
          name: 'test',
          requirements: [
            {
              id: 'AC-1',
              impact: 0.5,
              tags: { nist: ['AC-1'] },
              descriptions: [{ label: 'default', data: 'desc' }],
              results: [
                { status: 'passed', codeDesc: 'test', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
          ],
        },
      ],
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
    const input = JSON.stringify({
      baselines: [
        {
          name: 'multi-test',
          requirements: [
            {
              id: 'AC-1',
              impact: 0.5,
              tags: { nist: ['AC-1'] },
              descriptions: [{ label: 'default', data: 'first' }],
              results: [
                { status: 'passed', codeDesc: 'test1', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
            {
              id: 'AC-2',
              impact: 0.7,
              tags: { nist: ['AC-2'] },
              descriptions: [{ label: 'default', data: 'second' }],
              results: [
                { status: 'failed', codeDesc: 'test2', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
          ],
        },
      ],
    });

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results'].results).toHaveLength(1);
    expect(doc['assessment-results'].results[0].findings).toHaveLength(2);
    expect(doc['assessment-results'].results[0].observations).toHaveLength(2);
    expect(doc['assessment-results'].results[0].risks).toHaveLength(2);
  });

  it('should use baseline title when provided', async () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'test',
          title: 'My Custom Baseline Title',
          requirements: [
            {
              id: 'AC-1',
              impact: 0.5,
              tags: { nist: ['AC-1'] },
              descriptions: [{ label: 'default', data: 'desc' }],
              results: [
                { status: 'passed', codeDesc: 'test', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
          ],
        },
      ],
    });

    const output = await convertHdfToOscalSar(input);
    const doc = JSON.parse(output);

    expect(doc['assessment-results'].results[0].title).toBe('My Custom Baseline Title');
  });

  it('should not produce a risk for zero impact', async () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'test',
          requirements: [
            {
              id: 'AC-1',
              impact: 0.0,
              tags: { nist: ['AC-1'] },
              descriptions: [{ label: 'default', data: 'desc' }],
              results: [
                { status: 'passed', codeDesc: 'test', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
          ],
        },
      ],
    });

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
