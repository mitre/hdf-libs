import { describe, it, expect } from 'vitest';
import { convertHdfToOscalSar, aggregateStatus } from './converter.js';
import { nistTagToControlId as nistTagToControlID, impactToSeverity } from '../../oscal-to-hdf/typescript/shared.js';

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
