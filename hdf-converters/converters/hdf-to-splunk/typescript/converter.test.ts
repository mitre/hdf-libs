import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { convertHdfToSplunk, foldStatus } from './converter.js';
import type { SplunkData } from './types.js';

function convert(input: string): SplunkData {
  return JSON.parse(convertHdfToSplunk(input)) as SplunkData;
}

describe('hdf-to-splunk: shape and envelope', () => {
  it('produces one report, one profile, one control from the minimal fixture', () => {
    const d = convert(results.minimal.read());
    expect(d.reports).toHaveLength(1);
    expect(d.profiles).toHaveLength(1);
    expect(d.controls).toHaveLength(1);
    expect(d.reports[0].meta.subtype).toBe('header');
    expect(d.profiles[0].meta.subtype).toBe('profile');
    expect(d.controls[0].meta.subtype).toBe('control');
  });

  it('shares the same guid across all records in one call', () => {
    const d = convert(results.minimal.read());
    const guid = d.reports[0].meta.guid;
    expect(guid).toBeTruthy();
    for (const p of d.profiles) expect(p.meta.guid).toBe(guid);
    for (const c of d.controls) expect(c.meta.guid).toBe(guid);
  });

  it('produces a fresh guid between calls', () => {
    const a = convert(results.minimal.read());
    const b = convert(results.minimal.read());
    expect(a.reports[0].meta.guid).not.toBe(b.reports[0].meta.guid);
  });

  it('emits hdf_splunk_schema "1.1" on every record', () => {
    const d = convert(results.minimal.read());
    expect(d.reports[0].meta.hdf_splunk_schema).toBe('1.1');
    for (const p of d.profiles) expect(p.meta.hdf_splunk_schema).toBe('1.1');
    for (const c of d.controls) expect(c.meta.hdf_splunk_schema).toBe('1.1');
  });

  it('emits filetype "evaluation" on every record', () => {
    const d = convert(results.minimal.read());
    expect(d.reports[0].meta.filetype).toBe('evaluation');
    for (const p of d.profiles) expect(p.meta.filetype).toBe('evaluation');
    for (const c of d.controls) expect(c.meta.filetype).toBe('evaluation');
  });

  it('uses the documented placeholder filename', () => {
    const d = convert(results.minimal.read());
    expect(d.reports[0].meta.filename).toBe('hdf-results.json');
  });
});

describe('hdf-to-splunk: profile mapping', () => {
  it('copies baseline fields onto the profile record', () => {
    const d = convert(results.minimal.read());
    const p = d.profiles[0];
    expect(p.name).toBe('Minimal Baseline');
    expect(p.version).toBe('1.0.0');
    expect(p.meta.is_baseline).toBe(true);
  });

  it('derives profile_sha256 from integrity when resultsChecksum is absent', () => {
    const d = convert(results.minimal.read());
    expect(d.profiles[0].sha256).toBe('abc123');
    expect(d.profiles[0].meta.profile_sha256).toBe('abc123');
  });
});

describe('hdf-to-splunk: control mapping', () => {
  it('copies requirement fields onto the control record', () => {
    const d = convert(results.minimal.read());
    const c = d.controls[0];
    expect(c.id).toBe('REQ-001');
    expect(c.title).toBe('Test Requirement');
    expect(c.impact).toBeCloseTo(0.7);
  });

  it('links each control to its parent profile via profile_sha256', () => {
    const d = convert(results.minimal.read());
    expect(d.controls[0].meta.profile_sha256).toBe(d.profiles[0].sha256);
  });

  it('flattens descriptions array into a label→data object', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'T',
          requirements: [
            {
              id: 'R',
              title: 't',
              impact: 0,
              tags: {},
              descriptions: [
                { label: 'default', data: 'primary' },
                { label: 'fix', data: 'remediation' },
                { label: 'check', data: 'verify' },
              ],
              results: [{ status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const d = convert(input);
    expect(d.controls[0].descriptions).toEqual({
      default: 'primary',
      fix: 'remediation',
      check: 'verify',
    });
    expect(d.controls[0].desc).toBe('primary');
  });

  it('produces empty desc when no description has label "default"', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'T',
          requirements: [
            {
              id: 'R',
              impact: 0,
              tags: {},
              descriptions: [{ label: 'fix', data: 'only fix' }],
              results: [{ status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });
    const d = convert(input);
    expect(d.controls[0].desc).toBe('');
  });
});

describe('hdf-to-splunk: status fold', () => {
  it('returns notReviewed for empty results (direct)', () => {
    expect(foldStatus([])).toBe('notReviewed');
  });

  const cases: Array<[string, string[], string]> = [
    ['all passed', ['passed', 'passed'], 'passed'],
    ['passed and failed', ['passed', 'failed'], 'failed'],
    ['error trumps failed', ['failed', 'error'], 'error'],
    ['failed trumps notReviewed', ['notReviewed', 'failed'], 'failed'],
    ['only notApplicable', ['notApplicable', 'notApplicable'], 'notApplicable'],
  ];
  for (const [name, statuses, want] of cases) {
    it(`folds ${name}`, () => {
      expect(foldStatus(statuses.map((s) => ({ status: s })))).toBe(want);
    });
  }

  it('exposes the worst status on the control meta', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'T',
          requirements: [
            {
              id: 'R',
              impact: 0,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [
                { status: 'passed', codeDesc: 'a', startTime: '2026-01-01T00:00:00Z' },
                { status: 'failed', codeDesc: 'b', startTime: '2026-01-01T00:00:00Z' },
              ],
            },
          ],
        },
      ],
    });
    const d = convert(input);
    expect(d.controls[0].meta.status).toBe('failed');
  });
});

describe('hdf-to-splunk: is_waived', () => {
  it('is true when requirement.disposition is "waiver"', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'T',
          requirements: [
            {
              id: 'R',
              impact: 0,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' }],
              disposition: 'waiver',
            },
          ],
        },
      ],
    });
    const d = convert(input);
    expect(d.controls[0].meta.is_waived).toBe(true);
  });

  it('is false when no disposition is set', () => {
    const d = convert(results.minimal.read());
    expect(d.controls[0].meta.is_waived).toBe(false);
  });
});

describe('hdf-to-splunk: platform and passthrough', () => {
  it('derives platform.name and platform.release from tool', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'T',
          requirements: [
            {
              id: 'R',
              impact: 0,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
      tool: { name: 'Nessus', version: '10.2' },
    });
    const d = convert(input);
    expect(d.reports[0].platform.name).toBe('Nessus');
    expect(d.reports[0].platform.release).toBe('10.2');
  });

  it('routes extensions into passthrough', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'T',
          requirements: [
            {
              id: 'R',
              impact: 0,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'passed', codeDesc: 'ok', startTime: '2026-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
      extensions: { runner: 'inspec-4.50' },
    });
    const d = convert(input);
    expect(d.reports[0].passthrough).toEqual({ runner: 'inspec-4.50' });
  });
});

describe('hdf-to-splunk: multi-baseline', () => {
  it('produces one profile per baseline and links controls to them', () => {
    const d = convert(results.inspecMultilayered.read());
    expect(d.profiles.length).toBeGreaterThanOrEqual(2);
    expect(d.controls.length).toBeGreaterThan(0);
    const profileShas = new Set(d.profiles.map((p) => p.sha256));
    for (const c of d.controls) {
      expect(profileShas.has(c.meta.profile_sha256)).toBe(true);
    }
  });
});

describe('hdf-to-splunk: error paths', () => {
  it('rejects empty input', () => {
    expect(() => convertHdfToSplunk('')).toThrow();
  });

  it('rejects invalid JSON', () => {
    expect(() => convertHdfToSplunk('not json')).toThrow();
  });

  it('rejects a doc with no baselines', () => {
    expect(() => convertHdfToSplunk('{"baselines": []}')).toThrow();
  });

  it('rejects a doc whose baselines is not an array', () => {
    expect(() => convertHdfToSplunk('{"baselines": "nope"}')).toThrow();
  });
});
