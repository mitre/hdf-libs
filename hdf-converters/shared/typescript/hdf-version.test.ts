import { describe, it, expect } from 'vitest';
import { transformHDF, detectHDFVersion } from './hdf-version.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', '..', 'converters', 'legacyhdf-to-hdf', 'fixtures', 'input');

function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf-8');
}

describe('transformHDF', () => {
  it('upgrades v1 to v2', () => {
    const v1 = readFixture('minimal.json');
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed).toHaveProperty('baselines');
    expect(parsed).toHaveProperty('components');
    expect(parsed).not.toHaveProperty('profiles');
    expect(parsed).not.toHaveProperty('platform');
  });

  it('downgrades v2 to v1', () => {
    const v1 = readFixture('minimal.json');
    const v2 = transformHDF(v1, '1', '2');
    const v1Again = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1Again);
    expect(parsed).toHaveProperty('profiles');
    expect(parsed).toHaveProperty('platform');
    expect(parsed).not.toHaveProperty('baselines');
    expect(parsed).not.toHaveProperty('components');
  });

  it('returns input unchanged for same version', () => {
    const v1 = readFixture('minimal.json');
    const output = transformHDF(v1, '1', '1');
    expect(output).toBe(v1);
  });

  it('throws for unknown version pair', () => {
    expect(() => transformHDF('{}', '3', '2')).toThrow('No HDF transform');
  });

  it('round-trip preserves profile count', () => {
    const v1 = readFixture('minimal.json');
    const v2 = transformHDF(v1, '1', '2');
    const v1Again = transformHDF(v2, '2', '1');
    const original = JSON.parse(v1);
    const roundTripped = JSON.parse(v1Again);
    expect(roundTripped.profiles.length).toBe(original.profiles.length);
  });
});

describe('detectHDFVersion', () => {
  it('detects v1', () => {
    expect(detectHDFVersion('{"profiles":[],"platform":{"name":"test"}}')).toBe('1');
  });

  it('detects v2 with components', () => {
    expect(detectHDFVersion('{"baselines":[],"components":[]}')).toBe('2');
  });

  it('throws for ambiguous input', () => {
    expect(() => detectHDFVersion('{"version":"1.0"}')).toThrow('Cannot determine HDF version');
  });

  it('throws for invalid JSON', () => {
    expect(() => detectHDFVersion('not json')).toThrow();
  });
});

describe('transformHDF upgrade edge cases', () => {
  it('handles v1 with no platform', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'test',
        controls: [{
          id: 'ctrl-1',
          impact: 0.5,
          results: [{ status: 'passed', code_desc: 'ok', start_time: '2024-01-01T00:00:00Z' }],
        }],
      }],
      statistics: { duration: 1 },
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.components).toEqual([]);
    expect(parsed.baselines).toHaveLength(1);
  });

  it('handles v1 platform without release', () => {
    const v1 = JSON.stringify({
      platform: { name: 'test-host' },
      profiles: [],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.components[0].name).toBe('test-host');
    expect(parsed.components[0]).not.toHaveProperty('osVersion');
  });

  it('handles v1 with no profiles', () => {
    const v1 = JSON.stringify({ platform: { name: 'x', release: '1.0' } });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.baselines).toEqual([]);
    expect(parsed.statistics).toEqual({});
  });

  it('handles v1 control with no descriptions and no desc', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{ id: 'c1', impact: 0.7 }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const req = parsed.baselines[0].requirements[0];
    expect(req.descriptions).toEqual([{ label: 'default', data: '' }]);
  });

  it('handles v1 control with desc but no descriptions array', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{ id: 'c1', impact: 0.7, desc: 'My description' }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const req = parsed.baselines[0].requirements[0];
    expect(req.descriptions).toEqual([{ label: 'default', data: 'My description' }]);
  });

  it('handles v1 control with no title', () => {
    const v1 = JSON.stringify({
      profiles: [{ name: 'p', controls: [{ id: 'c1', impact: 0.5 }] }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.baselines[0].requirements[0]).not.toHaveProperty('title');
  });

  it('handles v1 control with no code or source_location', () => {
    const v1 = JSON.stringify({
      profiles: [{ name: 'p', controls: [{ id: 'c1', impact: 0.5 }] }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const req = parsed.baselines[0].requirements[0];
    expect(req).not.toHaveProperty('code');
    expect(req).not.toHaveProperty('sourceLocation');
  });

  it('handles v1 control with source_location having only ref', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{ id: 'c1', impact: 0.5, source_location: { ref: 'test.rb' } }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.baselines[0].requirements[0].sourceLocation).toEqual({ ref: 'test.rb' });
  });

  it('handles v1 control with source_location having only line', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{ id: 'c1', impact: 0.5, source_location: { line: 42 } }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.baselines[0].requirements[0].sourceLocation).toEqual({ line: 42 });
  });

  it('maps all v1 status values correctly', () => {
    const statuses = ['passed', 'failed', 'error', 'not_applicable', 'not_reviewed', 'skipped', 'custom_status'];
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: statuses.map((s, i) => ({
          id: `c${i}`,
          impact: 0.5,
          results: [{ status: s, code_desc: 'test', start_time: '2024-01-01T00:00:00Z' }],
        })),
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const resultStatuses = parsed.baselines[0].requirements.map(
      (r: Record<string, unknown>) => (r.results as Array<Record<string, unknown>>)[0].status,
    );
    expect(resultStatuses).toEqual([
      'passed', 'failed', 'error', 'notApplicable', 'notReviewed', 'notReviewed', 'custom_status',
    ]);
  });

  it('handles v1 result with message, exception, and backtrace', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{
          id: 'c1',
          impact: 0.5,
          results: [{
            status: 'failed',
            code_desc: 'should work',
            start_time: '2024-01-01T00:00:00Z',
            message: 'expected true got false',
            exception: 'AssertionError',
            backtrace: ['line1', 'line2'],
          }],
        }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const result = parsed.baselines[0].requirements[0].results[0];
    expect(result.message).toBe('expected true got false');
    expect(result.exception).toBe('AssertionError');
    expect(result.backtrace).toEqual(['line1', 'line2']);
  });

  it('handles v1 result with no code_desc or start_time', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{
          id: 'c1',
          impact: 0.5,
          results: [{ status: 'passed' }],
        }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const result = parsed.baselines[0].requirements[0].results[0];
    expect(result.codeDesc).toBe('');
    expect(result.startTime).toBeTruthy(); // defaults to current time
  });

  it('handles v1 result with empty backtrace', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        controls: [{
          id: 'c1',
          impact: 0.5,
          results: [{ status: 'passed', backtrace: [] }],
        }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const result = parsed.baselines[0].requirements[0].results[0];
    expect(result).not.toHaveProperty('backtrace');
  });

  it('handles profile with all optional metadata fields', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        title: 'My Title',
        version: '2.0',
        maintainer: 'MITRE',
        summary: 'A summary',
        license: 'Apache-2.0',
        copyright: 'MITRE 2024',
        copyright_email: 'test@mitre.org',
        groups: [{ id: 'grp1', title: 'Group 1', controls: ['c1'] }],
        controls: [],
        depends: [{ name: 'dep1' }],
        supports: [{ platform: 'linux' }],
        attributes: [{ name: 'attr1', default: 'val1' }],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    const bl = parsed.baselines[0];
    expect(bl.title).toBe('My Title');
    expect(bl.version).toBe('2.0');
    expect(bl.maintainer).toBe('MITRE');
    expect(bl.summary).toBe('A summary');
    expect(bl.license).toBe('Apache-2.0');
    expect(bl.copyright).toBe('MITRE 2024');
    expect(bl.copyrightEmail).toBe('test@mitre.org');
    expect(bl.groups).toEqual([{ id: 'grp1', title: 'Group 1', requirements: ['c1'] }]);
    expect(bl.depends).toEqual([{ name: 'dep1' }]);
    expect(bl.supports).toEqual([{ platform: 'linux' }]);
    expect(bl.inputs).toEqual([{ name: 'attr1', default: 'val1' }]);
  });

  it('handles group with no title', () => {
    const v1 = JSON.stringify({
      profiles: [{
        name: 'p',
        groups: [{ id: 'grp1' }],
        controls: [],
      }],
    });
    const v2 = transformHDF(v1, '1', '2');
    const parsed = JSON.parse(v2);
    expect(parsed.baselines[0].groups[0]).toEqual({ id: 'grp1', requirements: [] });
    expect(parsed.baselines[0].groups[0]).not.toHaveProperty('title');
  });
});

describe('transformHDF downgrade edge cases', () => {
  it('handles v2 with no components', () => {
    const v2 = JSON.stringify({
      baselines: [],
      components: [],
      statistics: {},
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    expect(parsed.platform.name).toBe('');
  });

  it('handles v2 component with osVersion and name', () => {
    const v2 = JSON.stringify({
      baselines: [],
      components: [{ name: 'my-host', type: 'host', osVersion: '22.04' }],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    expect(parsed.platform.name).toBe('my-host');
    expect(parsed.platform.release).toBe('22.04');
    expect(parsed.platform.target_id).toBe('my-host');
  });

  it('handles v2 component with no osVersion', () => {
    const v2 = JSON.stringify({
      baselines: [],
      components: [{ name: 'my-host' }],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    expect(parsed.platform.name).toBe('my-host');
    expect(parsed.platform).not.toHaveProperty('release');
  });

  it('handles v2 component with no name', () => {
    const v2 = JSON.stringify({
      baselines: [],
      components: [{ type: 'host' }],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    expect(parsed.platform.name).toBe('');
    expect(parsed.platform).not.toHaveProperty('target_id');
  });

  it('handles v2 baseline with optional fields', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        version: '1.0',
        title: 'Baseline',
        maintainer: 'MITRE',
        summary: 'Sum',
        license: 'MIT',
        copyright: 'MITRE',
        copyrightEmail: 'test@test.com',
        groups: [{ id: 'g1', title: 'Group', requirements: ['r1'] }],
        requirements: [],
        depends: [{ name: 'dep' }],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const prof = parsed.profiles[0];
    expect(prof.name).toBe('bl');
    expect(prof.version).toBe('1.0');
    expect(prof.title).toBe('Baseline');
    expect(prof.maintainer).toBe('MITRE');
    expect(prof.summary).toBe('Sum');
    expect(prof.license).toBe('MIT');
    expect(prof.copyright).toBe('MITRE');
    expect(prof.copyright_email).toBe('test@test.com');
    expect(prof.groups[0].controls).toEqual(['r1']);
  });

  it('handles v2 baseline with no optional fields', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const prof = parsed.profiles[0];
    expect(prof.name).toBe('bl');
    expect(prof).not.toHaveProperty('version');
    expect(prof).not.toHaveProperty('title');
  });

  it('handles v2 requirement with all status types in downgrade', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [
          {
            id: 'r1',
            impact: 0.5,
            descriptions: [{ label: 'default', data: 'desc' }],
            results: [
              { status: 'passed', codeDesc: 'ok', startTime: '2024-01-01T00:00:00Z' },
              { status: 'failed', codeDesc: 'bad', startTime: '2024-01-01T00:00:00Z' },
              { status: 'error', codeDesc: 'err', startTime: '2024-01-01T00:00:00Z' },
              { status: 'notApplicable', codeDesc: 'na', startTime: '2024-01-01T00:00:00Z' },
              { status: 'notReviewed', codeDesc: 'nr', startTime: '2024-01-01T00:00:00Z' },
              { status: 'custom', codeDesc: 'cust', startTime: '2024-01-01T00:00:00Z' },
            ],
          },
        ],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const ctrl = parsed.profiles[0].controls[0];
    const statuses = ctrl.results.map((r: Record<string, unknown>) => r.status);
    expect(statuses).toEqual(['passed', 'failed', 'error', 'not_applicable', 'not_reviewed', 'custom']);
  });

  it('handles v2 requirement with sourceLocation in downgrade', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [{
          id: 'r1',
          title: 'Req 1',
          impact: 0.5,
          code: 'control "r1" do end',
          sourceLocation: { ref: 'test.rb', line: 10 },
          descriptions: [{ label: 'default', data: 'desc' }],
          results: [],
        }],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const ctrl = parsed.profiles[0].controls[0];
    expect(ctrl.source_location).toEqual({ ref: 'test.rb', line: 10 });
    expect(ctrl.code).toBe('control "r1" do end');
    expect(ctrl.desc).toBe('desc');
  });

  it('handles v2 requirement with no desc in descriptions', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [{
          id: 'r1',
          impact: 0.5,
          descriptions: [{ label: 'rationale', data: 'why' }],
          results: [],
        }],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const ctrl = parsed.profiles[0].controls[0];
    expect(ctrl).not.toHaveProperty('desc');
  });

  it('handles v2 result with message, exception, backtrace', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [{
          id: 'r1',
          impact: 0.5,
          descriptions: [],
          results: [{
            status: 'failed',
            codeDesc: 'test',
            startTime: '2024-01-01T00:00:00Z',
            runTime: 0.5,
            message: 'msg',
            exception: 'exc',
            backtrace: ['a', 'b'],
          }],
        }],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const result = parsed.profiles[0].controls[0].results[0];
    expect(result.run_time).toBe(0.5);
    expect(result.message).toBe('msg');
    expect(result.exception).toBe('exc');
    expect(result.backtrace).toEqual(['a', 'b']);
  });

  it('handles v2 result with no startTime', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [{
          id: 'r1',
          impact: 0.5,
          descriptions: [],
          results: [{ status: 'passed', codeDesc: 'ok' }],
        }],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    const result = parsed.profiles[0].controls[0].results[0];
    expect(result).not.toHaveProperty('start_time');
  });

  it('handles v2 group with no title in downgrade', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        groups: [{ id: 'g1', requirements: ['r1'] }],
        requirements: [],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    expect(parsed.profiles[0].groups[0]).toEqual({ id: 'g1', controls: ['r1'] });
    expect(parsed.profiles[0].groups[0]).not.toHaveProperty('title');
  });

  it('handles sourceLocation with ref but no line in downgrade', () => {
    const v2 = JSON.stringify({
      baselines: [{
        name: 'bl',
        requirements: [{
          id: 'r1',
          impact: 0.5,
          descriptions: [],
          sourceLocation: { ref: 'test.rb' },
          results: [],
        }],
      }],
      components: [],
    });
    const v1 = transformHDF(v2, '2', '1');
    const parsed = JSON.parse(v1);
    expect(parsed.profiles[0].controls[0].source_location).toEqual({ ref: 'test.rb' });
  });
});
