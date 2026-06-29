import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { inspec } from '@mitre/hdf-fixtures';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { convertV1ToV2, isHDFV1, HDFV1Results } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

// Migrated to @mitre/hdf-fixtures/inspec/ — see bead hdf-libs-e95o. Other
// input fixtures (e.g. minimal.json) remain local to this converter as its
// single-package tested contract.
const SHARED_INPUTS: Record<string, string> = {
  'ubi9-scan.json': inspec.ubi9Scan.path,
  'container-scan.json': inspec.containerScan.path,
  'three-layer-overlay.json': inspec.threeLayerOverlay.path,
  'wrapper.json': inspec.wrapper.path,
};

function inputFixturePath(name: string): string {
  return SHARED_INPUTS[name] ?? join(FIXTURES_DIR, 'input', name);
}

describe('HDF v1.0 to v2.0 Converter', () => {
  describe('convertV1ToV2', () => {
    it('should convert minimal v1.0 to v2.0', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'ubuntu', release: '20.04' },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.baselines).toEqual([]);
      expect(v2.statistics).toEqual({});
      expect(v2.components).toHaveLength(1);
      // release present → osName/osVersion populated even without target_id
      // (mirrors Go).
      expect(v2.components![0]).toEqual({
        type: 'host',
        name: 'ubuntu',
        osName: 'ubuntu',
        osVersion: '20.04',
      });
      expect(v2.tool?.name).toBe('Heimdall Data Format v1');
      expect(v2.tool?.version).toBeUndefined();
      expect(v2.tool?.format).toBeUndefined();
    });

    it('should rename profiles to baselines', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{ name: 'profile1' }, { name: 'profile2' }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.baselines).toHaveLength(2);
      expect(v2.baselines[0]).toEqual({ name: 'profile1' });
      expect(v2.baselines[1]).toEqual({ name: 'profile2' });
    });

    it('should transform platform to targets array', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: {
          name: 'redhat',
          release: '8.5',
          target_id: 'server-123',
        },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.components).toHaveLength(1);
      // Mirrors the Go converter: {type, name} plus osName/osVersion when the
      // platform carries a target_id. No id/release/labels.
      expect(v2.components![0]).toEqual({
        type: 'host',
        name: 'redhat',
        osName: 'redhat',
        osVersion: '8.5',
      });
    });

    it('should emit only {type,name} when target_id is absent', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'debian' },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.components![0]).toEqual({ type: 'host', name: 'debian' });
    });

    it('should preserve generator information', () => {
      const generator = { name: 'inspec', version: '4.18.0' };
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
        generator,
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.generator).toEqual(generator);
    });

    it('should preserve timestamp', () => {
      const timestamp = '2024-01-03T12:00:00Z';
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
        timestamp,
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.timestamp).toBe(timestamp);
    });

    it('should handle missing optional fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.generator).toBeUndefined();
      expect(v2.timestamp).toBeUndefined();
    });

    it('should move unknown fields to extensions', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
        customField: 'custom value',
        anotherField: { nested: 'data' },
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.extensions).toBeDefined();
      expect(v2.extensions!.customField).toBe('custom value');
      expect(v2.extensions!.anotherField).toEqual({ nested: 'data' });
      expect(v2.extensions!.v1_version).toBe('1.0.0');
    });

    it('should not create extensions if no unknown fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.extensions).toBeUndefined();
    });

    it('should handle platform without release', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test-system' },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.components![0]).toEqual({
        type: 'host',
        name: 'test-system',
      });
      expect(v2.components![0]).not.toHaveProperty('release');
    });

    it('should handle complex statistics object', () => {
      const statistics = {
        duration: 10.5,
        total: 100,
        passed: 80,
        failed: 15,
        skipped: 5,
      };

      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics,
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.statistics).toEqual(statistics);
    });

    it('should handle undefined profiles with fallback', () => {
      const v1 = {
        version: '1.0.0',
        platform: { name: 'test' },
        statistics: {},
      } as HDFV1Results;

      const v2 = convertV1ToV2(v1);

      expect(v2.baselines).toEqual([]);
    });

    it('should handle undefined statistics with fallback', () => {
      const v1 = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
      } as HDFV1Results;

      const v2 = convertV1ToV2(v1);

      expect(v2.statistics).toEqual({});
    });
  });

  describe('Optional Field Coverage', () => {
    it('should convert all result optional fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test-profile',
          controls: [{
            id: 'control-1',
            impact: 0.7,
            results: [{
              status: 'failed',
              code_desc: 'Test code description',
              run_time: 1.5,
              start_time: '2024-01-01T00:00:00Z',
              message: 'Test message',
              exception: 'TestException',
              backtrace: ['line1', 'line2'],
              resource_class: 'File',
              resource_params: { path: '/test' },
              resource_id: '/etc/test',
              skip_message: 'Test skip',
            }],
          }],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      const result = v2.baselines[0].requirements![0].results[0];

      expect(result.codeDesc).toBe('Test code description');
      expect(result.runTime).toBe(1.5);
      expect(result.startTime).toBe('2024-01-01T00:00:00Z');
      expect(result.message).toBe('Test message');
      expect(result.exception).toBe('TestException');
      expect(result.backtrace).toEqual(['line1', 'line2']);
      // v1 resource_class maps to the v2 `resource` field (mirrors Go).
      expect(result.resource).toBe('File');
      expect(result.resourceId).toBe('/etc/test');
      // resourceClass/resourceParams/skipMessage are not Requirement_Result
      // fields and are intentionally dropped.
      expect(result.resourceClass).toBeUndefined();
      expect(result.resourceParams).toBeUndefined();
      expect(result.skipMessage).toBeUndefined();
    });

    it('emits Go zero-value time for an unparseable start_time (schema-valid, not passthrough)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'p',
          controls: [{ id: 'c', impact: 0.5, results: [{ status: 'passed', start_time: 'not-a-date' }] }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      // Matches the Go converter: an unparseable value becomes time.Time{}'s
      // zero rendering rather than an invalid passthrough string.
      expect(v2.baselines[0].requirements![0].results[0].startTime).toBe('0001-01-01T00:00:00Z');
    });

    it('emits Go zero-value time when start_time is absent (startTime stays present)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'p',
          controls: [{ id: 'c', impact: 0.5, results: [{ status: 'passed' }] }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].results[0].startTime).toBe('0001-01-01T00:00:00Z');
    });

    it('normalizes an offset-bearing start_time to UTC', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'p',
          controls: [{ id: 'c', impact: 0.5, results: [{ status: 'passed', start_time: '2026-02-22T15:57:06-05:00' }] }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].results[0].startTime).toBe('2026-02-22T20:57:06Z');
    });

    it('should convert all control/requirement optional fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test-profile',
          controls: [{
            id: 'control-1',
            impact: 0.7,
            title: 'Test Title',
            desc: 'Test Description',
            descriptions: [{ label: 'default', data: 'Test' }],
            refs: [{ url: 'https://example.com' }],
            tags: { nist: ['AC-1'] },
            code: 'describe "test" do\nend',
            source_location: { ref: 'test.rb', line: 10 },
            waiver_data: { expiration: '2025-01-01' },
            status: 'not_applicable',
            results: [{ status: 'passed' }],
          }],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      const req = v2.baselines[0].requirements![0];

      expect(req.title).toBe('Test Title');
      expect(req.descriptions).toEqual([{ label: 'default', data: 'Test' }]);
      expect(req.tags).toEqual({ nist: ['AC-1'] });
      expect(req.code).toBe('describe "test" do\nend');
      expect(req.sourceLocation).toEqual({ ref: 'test.rb', line: 10 });
      expect(req.effectiveStatus).toBe('notApplicable');
      // desc and waiver_data are not valid v2 Requirement fields (desc →
      // descriptions; waivers are amendments in v2) and are dropped, matching Go.
      expect(req.desc).toBeUndefined();
      expect(req.waiverData).toBeUndefined();
    });

    it('should convert all status values correctly', () => {
      const statuses = [
        { v1: 'passed', v2: 'passed' },
        { v1: 'failed', v2: 'failed' },
        { v1: 'error', v2: 'error' },
        { v1: 'not_applicable', v2: 'notApplicable' },
        { v1: 'not_reviewed', v2: 'notReviewed' },
        { v1: 'skipped', v2: 'notReviewed' },
      ];

      statuses.forEach(({ v1: v1Status, v2: v2Status }) => {
        const v1: HDFV1Results = {
          version: '1.0.0',
          platform: { name: 'test' },
          profiles: [{
            name: 'test',
            controls: [{
              id: 'test',
              impact: 0.5,
              status: v1Status,
              results: [{ status: v1Status }],
            }],
          }],
          statistics: {},
        };

        const v2 = convertV1ToV2(v1);
        expect(v2.baselines[0].requirements![0].effectiveStatus).toBe(v2Status);
        expect(v2.baselines[0].requirements![0].results[0].status).toBe(v2Status);
      });
    });

    it('should default unknown status values to notReviewed', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'test',
            impact: 0.5,
            status: 'custom_status',
            results: [{ status: 'custom_result_status' }],
          }],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('notReviewed');
      expect(v2.baselines[0].requirements![0].results![0].status).toBe('notReviewed');
    });

    it('should convert group with all optional fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test-profile',
          groups: [{
            id: 'group-1',
            title: 'Group Title',
            controls: ['control-1', 'control-2'],
          }],
          controls: [],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      const group = v2.baselines[0].groups![0];

      expect(group.id).toBe('group-1');
      expect(group.title).toBe('Group Title');
      expect(group.requirements).toEqual(['control-1', 'control-2']);
    });

    it('should convert dependency with all optional fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test-profile',
          depends: [{
            name: 'dep-profile',
            url: 'https://example.com/profile',
            path: '/path/to/profile',
            git: 'https://github.com/test/profile.git',
            branch: 'main',
            tag: 'v1.0.0',
            commit: 'abc123',
            version: '1.0.0',
            supermarket: 'test/profile',
            compliance: { name: 'compliance' },
            status: 'loaded',
            skip_message: 'Skipped',
          }],
          controls: [],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      const dep = v2.baselines[0].depends![0];

      expect(dep.name).toBe('dep-profile');
      expect(dep.url).toBe('https://example.com/profile');
      expect(dep.path).toBe('/path/to/profile');
      expect(dep.git).toBe('https://github.com/test/profile.git');
      expect(dep.branch).toBe('main');
      expect(dep.tag).toBe('v1.0.0');
      expect(dep.commit).toBe('abc123');
      expect(dep.version).toBe('1.0.0');
      expect(dep.supermarket).toBe('test/profile');
      expect(dep.compliance).toEqual({ name: 'compliance' });
      expect(dep.status).toBe('loaded');
      expect(dep.skipMessage).toBe('Skipped');
    });

    it('should convert profile/baseline with all optional fields', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test-profile',
          version: '1.0.0',
          title: 'Test Profile',
          maintainer: 'Test Maintainer',
          summary: 'Test Summary',
          license: 'Apache-2.0',
          copyright: 'Copyright 2024',
          copyright_email: 'test@example.com',
          supports: [{ platform: 'ubuntu' }],
          attributes: [{ name: 'attr1', options: {} }],
          status: 'loaded',
          sha256: 'abc123',
          parent_profile: 'parent-profile',
          status_message: 'Status message',
          skip_message: 'Skip message',
          groups: [],
          controls: [],
          depends: [],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      const baseline = v2.baselines[0];

      expect(baseline.version).toBe('1.0.0');
      expect(baseline.title).toBe('Test Profile');
      expect(baseline.maintainer).toBe('Test Maintainer');
      expect(baseline.summary).toBe('Test Summary');
      expect(baseline.license).toBe('Apache-2.0');
      expect(baseline.copyright).toBe('Copyright 2024');
      expect(baseline.copyrightEmail).toBe('test@example.com');
      expect(baseline.supports).toEqual([{ platform: 'ubuntu' }]);
      expect(baseline.inputs).toEqual([{ name: 'attr1', options: {} }]);
      expect(baseline.status).toBe('loaded');
      expect(baseline.integrity).toEqual({ algorithm: 'sha256', checksum: 'abc123' });
      expect(baseline.parentBaseline).toBe('parent-profile');
      expect(baseline.statusMessage).toBe('Status message');
      expect(baseline.skipMessage).toBe('Skip message');
    });

    it('should drop unknown fields in results (closed v2 shape)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'test',
            impact: 0.5,
            results: [{
              status: 'passed',
              custom_field: 'custom_value',
            }],
          }],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      // Requirement_Result is a closed schema shape; unknown v1 fields are not
      // carried (matches the Go converter).
      expect(v2.baselines[0].requirements![0].results[0]).not.toHaveProperty('custom_field');
    });

    it('should drop unknown fields in controls (closed v2 shape)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'test',
            impact: 0.5,
            custom_control_field: 'custom',
            results: [],
          }],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0]).not.toHaveProperty('custom_control_field');
    });

    it('should preserve unknown fields in groups', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          groups: [{
            id: 'group1',
            controls: [],
            custom_group_field: 'custom',
          }],
          controls: [],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].groups![0]).toHaveProperty('custom_group_field', 'custom');
    });

    it('should preserve unknown fields in dependencies', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          depends: [{
            name: 'dep',
            custom_dep_field: 'custom',
          }],
          controls: [],
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].depends![0]).toHaveProperty('custom_dep_field', 'custom');
    });

    it('should drop unknown fields in profiles/baselines (closed v2 shape)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [],
          custom_profile_field: 'custom',
        }],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0]).not.toHaveProperty('custom_profile_field');
    });
  });

  // --- Real InSpec fixture (ubi9 STIG scan, 452 controls) ---

  describe('ubi9-scan fixture (real InSpec exec-json)', () => {
    const raw = readFileSync(
      inputFixturePath('ubi9-scan.json'),
      'utf-8'
    );
    const v1 = JSON.parse(raw) as HDFV1Results;

    it('should be detected as valid HDF v1.0', () => {
      expect(isHDFV1(v1)).toBe(true);
    });

    it('should convert without throwing', () => {
      expect(() => convertV1ToV2(v1)).not.toThrow();
    });

    it('should produce one baseline from one profile', () => {
      const v2 = convertV1ToV2(v1);
      expectValidResults(v2);
      expect(v2.baselines).toHaveLength(1);
      expect(v2.baselines[0].name).toBe(
        'redhat-enterprise-linux-9-stig-baseline'
      );
    });

    it('should convert all 452 controls to requirements', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements).toHaveLength(452);
    });

    it('should map platform to target', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.components).toHaveLength(1);
      // target_id present → osName/osVersion populated (mirrors Go).
      expect(v2.components![0]).toEqual({
        type: 'host',
        name: 'redhat',
        osName: 'redhat',
        osVersion: '9.7',
      });
    });

    it('should preserve statistics', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.statistics).toMatchObject({ duration: 47.904315 });
    });

    it('should normalize status values', () => {
      const v2 = convertV1ToV2(v1);
      const reqs = v2.baselines[0].requirements!;
      const statuses = reqs.map((r) => r.effectiveStatus);
      expect(statuses).toContain('passed');
      expect(statuses).toContain('failed');
      expect(statuses).toContain('notApplicable');
      expect(statuses).toContain('notReviewed');
      // skipped in v1 → notReviewed in v2 (no raw 'skipped' should remain)
      expect(statuses).not.toContain('skipped');
      expect(statuses).not.toContain('not_applicable');
    });

    it('should preserve NIST tags on controls', () => {
      const v2 = convertV1ToV2(v1);
      const withNist = v2.baselines[0].requirements!.filter(
        (r) => r.tags?.['nist']
      );
      expect(withNist.length).toBeGreaterThan(0);
    });

    it('should preserve sha256 as integrity', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].integrity).toEqual({
        algorithm: 'sha256',
        checksum: expect.stringMatching(/^[a-f0-9]{64}$/),
      });
    });

    it('maps profile supports onto the baseline (real data)', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].supports).toEqual([{ platformFamily: 'redhat', release: '9.*' }]);
    });

    it('maps control refs onto requirements (real DPMS ref)', () => {
      const v2 = convertV1ToV2(v1);
      const sawDpms = v2.baselines[0].requirements!.some(
        (r) =>
          Array.isArray(r.refs) &&
          r.refs.some((ref) => (ref as { ref?: unknown }).ref === 'DPMS Target Red Hat Enterprise Linux 9'),
      );
      expect(sawDpms).toBe(true);
    });
  });

  describe('overlay flattening — deep nesting (3-layer overlay)', () => {
    const raw = readFileSync(
      inputFixturePath('three-layer-overlay.json'),
      'utf-8'
    );
    const v1 = JSON.parse(raw) as HDFV1Results;

    it('should flatten 3 profiles into 1 baseline', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines).toHaveLength(1);
    });

    it('should produce exactly 247 deduplicated requirements', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements).toHaveLength(247);
    });

    it('should have results on every requirement (from base profile)', () => {
      const v2 = convertV1ToV2(v1);
      const withResults = v2.baselines[0].requirements!.filter(
        (r) => r.results && r.results.length > 0
      );
      expect(withResults).toHaveLength(247);
    });

    it('should clear parentBaseline on flattened output', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].parentBaseline).toBeUndefined();
    });

    it('should use top overlay name as baseline name', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].name).toContain('second-layer');
    });
  });

  describe('overlay flattening — wide nesting (wrapper)', () => {
    const raw = readFileSync(
      inputFixturePath('wrapper.json'),
      'utf-8'
    );
    const v1 = JSON.parse(raw) as HDFV1Results;

    it('should flatten 4 profiles into 1 baseline', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines).toHaveLength(1);
    });

    it('should produce 534 aggregated requirements', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements).toHaveLength(534);
    });

    it('should use wrapper name as baseline name', () => {
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].name).toBe('wrapper');
    });
  });

  describe('overlay flattening — passthrough (no overlays)', () => {
    it('should pass through single-profile input unchanged', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'simple-profile',
          controls: [
            { id: 'V-1', impact: 0.5, results: [{ status: 'passed', code_desc: 'test' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines).toHaveLength(1);
      expect(v2.baselines[0].name).toBe('simple-profile');
      expect(v2.baselines[0].requirements).toHaveLength(1);
    });
  });

  describe('impact=0 → effectiveStatus notApplicable', () => {
    it('should set effectiveStatus to notApplicable when impact is 0 and no explicit status', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0, results: [{ status: 'skipped' }] },
            { id: 'V-2', impact: 0.7, results: [{ status: 'passed' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      const reqs = v2.baselines[0].requirements!;
      expect(reqs.find(r => r.id === 'V-1')!.effectiveStatus).toBe('notApplicable');
      expect(reqs.find(r => r.id === 'V-2')!.effectiveStatus).toBe('passed');
    });

    it('should not override explicit effectiveStatus even if impact is 0', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0, status: 'passed', results: [{ status: 'passed' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('passed');
    });

    it('should classify 27 impact=0 controls as notApplicable in Three_Layer fixture', () => {
      const raw = readFileSync(
        inputFixturePath('three-layer-overlay.json'),
        'utf-8'
      );
      const v1 = JSON.parse(raw) as HDFV1Results;
      const v2 = convertV1ToV2(v1);
      const reqs = v2.baselines[0].requirements!;
      const notApplicable = reqs.filter(r => r.effectiveStatus === 'notApplicable');
      expect(notApplicable).toHaveLength(27);

      // All 27 should have impact=0
      for (const r of notApplicable) {
        expect(r.impact).toBe(0);
      }
    });
  });

  describe('effectiveStatus always computed from results', () => {
    it('should set effectiveStatus=passed when all results passed', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0.7, results: [{ status: 'passed' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('passed');
    });

    it('should set effectiveStatus=failed when any result failed', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0.7, results: [{ status: 'passed' }, { status: 'failed' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('failed');
    });

    it('should set effectiveStatus=passed when mixed passed+skipped (not all passed)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0.7, results: [{ status: 'skipped' }, { status: 'passed' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('passed');
    });

    it('should set effectiveStatus=notReviewed when all results skipped', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0.5, results: [{ status: 'skipped' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('notReviewed');
    });

    it('should set effectiveStatus=notReviewed when no results', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0.5, results: [] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('notReviewed');
    });

    it('should set effectiveStatus=error when any result errored', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [
            { id: 'V-1', impact: 0.7, results: [{ status: 'passed' }, { status: 'error' }] },
          ],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].effectiveStatus).toBe('error');
    });

    it('Three_Layer fixture: every control has effectiveStatus set', () => {
      const raw = readFileSync(
        inputFixturePath('three-layer-overlay.json'),
        'utf-8'
      );
      const v1 = JSON.parse(raw) as HDFV1Results;
      const v2 = convertV1ToV2(v1);
      const reqs = v2.baselines[0].requirements!;
      const withoutES = reqs.filter(r => r.effectiveStatus === undefined);
      expect(withoutES).toHaveLength(0);
    });

    it('Three_Layer fixture: counts match expected (73 passed, 138 failed, 27 NA, 9 NR)', () => {
      const raw = readFileSync(
        inputFixturePath('three-layer-overlay.json'),
        'utf-8'
      );
      const v1 = JSON.parse(raw) as HDFV1Results;
      const v2 = convertV1ToV2(v1);
      const reqs = v2.baselines[0].requirements!;
      const counts = { passed: 0, failed: 0, notApplicable: 0, notReviewed: 0, error: 0 };
      for (const r of reqs) {
        const es = r.effectiveStatus as string;
        if (es in counts) counts[es as keyof typeof counts]++;
      }
      expect(counts.passed).toBe(73);
      expect(counts.failed).toBe(138);
      expect(counts.notApplicable).toBe(27);
      expect(counts.notReviewed).toBe(9);
      expect(counts.error).toBe(0);
    });
  });

  describe('severity from tags.severity', () => {
    it('should populate severity from tags.severity for NA controls (impact=0)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'V-1',
            impact: 0,
            tags: { severity: 'medium', nist: ['AC-1'] },
            results: [{ status: 'skipped' }],
          }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      const req = v2.baselines[0].requirements![0];
      expect(req.severity).toBe('medium');
      expect(req.effectiveStatus).toBe('notApplicable');
    });

    it('should populate severity from tags.severity for non-NA controls', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'V-1',
            impact: 0.7,
            tags: { severity: 'high' },
            results: [{ status: 'passed' }],
          }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].severity).toBe('high');
    });

    it('should fall back to impact-derived severity when tags.severity missing', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'V-1',
            impact: 0.7,
            results: [{ status: 'passed' }],
          }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].severity).toBe('high');
    });

    it('should map impact values to correct severity levels', () => {
      const cases = [
        { impact: 0.9, expected: 'critical' },
        { impact: 0.7, expected: 'high' },
        { impact: 0.5, expected: 'medium' },
        { impact: 0.3, expected: 'low' },
        { impact: 0, expected: 'informational' }, // canonical bands: 0 → informational (never 'none')
      ];
      for (const { impact, expected } of cases) {
        const v1: HDFV1Results = {
          version: '1.0.0',
          platform: { name: 'test' },
          profiles: [{
            name: 'test',
            controls: [{ id: 'V-1', impact, results: [] }],
          }],
          statistics: {},
        };
        const v2 = convertV1ToV2(v1);
        expect(v2.baselines[0].requirements![0].severity).toBe(expected);
      }
    });

    it('should ignore invalid tags.severity values and fall back to impact', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'test',
          controls: [{
            id: 'V-1',
            impact: 0.7,
            tags: { severity: 'bogus' },
            results: [{ status: 'passed' }],
          }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].requirements![0].severity).toBe('high');
    });

    it('ubi9 fixture: NA controls should have severity from tags, not "none"', () => {
      const raw = readFileSync(inputFixturePath('ubi9-scan.json'), 'utf-8');
      const v1 = JSON.parse(raw) as HDFV1Results;
      const v2 = convertV1ToV2(v1);
      const reqs = v2.baselines[0].requirements!;

      // SV-257779 has impact=0 (NA) but tags.severity=medium
      const sv257779 = reqs.find(r => r.id === 'SV-257779');
      expect(sv257779).toBeDefined();
      expect(sv257779!.effectiveStatus).toBe('notApplicable');
      expect(sv257779!.severity).toBe('medium');

      // No NA control should have severity "none" when tags.severity exists
      const naWithNone = reqs.filter(
        r => r.effectiveStatus === 'notApplicable' && r.severity === 'none'
      );
      expect(naWithNone).toHaveLength(0);
    });
  });

  // ── v1 field fidelity (bead hdf-libs-9q8o) ──────────────────
  describe('v1 field fidelity', () => {
    function singleControl(control: Record<string, unknown>): HDFV1Results {
      return {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{ name: 'p', controls: [control as never] }],
        statistics: {},
      };
    }

    it('maps a string-valued control ref to requirement refs', () => {
      const v2 = convertV1ToV2(
        singleControl({ id: 'V-1', impact: 0.5, refs: [{ ref: 'DPMS Target Red Hat Enterprise Linux 9' }] }),
      );
      expect(v2.baselines[0].requirements![0].refs).toEqual([
        { ref: 'DPMS Target Red Hat Enterprise Linux 9' },
      ]);
    });

    it('maps a bare-string ref element', () => {
      const v2 = convertV1ToV2(singleControl({ id: 'V-1', impact: 0.5, refs: ['NIST SP 800-53'] }));
      expect(v2.baselines[0].requirements![0].refs).toEqual([{ ref: 'NIST SP 800-53' }]);
    });

    it('preserves url and uri on a ref', () => {
      const v2 = convertV1ToV2(
        singleControl({ id: 'V-1', impact: 0.5, refs: [{ ref: 'doc', url: 'https://example.com', uri: 'urn:x' }] }),
      );
      expect(v2.baselines[0].requirements![0].refs).toEqual([
        { ref: 'doc', url: 'https://example.com', uri: 'urn:x' },
      ]);
    });

    it('maps an array-of-objects ref through unchanged', () => {
      const v2 = convertV1ToV2(
        singleControl({ id: 'V-1', impact: 0.5, refs: [{ ref: [{ url: 'https://example.com/doc' }] }] }),
      );
      expect(v2.baselines[0].requirements![0].refs).toEqual([
        { ref: [{ url: 'https://example.com/doc' }] },
      ]);
    });

    it('drops an empty ref array (no content)', () => {
      const v2 = convertV1ToV2(singleControl({ id: 'V-1', impact: 0.5, refs: [{ ref: [] }] }));
      expect(v2.baselines[0].requirements![0].refs).toBeUndefined();
    });

    it('maps result skip_message to result.message when message is absent', () => {
      const v2 = convertV1ToV2(
        singleControl({
          id: 'V-1',
          impact: 0.5,
          results: [{ status: 'skipped', skip_message: 'Skipped control due to only_if condition' }],
        }),
      );
      expect(v2.baselines[0].requirements![0].results![0].message).toBe(
        'Skipped control due to only_if condition',
      );
    });

    it('does not override an explicit result message with skip_message', () => {
      const v2 = convertV1ToV2(
        singleControl({
          id: 'V-1',
          impact: 0.5,
          results: [{ status: 'failed', message: 'real message', skip_message: 'skip message' }],
        }),
      );
      expect(v2.baselines[0].requirements![0].results![0].message).toBe('real message');
    });

    it('maps profile supports (hyphenated keys) to baseline supports (camelCase)', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{
          name: 'p',
          supports: [
            { 'platform-family': 'redhat', release: '9.*' },
            { 'platform-name': 'centos', release: '7.*' },
            { platform: 'os' },
          ],
          controls: [{ id: 'V-1', impact: 0.5, results: [{ status: 'passed' }] }],
        }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].supports).toEqual([
        { platformFamily: 'redhat', release: '9.*' },
        { platformName: 'centos', release: '7.*' },
        { platform: 'os' },
      ]);
    });

    it('drops supports entries with no recognized keys', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [{ name: 'p', supports: [{ 'unknown-key': 'x' }, {}], controls: [] }],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.baselines[0].supports).toBeUndefined();
    });

    it('populates osName/osVersion from release even without target_id', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'centos', release: '7.9.2009' },
        profiles: [],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.components![0]).toEqual({ type: 'host', name: 'centos', osName: 'centos', osVersion: '7.9.2009' });
    });

    it('leaves OS fields unset when neither release nor target_id present', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
      };
      const v2 = convertV1ToV2(v1);
      expect(v2.components![0]).toEqual({ type: 'host', name: 'test' });
    });
  });

  describe('isHDFV1', () => {
    it('should return true for valid v1.0 structure', () => {
      const data = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(true);
    });

    it('should return false for v2.0 structure (baselines instead of profiles)', () => {
      const data = {
        baselines: [],
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });

    it('should return false for null', () => {
      expect(isHDFV1(null)).toBe(false);
    });

    it('should return false for undefined', () => {
      expect(isHDFV1(undefined)).toBe(false);
    });

    it('should return false for non-object types', () => {
      expect(isHDFV1('string')).toBe(false);
      expect(isHDFV1(123)).toBe(false);
      expect(isHDFV1(true)).toBe(false);
      expect(isHDFV1([])).toBe(false);
    });

    it('should return false if missing version', () => {
      const data = {
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });

    it('should return false if missing profiles', () => {
      const data = {
        version: '1.0.0',
        platform: { name: 'test' },
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });

    it('should return false if missing platform', () => {
      const data = {
        version: '1.0.0',
        profiles: [],
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });

    it('should return false if platform is null', () => {
      const data = {
        version: '1.0.0',
        platform: null,
        profiles: [],
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });

    it('should return false if profiles is not an array', () => {
      const data = {
        version: '1.0.0',
        platform: { name: 'test' },
        profiles: {},
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });

    it('should return false if version is not a string', () => {
      const data = {
        version: 1.0,
        platform: { name: 'test' },
        profiles: [],
        statistics: {},
      };

      expect(isHDFV1(data)).toBe(false);
    });
  });
});

// Pins Go↔TS parity for the three-layer-overlay fixture (bead hdf-libs-rf06):
// the committed snapshot is generated from the Go converter, so asserting the
// TS output equals it byte-for-byte locks both languages to identical output.
describe('three-layer-overlay parity snapshot', () => {
  it('TS output equals the committed (Go-generated) snapshot and is schema-valid', () => {
    const v1 = JSON.parse(readFileSync(inputFixturePath('three-layer-overlay.json'), 'utf-8')) as HDFV1Results;
    const v2 = convertV1ToV2(v1);
    expectValidResults(v2);
    const expected = JSON.parse(
      readFileSync(join(FIXTURES_DIR, 'expected', 'three-layer-overlay.json'), 'utf-8'),
    );
    expect(v2).toEqual(expected);
  });
});
