import { describe, it, expect } from 'vitest';
import { convertV1ToV2, isHDFV1, HDFV1Results } from './converter.js';

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
      expect(v2.targets).toHaveLength(1);
      expect(v2.targets![0]).toMatchObject({
        type: 'host',
        name: 'ubuntu',
        release: '20.04',
      });
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

      expect(v2.targets).toHaveLength(1);
      expect(v2.targets![0]).toEqual({
        type: 'host',
        id: 'server-123',
        name: 'redhat',
        release: '8.5',
      });
    });

    it('should use platform name as target id if target_id not provided', () => {
      const v1: HDFV1Results = {
        version: '1.0.0',
        platform: { name: 'debian' },
        profiles: [],
        statistics: {},
      };

      const v2 = convertV1ToV2(v1);

      expect(v2.targets![0].id).toBe('debian');
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

      expect(v2.targets![0]).toEqual({
        type: 'host',
        id: 'test-system',
        name: 'test-system',
      });
      expect(v2.targets![0]).not.toHaveProperty('release');
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
