import { describe, it, expect, vi } from 'vitest';
import {
  getCCIDescription,
  getCCINistMappings,
  getAllCCIIds,
  cciExists,
} from '../src/cci/index.js';

describe('CCI Mapping Functions', () => {
  describe('getCCIDescription', () => {
    it('should return description for valid CCI ID', () => {
      const desc = getCCIDescription('CCI-000001');
      expect(desc).toBeDefined();
      expect(desc).toContain('access control policy');
    });

    it('should return undefined for invalid CCI ID', () => {
      const desc = getCCIDescription('CCI-999999');
      expect(desc).toBeUndefined();
    });

    it('should handle empty string', () => {
      const desc = getCCIDescription('');
      expect(desc).toBeUndefined();
    });

    it('should be case-sensitive', () => {
      const desc = getCCIDescription('cci-000001');
      expect(desc).toBeUndefined();
    });
  });

  describe('getCCINistMappings', () => {
    it('should return NIST mappings for valid CCI ID', () => {
      const mappings = getCCINistMappings('CCI-000001');
      expect(mappings).toBeDefined();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings!.length).toBeGreaterThan(0);
      expect(mappings).toContain('AC-1 a');
    });

    it('should return undefined for invalid CCI ID', () => {
      const mappings = getCCINistMappings('CCI-999999');
      expect(mappings).toBeUndefined();
    });

    it('should return all NIST mappings for CCI with multiple mappings', () => {
      const mappings = getCCINistMappings('CCI-000001');
      expect(mappings).toBeDefined();
      expect(mappings!.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle empty string', () => {
      const mappings = getCCINistMappings('');
      expect(mappings).toBeUndefined();
    });
  });

  describe('getAllCCIIds', () => {
    it('should return array of all CCI IDs', () => {
      const ids = getAllCCIIds();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(3000); // We know there are 3551 CCIs
    });

    it('should return CCI IDs in expected format', () => {
      const ids = getAllCCIIds();
      const sampleId = ids[0];
      expect(sampleId).toMatch(/^CCI-\d{6}$/);
    });

    it('should return unique CCI IDs', () => {
      const ids = getAllCCIIds();
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('cciExists', () => {
    it('should return true for valid CCI ID', () => {
      expect(cciExists('CCI-000001')).toBe(true);
    });

    it('should return false for invalid CCI ID', () => {
      expect(cciExists('CCI-999999')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(cciExists('')).toBe(false);
    });

    it('should be case-sensitive', () => {
      expect(cciExists('cci-000001')).toBe(false);
    });
  });

  describe('type guard: non-string inputs', () => {
    it('getCCIDescription returns undefined for null', () => {
      expect(getCCIDescription(null as unknown as string)).toBeUndefined();
    });

    it('getCCIDescription returns undefined for undefined', () => {
      expect(getCCIDescription(undefined as unknown as string)).toBeUndefined();
    });

    it('getCCIDescription returns undefined for number', () => {
      expect(getCCIDescription(123 as unknown as string)).toBeUndefined();
    });

    it('getCCIDescription returns undefined for false', () => {
      expect(getCCIDescription(false as unknown as string)).toBeUndefined();
    });

    it('getCCINistMappings returns undefined for null', () => {
      expect(getCCINistMappings(null as unknown as string)).toBeUndefined();
    });

    it('getCCINistMappings returns undefined for 0', () => {
      expect(getCCINistMappings(0 as unknown as string)).toBeUndefined();
    });

    it('cciExists returns false for null', () => {
      expect(cciExists(null as unknown as string)).toBe(false);
    });

    it('cciExists returns false for 42', () => {
      expect(cciExists(42 as unknown as string)).toBe(false);
    });
  });

  describe('lazy initialization (cold start)', () => {
    it('loads data on first call after module reset', async () => {
      vi.resetModules();
      const { getCCIDescription: getCCIDescFresh } = await import('../src/cci/index.js');
      expect(getCCIDescFresh('CCI-000001')).toBeDefined();
    });
  });

  describe('Edge cases and error handling', () => {
    it('should handle CCI IDs with different number formats', () => {
      // Test some known CCI IDs
      expect(cciExists('CCI-000001')).toBe(true);
      expect(cciExists('CCI-001545')).toBe(true);
      expect(cciExists('CCI-001546')).toBe(true);
    });

    it('should return consistent results for same CCI ID', () => {
      const desc1 = getCCIDescription('CCI-000001');
      const desc2 = getCCIDescription('CCI-000001');
      expect(desc1).toBe(desc2);

      const mappings1 = getCCINistMappings('CCI-000001');
      const mappings2 = getCCINistMappings('CCI-000001');
      expect(mappings1).toEqual(mappings2);
    });
  });
});
