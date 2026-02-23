import { describe, it, expect, vi } from 'vitest';
import {
  getCCIDescription,
  getCCINistMappings,
  getAllCCIIds,
  cciExists,
  getNistCCIMappings,
  nistToCci,
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

  describe('getNistCCIMappings', () => {
    it('should return CCI IDs for a known NIST control', () => {
      const ccis = getNistCCIMappings('AC-3');
      expect(ccis).toBeDefined();
      expect(Array.isArray(ccis)).toBe(true);
      expect(ccis!.length).toBeGreaterThan(0);
      expect(ccis![0]).toMatch(/^CCI-\d{6}$/);
    });

    it('should normalize qualified controls to base control', () => {
      // 'AC-6 (2)' should be looked up as 'AC-6'
      const fromQualified = getNistCCIMappings('AC-6 (2)');
      const fromBase = getNistCCIMappings('AC-6');
      expect(fromQualified).toEqual(fromBase);
    });

    it('should normalize space-delimited enhancements to base control', () => {
      // 'AC-4 a 1' should be looked up as 'AC-4'
      const fromEnhancement = getNistCCIMappings('AC-4 a 1');
      const fromBase = getNistCCIMappings('AC-4');
      expect(fromEnhancement).toEqual(fromBase);
    });

    it('should return undefined for unknown NIST control', () => {
      expect(getNistCCIMappings('ZZ-999')).toBeUndefined();
    });

    it('should return undefined for empty string', () => {
      expect(getNistCCIMappings('')).toBeUndefined();
    });

    it('should return undefined for null', () => {
      expect(getNistCCIMappings(null as unknown as string)).toBeUndefined();
    });

    it('should return undefined for non-string input', () => {
      expect(getNistCCIMappings(42 as unknown as string)).toBeUndefined();
    });
  });

  describe('nistToCci', () => {
    it('should return CCI IDs for an array of NIST controls', () => {
      const ccis = nistToCci(['AC-3', 'AU-12']);
      expect(Array.isArray(ccis)).toBe(true);
      expect(ccis.length).toBeGreaterThan(0);
      expect(ccis[0]).toMatch(/^CCI-\d{6}$/);
    });

    it('should return sorted results', () => {
      const ccis = nistToCci(['AC-3', 'AU-12']);
      const sorted = [...ccis].sort();
      expect(ccis).toEqual(sorted);
    });

    it('should deduplicate CCI IDs', () => {
      // Same control twice should not produce duplicates
      const ccis = nistToCci(['AC-3', 'AC-3']);
      const unique = new Set(ccis);
      expect(unique.size).toBe(ccis.length);
    });

    it('should return empty array for unknown controls', () => {
      const ccis = nistToCci(['ZZ-999', 'ZZ-888']);
      expect(ccis).toEqual([]);
    });

    it('should return empty array for empty input', () => {
      const ccis = nistToCci([]);
      expect(ccis).toEqual([]);
    });

    it('should skip controls with no mappings', () => {
      const ccisWithUnknown = nistToCci(['AC-3', 'ZZ-999']);
      const ccisWithoutUnknown = nistToCci(['AC-3']);
      expect(ccisWithUnknown).toEqual(ccisWithoutUnknown);
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
