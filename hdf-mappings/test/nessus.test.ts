import { describe, it, expect, vi } from 'vitest';
import {
  getNessusNistControl,
  getNessusPluginFamilyMappings,
  getAllNessusPluginFamilies,
  nessusPluginFamilyExists,
  getAllNessusMappings,
} from '../src/nessus/index.js';

describe('Nessus Mapping Functions', () => {
  describe('getNessusNistControl', () => {
    it('should return NIST control for plugin family with wildcard', () => {
      const nistId = getNessusNistControl('AIX Local Security Checks');
      expect(nistId).toBe('SI-2|RA-5');
    });

    it('should return NIST control for plugin family with specific ID', () => {
      const nistId = getNessusNistControl('AIX Local Security Checks', '*');
      expect(nistId).toBe('SI-2|RA-5');
    });

    it('should return undefined for invalid plugin family', () => {
      const nistId = getNessusNistControl('Invalid Plugin Family');
      expect(nistId).toBeUndefined();
    });

    it('should handle multiple plugin families', () => {
      const nistId1 = getNessusNistControl('Amazon Linux Local Security Checks');
      const nistId2 = getNessusNistControl('CentOS Local Security Checks');
      expect(nistId1).toBe('SI-2|RA-5');
      expect(nistId2).toBe('SI-2|RA-5');
    });
  });

  describe('getNessusPluginFamilyMappings', () => {
    it('should return mappings for valid plugin family', () => {
      const mappings = getNessusPluginFamilyMappings('AIX Local Security Checks');
      expect(mappings.length).toBeGreaterThan(0);
      expect(mappings[0].pluginFamily).toBe('AIX Local Security Checks');
    });

    it('should return empty array for invalid plugin family', () => {
      const mappings = getNessusPluginFamilyMappings('Invalid Plugin Family');
      expect(mappings).toEqual([]);
    });
  });

  describe('getAllNessusPluginFamilies', () => {
    it('should return all plugin families', () => {
      const families = getAllNessusPluginFamilies();
      expect(Array.isArray(families)).toBe(true);
      expect(families.length).toBeGreaterThan(0);
      expect(families).toContain('AIX Local Security Checks');
      expect(families).toContain('Amazon Linux Local Security Checks');
    });

    it('should return unique families', () => {
      const families = getAllNessusPluginFamilies();
      const uniqueFamilies = new Set(families);
      expect(families.length).toBe(uniqueFamilies.size);
    });
  });

  describe('nessusPluginFamilyExists', () => {
    it('should return true for valid plugin families', () => {
      expect(nessusPluginFamilyExists('AIX Local Security Checks')).toBe(true);
      expect(nessusPluginFamilyExists('Amazon Linux Local Security Checks')).toBe(true);
    });

    it('should return false for invalid plugin family', () => {
      expect(nessusPluginFamilyExists('Invalid Plugin Family')).toBe(false);
    });
  });

  describe('wildcard fallback path', () => {
    it('returns wildcard mapping when specific pluginId has no exact match', () => {
      // The 'AIX Local Security Checks' family only has a wildcard (*) entry
      // Passing a non-matching pluginId should fall back to the wildcard
      const nistId = getNessusNistControl('AIX Local Security Checks', 'NONEXISTENT-PLUGIN-99999');
      expect(nistId).toBe('SI-2|RA-5');
    });

    it('returns undefined when neither exact nor wildcard matches', () => {
      const nistId = getNessusNistControl('Nonexistent Family', 'PLUGIN-123');
      expect(nistId).toBeUndefined();
    });
  });

  describe('lazy initialization (cold start)', () => {
    it('loads mappings on first call after module reset', async () => {
      vi.resetModules();
      const { getNessusNistControl: getFresh } = await import('../src/nessus/index.js');
      expect(getFresh('AIX Local Security Checks')).toBe('SI-2|RA-5');
    });
  });

  describe('getAllNessusMappings', () => {
    it('should return all mappings', () => {
      const mappings = getAllNessusMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBeGreaterThan(0);
    });

    it('should return mappings with correct structure', () => {
      const mappings = getAllNessusMappings();
      const firstMapping = mappings[0];
      expect(firstMapping).toHaveProperty('pluginFamily');
      expect(firstMapping).toHaveProperty('pluginID');
      expect(firstMapping).toHaveProperty('NIST-ID');
    });

    it('should include specific plugin families', () => {
      const mappings = getAllNessusMappings();
      const families = mappings.map((m) => m.pluginFamily);
      expect(families).toContain('AIX Local Security Checks');
      expect(families).toContain('Amazon Linux Local Security Checks');
    });
  });
});
