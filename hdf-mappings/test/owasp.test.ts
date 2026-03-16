import { describe, it, expect, vi } from 'vitest';
import {
  getOwaspNistMapping,
  getOwaspNistControl,
  getOwaspName,
  getAllOwaspIds,
  owaspExists,
  getAllOwaspMappings,
} from '../src/owasp/index.js';

describe('OWASP Mapping Functions', () => {
  describe('getOwaspNistMapping', () => {
    it('should return mapping for valid OWASP ID', () => {
      const mapping = getOwaspNistMapping('A1');
      expect(mapping).toBeDefined();
      expect(mapping?.['OWASP-ID']).toBe('A1');
      expect(mapping?.['OWASP Name']).toBe('Injection');
      expect(mapping?.['NIST-ID']).toBe('SI-10');
    });

    it('should return undefined for invalid OWASP ID', () => {
      const mapping = getOwaspNistMapping('A99');
      expect(mapping).toBeUndefined();
    });

    it('should handle empty string', () => {
      const mapping = getOwaspNistMapping('');
      expect(mapping).toBeUndefined();
    });

    it('should handle non-string input', () => {
      const mapping = getOwaspNistMapping(null as any);
      expect(mapping).toBeUndefined();
    });
  });

  describe('getOwaspNistControl', () => {
    it('should return NIST control ID for valid OWASP ID', () => {
      const nistId = getOwaspNistControl('A1');
      expect(nistId).toBe('SI-10');
    });

    it('should return NIST control for A2', () => {
      const nistId = getOwaspNistControl('A2');
      expect(nistId).toBe('SC-23');
    });

    it('should return undefined for invalid OWASP ID', () => {
      const nistId = getOwaspNistControl('A99');
      expect(nistId).toBeUndefined();
    });

    it('should handle empty string', () => {
      const nistId = getOwaspNistControl('');
      expect(nistId).toBeUndefined();
    });
  });

  describe('getOwaspName', () => {
    it('should return OWASP name for valid ID', () => {
      const name = getOwaspName('A1');
      expect(name).toBe('Injection');
    });

    it('should return OWASP name for A7', () => {
      const name = getOwaspName('A7');
      expect(name).toBe('Cross-Site Scripting (XSS)');
    });

    it('should return undefined for invalid OWASP ID', () => {
      const name = getOwaspName('A99');
      expect(name).toBeUndefined();
    });

    it('should handle empty string', () => {
      const name = getOwaspName('');
      expect(name).toBeUndefined();
    });
  });

  describe('getAllOwaspIds', () => {
    it('should return all OWASP IDs', () => {
      const ids = getAllOwaspIds();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBe(10);
      expect(ids).toContain('A1');
      expect(ids).toContain('A10');
    });

    it('should return IDs in a consistent order', () => {
      const ids1 = getAllOwaspIds();
      const ids2 = getAllOwaspIds();
      expect(ids1).toEqual(ids2);
    });
  });

  describe('owaspExists', () => {
    it('should return true for valid OWASP IDs', () => {
      expect(owaspExists('A1')).toBe(true);
      expect(owaspExists('A5')).toBe(true);
      expect(owaspExists('A10')).toBe(true);
    });

    it('should return false for invalid OWASP ID', () => {
      expect(owaspExists('A99')).toBe(false);
      expect(owaspExists('B1')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(owaspExists('')).toBe(false);
    });

    it('should return false for non-string input', () => {
      expect(owaspExists(null as any)).toBe(false);
      expect(owaspExists(undefined as any)).toBe(false);
    });
  });

  describe('lazy initialization (cold start)', () => {
    it('loads mappings on first call after module reset', async () => {
      vi.resetModules();
      const { getOwaspNistControl: getFresh } = await import('../src/owasp/index.js');
      expect(getFresh('A1')).toBe('SI-10');
    });
  });

  describe('getAllOwaspMappings', () => {
    it('should return all mappings', () => {
      const mappings = getAllOwaspMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBe(10);
    });

    it('should return mappings with correct structure', () => {
      const mappings = getAllOwaspMappings();
      const firstMapping = mappings[0];
      expect(firstMapping).toHaveProperty('OWASP-ID');
      expect(firstMapping).toHaveProperty('OWASP Name');
      expect(firstMapping).toHaveProperty('NIST-ID');
      expect(firstMapping).toHaveProperty('Rev');
      expect(firstMapping).toHaveProperty('NIST Name');
    });

    it('should include all Top 10 items', () => {
      const mappings = getAllOwaspMappings();
      const ids = mappings.map(m => m['OWASP-ID']);
      for (let i = 1; i <= 10; i++) {
        expect(ids).toContain(`A${i}`);
      }
    });
  });
});
