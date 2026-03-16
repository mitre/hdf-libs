import { describe, it, expect } from 'vitest';
import {
  getCweNistMapping,
  getCweNistControl,
  getCweName,
  getAllCweIds,
  cweExists,
  getAllCweMappings,
} from '../src/cwe/index.js';

describe('CWE Mapping Functions', () => {
  describe('getCweNistMapping', () => {
    it('should return mapping for valid CWE ID', () => {
      const mapping = getCweNistMapping(5);
      expect(mapping).toBeDefined();
      expect(mapping?.['CWE-ID']).toBe(5);
      expect(mapping?.['CWE Name']).toBe(
        'J2EE Misconfiguration: Data Transmission Without Encryption'
      );
      expect(mapping?.['NIST-ID']).toBe('SC-8');
    });

    it('should return undefined for invalid CWE ID', () => {
      const mapping = getCweNistMapping(999999);
      expect(mapping).toBeUndefined();
    });

    it('should handle CWE-6', () => {
      const mapping = getCweNistMapping(6);
      expect(mapping).toBeDefined();
      expect(mapping?.['NIST-ID']).toBe('SC-23');
    });
  });

  describe('getCweNistControl', () => {
    it('should return NIST control ID for valid CWE ID', () => {
      const nistId = getCweNistControl(5);
      expect(nistId).toBe('SC-8');
    });

    it('should return undefined for invalid CWE ID', () => {
      const nistId = getCweNistControl(999999);
      expect(nistId).toBeUndefined();
    });
  });

  describe('getCweName', () => {
    it('should return CWE name for valid ID', () => {
      const name = getCweName(5);
      expect(name).toBe('J2EE Misconfiguration: Data Transmission Without Encryption');
    });

    it('should return undefined for invalid CWE ID', () => {
      const name = getCweName(999999);
      expect(name).toBeUndefined();
    });
  });

  describe('getAllCweIds', () => {
    it('should return all CWE IDs', () => {
      const ids = getAllCweIds();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(0);
      expect(ids).toContain(5);
      expect(ids).toContain(6);
    });

    it('should return IDs in a consistent order', () => {
      const ids1 = getAllCweIds();
      const ids2 = getAllCweIds();
      expect(ids1).toEqual(ids2);
    });
  });

  describe('cweExists', () => {
    it('should return true for valid CWE IDs', () => {
      expect(cweExists(5)).toBe(true);
      expect(cweExists(6)).toBe(true);
    });

    it('should return false for invalid CWE ID', () => {
      expect(cweExists(999999)).toBe(false);
    });
  });

  describe('getAllCweMappings', () => {
    it('should return all mappings', () => {
      const mappings = getAllCweMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBeGreaterThan(0);
    });

    it('should return mappings with correct structure', () => {
      const mappings = getAllCweMappings();
      const firstMapping = mappings[0];
      expect(firstMapping).toHaveProperty('CWE-ID');
      expect(firstMapping).toHaveProperty('CWE Name');
      expect(firstMapping).toHaveProperty('NIST-ID');
      expect(firstMapping).toHaveProperty('Rev');
      expect(firstMapping).toHaveProperty('NIST Name');
    });

    it('should include specific CWE entries', () => {
      const mappings = getAllCweMappings();
      const ids = mappings.map((m) => m['CWE-ID']);
      expect(ids).toContain(5);
      expect(ids).toContain(6);
    });
  });
});
