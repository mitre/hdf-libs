import { describe, it, expect, vi } from 'vitest';
import {
  getNiktoNistControl,
  getAllNiktoIds,
  niktoExists,
  getAllNiktoMappings,
} from '../src/nikto/index.js';

describe('Nikto Mapping Functions', () => {
  describe('getNiktoNistControl', () => {
    it('should return NIST control for valid Nikto ID (string)', () => {
      const nistId = getNiktoNistControl('750500');
      expect(nistId).toBe('SI-11');
    });

    it('should return NIST control for valid Nikto ID (number)', () => {
      const nistId = getNiktoNistControl(750500);
      expect(nistId).toBe('SI-11');
    });

    it('should return undefined for invalid Nikto ID', () => {
      const nistId = getNiktoNistControl('999999999');
      expect(nistId).toBeUndefined();
    });

    it('should handle multiple Nikto IDs', () => {
      const nistId1 = getNiktoNistControl('750501');
      const nistId2 = getNiktoNistControl('750502');
      expect(nistId1).toBe('SI-11');
      expect(nistId2).toBe('SI-11');
    });
  });

  describe('getAllNiktoIds', () => {
    it('should return all Nikto IDs', () => {
      const ids = getAllNiktoIds();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(0);
      expect(ids).toContain('750500');
      expect(ids).toContain('750501');
    });

    it('should return IDs as strings', () => {
      const ids = getAllNiktoIds();
      expect(typeof ids[0]).toBe('string');
    });
  });

  describe('niktoExists', () => {
    it('should return true for valid Nikto ID (string)', () => {
      expect(niktoExists('750500')).toBe(true);
      expect(niktoExists('750501')).toBe(true);
    });

    it('should return true for valid Nikto ID (number)', () => {
      expect(niktoExists(750500)).toBe(true);
      expect(niktoExists(750501)).toBe(true);
    });

    it('should return false for invalid Nikto ID', () => {
      expect(niktoExists('999999999')).toBe(false);
      expect(niktoExists(999999999)).toBe(false);
    });
  });

  describe('lazy initialization (cold start)', () => {
    it('loads mappings on first call after module reset', async () => {
      vi.resetModules();
      const { getNiktoNistControl: getFresh } = await import('../src/nikto/index.js');
      expect(getFresh('750500')).toBe('SI-11');
    });
  });

  describe('getAllNiktoMappings', () => {
    it('should return all mappings as object', () => {
      const mappings = getAllNiktoMappings();
      expect(typeof mappings).toBe('object');
      expect(Array.isArray(mappings)).toBe(false);
    });

    it('should return mappings with correct structure', () => {
      const mappings = getAllNiktoMappings();
      expect(mappings['750500']).toBe('SI-11');
      expect(mappings['750501']).toBe('SI-11');
    });

    it('should have many entries', () => {
      const mappings = getAllNiktoMappings();
      const count = Object.keys(mappings).length;
      expect(count).toBeGreaterThan(1000);
    });
  });
});
