import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  getNISTDescription,
  getAllNISTIds,
  nistExists,
  getNISTFamily,
  DEFAULT_NIST_REVISION,
  SUPPORTED_NIST_REVISIONS,
  getCurrentNistRevision,
  setCurrentNistRevision,
  resetNistRevision,
  isNistStrict,
  setNistStrict,
} from '../src/nist/index.js';

describe('NIST revision selection', () => {
  afterEach(() => {
    resetNistRevision();
  });

  it('defaults to revision 5', () => {
    expect(DEFAULT_NIST_REVISION).toBe(5);
    expect(getCurrentNistRevision()).toBe(5);
  });

  it('lists supported revisions', () => {
    expect([...SUPPORTED_NIST_REVISIONS]).toEqual([4, 5]);
  });

  it('sets a supported revision', () => {
    setCurrentNistRevision(5);
    expect(getCurrentNistRevision()).toBe(5);
  });

  it('rejects an unsupported revision without mutating state', () => {
    expect(() => setCurrentNistRevision(99)).toThrow(/unsupported NIST revision 99/);
    expect(getCurrentNistRevision()).toBe(DEFAULT_NIST_REVISION);
  });

  it('resets to the default revision', () => {
    setCurrentNistRevision(5);
    resetNistRevision();
    expect(getCurrentNistRevision()).toBe(DEFAULT_NIST_REVISION);
  });

  it('toggles strict revision alignment', () => {
    expect(isNistStrict()).toBe(false);
    setNistStrict(true);
    expect(isNistStrict()).toBe(true);
    setNistStrict(false);
    expect(isNistStrict()).toBe(false);
  });
});

describe('NIST Mapping Functions', () => {
  describe('getNISTDescription', () => {
    it('should return description for valid NIST control ID', () => {
      const desc = getNISTDescription('AC-01');
      expect(desc).toBeDefined();
      expect(desc).toBe('ACCESS CONTROL POLICY AND PROCEDURES');
    });

    it('should return description for NIST control sub-parts', () => {
      const desc = getNISTDescription('AC-01 a');
      expect(desc).toBeDefined();
      expect(desc).toContain('Develops, documents, and disseminates');
    });

    it('should return undefined for invalid NIST ID', () => {
      const desc = getNISTDescription('ZZ-999');
      expect(desc).toBeUndefined();
    });

    it('should handle empty string', () => {
      const desc = getNISTDescription('');
      expect(desc).toBeUndefined();
    });

    it('should handle different NIST ID formats', () => {
      expect(getNISTDescription('AC-01')).toBeDefined();
      expect(getNISTDescription('AC-01 a')).toBeDefined();
      expect(getNISTDescription('AC-01 a 01')).toBeDefined();
      expect(getNISTDescription('AC-02')).toBeDefined();
    });
  });

  describe('getAllNISTIds', () => {
    it('should return array of all NIST IDs', () => {
      const ids = getAllNISTIds();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(1600); // We know there are 1682 NIST entries
    });

    it('should include base controls and sub-parts', () => {
      const ids = getAllNISTIds();
      expect(ids).toContain('AC-01');
      expect(ids).toContain('AC-01 a');
      expect(ids).toContain('AC-02');
    });

    it('should return unique NIST IDs', () => {
      const ids = getAllNISTIds();
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('nistExists', () => {
    it('should return true for valid NIST ID', () => {
      expect(nistExists('AC-01')).toBe(true);
    });

    it('should return true for NIST sub-parts', () => {
      expect(nistExists('AC-01 a')).toBe(true);
      expect(nistExists('AC-01 a 01')).toBe(true);
    });

    it('should return false for invalid NIST ID', () => {
      expect(nistExists('ZZ-999')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(nistExists('')).toBe(false);
    });
  });

  describe('getNISTFamily', () => {
    it('should return family for NIST control', () => {
      expect(getNISTFamily('AC-01')).toBe('AC');
      expect(getNISTFamily('AC-02')).toBe('AC');
      expect(getNISTFamily('SI-01')).toBe('SI');
    });

    it('should return family for NIST sub-parts', () => {
      expect(getNISTFamily('AC-01 a')).toBe('AC');
      expect(getNISTFamily('AC-01 a 01')).toBe('AC');
    });

    it('should return undefined for invalid NIST ID', () => {
      expect(getNISTFamily('ZZ-999')).toBeUndefined();
      expect(getNISTFamily('invalid')).toBeUndefined();
      expect(getNISTFamily('')).toBeUndefined();
    });

    it('should handle all common NIST families', () => {
      // Verify the function works for a representative NIST family
      expect(getNISTFamily('AC-01')).toBe('AC');
    });
  });

  describe('type guard: non-string inputs', () => {
    it('getNISTDescription returns undefined for null', () => {
      expect(getNISTDescription(null as unknown as string)).toBeUndefined();
    });

    it('getNISTDescription returns undefined for 0', () => {
      expect(getNISTDescription(0 as unknown as string)).toBeUndefined();
    });

    it('nistExists returns false for null', () => {
      expect(nistExists(null as unknown as string)).toBe(false);
    });

    it('nistExists returns false for false', () => {
      expect(nistExists(false as unknown as string)).toBe(false);
    });
  });

  describe('lazy initialization (cold start)', () => {
    it('loads data on first call after module reset', async () => {
      vi.resetModules();
      const { getNISTDescription: getNISTFresh } = await import('../src/nist/index.js');
      expect(getNISTFresh('AC-01')).toBeDefined();
    });
  });

  describe('getNISTFamily with prefix content', () => {
    it('returns undefined for ID with characters before the control code', () => {
      // The regex uses ^ anchor, so 'prefix-AC-2' should not match
      // (getNISTFamily finds the control in the DB and extracts the family prefix)
      // If AC-2 is not a direct entry prefix, this falls through to undefined
      const family = getNISTFamily('prefix-AC-2');
      expect(family).toBeUndefined();
    });
  });

  describe('Edge cases and error handling', () => {
    it('should return consistent results for same NIST ID', () => {
      const desc1 = getNISTDescription('AC-01');
      const desc2 = getNISTDescription('AC-01');
      expect(desc1).toBe(desc2);
    });

    it('should handle whitespace variations', () => {
      // Our implementation should be strict - only exact matches
      const desc = getNISTDescription('AC-01');
      expect(desc).toBeDefined();

      // These should not match (different format)
      expect(getNISTDescription(' AC-01')).toBeUndefined();
      expect(getNISTDescription('AC-01 ')).toBeUndefined();
    });
  });
});
