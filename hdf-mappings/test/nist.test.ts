import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  getNISTDescription,
  getAllNISTIds,
  nistExists,
  normalizeNistId,
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
    it('should return description for valid NIST control ID (Rev 5 default)', () => {
      const desc = getNISTDescription('AC-01');
      expect(desc).toBeDefined();
      expect(desc).toBe('Policy and Procedures');
    });

    it('should return description for NIST control sub-parts (Rev 5 default)', () => {
      const desc = getNISTDescription('AC-01 a');
      expect(desc).toBeDefined();
      expect(desc).toContain('Develop, document, and disseminate');
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

    it('accepts the unpadded and parenthesized spellings nistExists accepts', () => {
      expect(getNISTDescription('AC-2', 5)).toBe(getNISTDescription('AC-02', 5));
      expect(getNISTDescription('AC-2 (3)', 5)).toBe(getNISTDescription('AC-02 03', 5));
      expect(getNISTDescription('AC-2(3)', 5)).toBeDefined();
    });
  });

  describe('getAllNISTIds', () => {
    it('should return array of all NIST IDs', () => {
      const ids = getAllNISTIds();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(1600); // full 800-53 catalog at the default revision
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

    it('accepts the unpadded and parenthesized spellings HDF uses', () => {
      expect(nistExists('AC-2', 5)).toBe(true);
      expect(nistExists('AC-2(3)', 5)).toBe(true);
      expect(nistExists('AC-2 (3)', 5)).toBe(true);
      expect(nistExists('SV-230221', 5)).toBe(false);
    });
  });

  // The Go peer (go/nist/exists_test.go) asserts this same table, which is what
  // keeps the two normalizers agreeing on every spelling.
  describe('NIST id spelling (shared case table)', () => {
    interface SpellingCase {
      input: string;
      normalized: string | null;
      exists: Record<string, boolean>;
      why: string;
    }

    const casesPath = join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      'go',
      'nist',
      'testdata',
      'nist-id-spelling-cases.json'
    );
    const { cases } = JSON.parse(readFileSync(casesPath, 'utf-8')) as { cases: SpellingCase[] };

    it('has cases, each with a result for every supported revision', () => {
      expect(cases.length).toBeGreaterThan(0);
      for (const c of cases) {
        expect(Object.keys(c.exists).map(Number).sort()).toEqual([...SUPPORTED_NIST_REVISIONS]);
      }
    });

    it.each(cases.map((c) => [c.input, c.normalized, c.why] as const))(
      'normalizeNistId(%j) is %j',
      (input, normalized, why) => {
        expect(normalizeNistId(input), why).toBe(normalized ?? undefined);
      }
    );

    it.each(
      cases.flatMap((c) =>
        Object.entries(c.exists).map(([rev, exists]) => [c.input, Number(rev), exists, c.why] as const)
      )
    )('nistExists(%j, %d) is %s', (input, rev, exists, why) => {
      expect(nistExists(input, rev), why).toBe(exists);
    });

    it.each(
      cases.flatMap((c) =>
        Object.entries(c.exists).map(
          ([rev, exists]) => [c.input, Number(rev), exists, c.normalized, c.why] as const
        )
      )
    )('getNISTDescription(%j, %d) is defined: %s', (input, rev, exists, normalized, why) => {
      const desc = getNISTDescription(input, rev);
      if (exists) {
        expect(typeof desc, why).toBe('string');
        expect(desc, why).toBe(getNISTDescription(normalized!, rev));
      } else {
        expect(desc, why).toBeUndefined();
      }
    });

    it('accepts every description key at its revision, and each key normalizes to itself', () => {
      for (const rev of SUPPORTED_NIST_REVISIONS) {
        const ids = getAllNISTIds(rev);
        expect(ids.length).toBeGreaterThan(0);
        for (const id of ids) {
          expect(nistExists(id, rev), `${id} at Rev ${rev}`).toBe(true);
          expect(normalizeNistId(id)).toBe(id);
        }
      }
    });

    it('uses the default revision data for an unsupported revision', () => {
      expect(nistExists('SR-3', 99)).toBe(nistExists('SR-3', DEFAULT_NIST_REVISION));
    });

    it('normalizeNistId returns undefined for non-string input', () => {
      expect(normalizeNistId(null as unknown as string)).toBeUndefined();
      expect(normalizeNistId(3 as unknown as string)).toBeUndefined();
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

  describe('revision-aware descriptions', () => {
    afterEach(() => {
      resetNistRevision();
    });

    it('returns the revision-specific title for a renamed control', () => {
      expect(getNISTDescription('AC-01', 4)).toBe('ACCESS CONTROL POLICY AND PROCEDURES');
      expect(getNISTDescription('AC-01', 5)).toBe('Policy and Procedures');
    });

    it('resolves a Rev 5-only family (SR) at Rev 5 but not Rev 4', () => {
      expect(getNISTDescription('SR-01', 5)).toBeDefined();
      expect(getNISTDescription('SR-01', 4)).toBeUndefined();
      expect(nistExists('SR-01', 5)).toBe(true);
      expect(nistExists('SR-01', 4)).toBe(false);
      expect(getNISTFamily('SR-01', 5)).toBe('SR');
      expect(getNISTFamily('SR-01', 4)).toBeUndefined();
    });

    it('resolves a Rev 4 control withdrawn in Rev 5 (IR-10) at Rev 4 but not Rev 5', () => {
      expect(getNISTDescription('IR-10', 4)).toBeDefined();
      expect(getNISTDescription('IR-10', 5)).toBeUndefined();
    });

    it('honors the module-global revision when no explicit rev is passed', () => {
      expect(getNISTDescription('AC-01')).toBe('Policy and Procedures'); // default Rev 5
      setCurrentNistRevision(4);
      expect(getNISTDescription('AC-01')).toBe('ACCESS CONTROL POLICY AND PROCEDURES');
      expect(nistExists('SR-01')).toBe(false); // SR family absent at Rev 4
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
