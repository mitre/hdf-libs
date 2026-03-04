import { describe, it, expect } from 'vitest';
import { inputChecksum, buildNistCciTags, DEFAULT_STATIC_ANALYSIS_NIST_TAGS, limitArray, extractCWEIDs, validateInputSize, DEFAULT_MAX_INPUT_SIZE, ensureArray } from './converterutil.js';

describe('inputChecksum', () => {
  it('should return a sha256 checksum', async () => {
    const result = await inputChecksum('hello');
    expect(result.algorithm).toBe('sha256');
    expect(result.value).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should produce consistent results for same input', async () => {
    const a = await inputChecksum('test-input');
    const b = await inputChecksum('test-input');
    expect(a.value).toBe(b.value);
  });

  it('should produce different results for different input', async () => {
    const a = await inputChecksum('input-a');
    const b = await inputChecksum('input-b');
    expect(a.value).not.toBe(b.value);
  });

  it('should handle empty input', async () => {
    const result = await inputChecksum('');
    expect(result.algorithm).toBe('sha256');
    expect(result.value).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('buildNistCciTags', () => {
  it('should build tags with nist only when cci is empty', () => {
    const tags = buildNistCciTags(['SA-11', 'RA-5'], []);
    expect(tags).toEqual({ nist: ['SA-11', 'RA-5'] });
    expect(tags).not.toHaveProperty('cci');
  });

  it('should build tags with nist and cci', () => {
    const tags = buildNistCciTags(['SA-11'], ['CCI-001453']);
    expect(tags).toEqual({
      nist: ['SA-11'],
      cci: ['CCI-001453'],
    });
  });

  it('should include extras', () => {
    const tags = buildNistCciTags(['SA-11'], ['CCI-001453'], { cveid: 'CVE-2024-1234' });
    expect(tags).toHaveProperty('cveid', 'CVE-2024-1234');
    expect(tags).toHaveProperty('nist');
    expect(tags).toHaveProperty('cci');
  });

  it('should handle undefined extras', () => {
    const tags = buildNistCciTags(['SA-11'], []);
    expect(Object.keys(tags)).toEqual(['nist']);
  });
});

describe('limitArray', () => {
  it('should return full array when under limit', () => {
    const result = limitArray(['a', 'b', 'c'], 10);
    expect(result.items).toEqual(['a', 'b', 'c']);
    expect(result.truncated).toBe(false);
  });

  it('should truncate when over limit', () => {
    const result = limitArray([1, 2, 3, 4, 5], 3);
    expect(result.items).toEqual([1, 2, 3]);
    expect(result.truncated).toBe(true);
  });

  it('should use default limit when not specified', () => {
    const result = limitArray(['a']);
    expect(result.items).toEqual(['a']);
    expect(result.truncated).toBe(false);
  });

  it('should handle empty array', () => {
    const result = limitArray([], 10);
    expect(result.items).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  it('should handle exact boundary', () => {
    const result = limitArray(['a', 'b', 'c'], 3);
    expect(result.items).toEqual(['a', 'b', 'c']);
    expect(result.truncated).toBe(false);
  });
});

describe('extractCWEIDs', () => {
  it('should extract single CWE-NNN', () => {
    expect(extractCWEIDs('CWE-79')).toEqual(['79']);
  });

  it('should extract multiple CWEs sorted', () => {
    expect(extractCWEIDs('CWE 89 and CWE-79')).toEqual(['79', '89']);
  });

  it('should be case insensitive', () => {
    expect(extractCWEIDs('cwe22')).toEqual(['22']);
  });

  it('should return empty array for no matches', () => {
    expect(extractCWEIDs('no cwe here')).toEqual([]);
  });

  it('should return empty array for empty string', () => {
    expect(extractCWEIDs('')).toEqual([]);
  });

  it('should deduplicate CWE IDs', () => {
    expect(extractCWEIDs('CWE-79, CWE-79')).toEqual(['79']);
  });

  it('should handle mixed formats', () => {
    expect(extractCWEIDs('CWE-79, cwe 89, CWE22')).toEqual(['22', '79', '89']);
  });
});

describe('validateInputSize', () => {
  it('should accept input within limit', () => {
    expect(() => validateInputSize('hello', 'test')).not.toThrow();
  });

  it('should reject input exceeding limit', () => {
    const big = 'x'.repeat(100);
    expect(() => validateInputSize(big, 'test', 50)).toThrow('exceeds maximum');
  });

  it('should use default limit for normal input', () => {
    expect(() => validateInputSize('normal input', 'test')).not.toThrow();
  });

  it('should include converter name in error message', () => {
    const big = 'x'.repeat(100);
    expect(() => validateInputSize(big, 'my-converter', 50)).toThrow('my-converter');
  });

  it('should accept input at exact limit', () => {
    const exact = 'x'.repeat(50);
    expect(() => validateInputSize(exact, 'test', 50)).not.toThrow();
  });

  it('should reject input one character over limit', () => {
    const overByOne = 'x'.repeat(51);
    expect(() => validateInputSize(overByOne, 'test', 50)).toThrow('exceeds maximum');
  });

  it('should export DEFAULT_MAX_INPUT_SIZE as 50MB', () => {
    expect(DEFAULT_MAX_INPUT_SIZE).toBe(50 * 1024 * 1024);
  });
});

describe('ensureArray', () => {
  it('should return empty array for undefined', () => {
    expect(ensureArray(undefined)).toEqual([]);
  });

  it('should return empty array for null', () => {
    expect(ensureArray(null)).toEqual([]);
  });

  it('should wrap a single value in an array', () => {
    expect(ensureArray('hello')).toEqual(['hello']);
  });

  it('should wrap a single object in an array', () => {
    const obj = { key: 'value' };
    expect(ensureArray(obj)).toEqual([obj]);
  });

  it('should return an array unchanged', () => {
    expect(ensureArray([1, 2, 3])).toEqual([1, 2, 3]);
  });

  it('should return an empty array unchanged', () => {
    expect(ensureArray([])).toEqual([]);
  });

  it('should wrap a number in an array', () => {
    expect(ensureArray(42)).toEqual([42]);
  });

  it('should wrap false in an array (not treat as nullish)', () => {
    expect(ensureArray(false)).toEqual([false]);
  });

  it('should wrap zero in an array (not treat as nullish)', () => {
    expect(ensureArray(0)).toEqual([0]);
  });

  it('should wrap empty string in an array (not treat as nullish)', () => {
    expect(ensureArray('')).toEqual(['']);
  });
});

describe('re-exports', () => {
  it('should re-export DEFAULT_STATIC_ANALYSIS_NIST_TAGS', () => {
    expect(DEFAULT_STATIC_ANALYSIS_NIST_TAGS).toBeDefined();
    expect(Array.isArray(DEFAULT_STATIC_ANALYSIS_NIST_TAGS)).toBe(true);
    expect(DEFAULT_STATIC_ANALYSIS_NIST_TAGS).toContain('SA-11');
  });
});
