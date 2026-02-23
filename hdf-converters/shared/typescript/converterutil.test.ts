import { describe, it, expect } from 'vitest';
import { inputChecksum, buildNistCciTags, DEFAULT_STATIC_ANALYSIS_NIST_TAGS, limitArray } from './converterutil.js';

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

describe('re-exports', () => {
  it('should re-export DEFAULT_STATIC_ANALYSIS_NIST_TAGS', () => {
    expect(DEFAULT_STATIC_ANALYSIS_NIST_TAGS).toBeDefined();
    expect(Array.isArray(DEFAULT_STATIC_ANALYSIS_NIST_TAGS)).toBe(true);
    expect(DEFAULT_STATIC_ANALYSIS_NIST_TAGS).toContain('SA-11');
  });
});
