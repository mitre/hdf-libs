import { describe, it, expect } from 'vitest';
import { inputChecksum, buildNistCciTags, DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from './converterutil.js';

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

describe('re-exports', () => {
  it('should re-export DEFAULT_STATIC_ANALYSIS_NIST_TAGS', () => {
    expect(DEFAULT_STATIC_ANALYSIS_NIST_TAGS).toBeDefined();
    expect(Array.isArray(DEFAULT_STATIC_ANALYSIS_NIST_TAGS)).toBe(true);
    expect(DEFAULT_STATIC_ANALYSIS_NIST_TAGS).toContain('SA-11');
  });
});
