import { describe, it, expect, vi } from 'vitest';
import { ControlType, VerificationMethodEnum } from '@mitre/hdf-schema';
import { inputChecksum, buildNistCciTags, limitArray, limitArrayWithWarning, extractCWEIDs, validateInputSize, DEFAULT_MAX_INPUT_SIZE, ensureArray, deriveControlTypeFromTags, deriveVerificationMethod } from './converterutil.js';

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

describe('limitArrayWithWarning', () => {
  it('warns and truncates when items exceed limit', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const result = limitArrayWithWarning([1, 2, 3, 4, 5], 'item', 2);
    expect(result).toEqual([1, 2]);
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]![0]).toContain('truncated at 2 item items (original: 5)');
    warn.mockRestore();
  });

  it('passes through without warning when within limit', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const result = limitArrayWithWarning(['a', 'b'], 'item', 10);
    expect(result).toEqual(['a', 'b']);
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
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

describe('deriveControlTypeFromTags (single tag — exercises internal classification)', () => {
  it.each<[string, ControlType]>([
    ['AC-3', ControlType.Technical],
    ['SC-7', ControlType.Technical],
    ['SI-2', ControlType.Technical],
    ['IA-5', ControlType.Technical],
    ['AC-3(1)', ControlType.Technical],
    ['AC-3.1', ControlType.Technical],
    ['AT-2', ControlType.Operational],
    ['IR-4', ControlType.Operational],
    ['MA-3', ControlType.Operational],
    ['AU-12', ControlType.Operational],
    ['PM-2', ControlType.Management],
    ['CA-2', ControlType.Management],
    ['SR-3', ControlType.Management],
    ['AC-1', ControlType.Policy],
    ['PM-1', ControlType.Policy],
    ['SC-1', ControlType.Policy],
    ['AC-1(1)', ControlType.Policy],
  ])('should classify %s as %s', (tag, expected) => {
    expect(deriveControlTypeFromTags([tag])).toBe(expected);
  });

  it.each<[string]>([
    ['SV-238196'],
    ['CCI-000192'],
    ['XX-9'],
    [''],
    ['AC'],
    ['AC-'],
  ])('should return undefined for non-NIST tag %s', (tag) => {
    expect(deriveControlTypeFromTags([tag])).toBeUndefined();
  });

  it('should normalize case', () => {
    expect(deriveControlTypeFromTags(['ac-3'])).toBe(ControlType.Technical);
  });

  it('should trim whitespace', () => {
    expect(deriveControlTypeFromTags(['  AC-3  '])).toBe(ControlType.Technical);
  });
});

describe('deriveControlTypeFromTags', () => {
  it('returns the single class when one tag', () => {
    expect(deriveControlTypeFromTags(['AC-3'])).toBe(ControlType.Technical);
  });

  it('technical beats management', () => {
    expect(deriveControlTypeFromTags(['PM-2', 'AC-3'])).toBe(ControlType.Technical);
  });

  it('operational beats management', () => {
    expect(deriveControlTypeFromTags(['PM-2', 'AT-2'])).toBe(ControlType.Operational);
  });

  it('technical beats operational', () => {
    expect(deriveControlTypeFromTags(['AT-2', 'AC-3'])).toBe(ControlType.Technical);
  });

  it('technical beats policy', () => {
    expect(deriveControlTypeFromTags(['AC-1', 'SC-7'])).toBe(ControlType.Technical);
  });

  it('ignores unknown families', () => {
    expect(deriveControlTypeFromTags(['SV-12345', 'AC-3'])).toBe(ControlType.Technical);
  });

  it('returns undefined for empty input', () => {
    expect(deriveControlTypeFromTags([])).toBeUndefined();
  });

  it('returns undefined when all tags are unknown', () => {
    expect(deriveControlTypeFromTags(['SV-1', 'CCI-1'])).toBeUndefined();
  });

  it('static-fallback bundle DEFAULT_STATIC_ANALYSIS_NIST_TAGS returns undefined', () => {
    expect(deriveControlTypeFromTags(['SA-11', 'RA-5'])).toBeUndefined();
  });

  it('static-fallback bundle DEFAULT_REMEDIATION_NIST_TAGS returns undefined', () => {
    expect(deriveControlTypeFromTags(['SI-2', 'RA-5'])).toBeUndefined();
  });

  it('static-fallback bundle component-management returns undefined', () => {
    expect(deriveControlTypeFromTags(['CM-8'])).toBeUndefined();
  });

  it('non-fallback superset bypasses the gate (real signal wins)', () => {
    expect(deriveControlTypeFromTags(['SA-11', 'RA-5', 'AC-3'])).toBe(ControlType.Technical);
  });

  it('standalone SA-11 keeps real signal (not the bundle)', () => {
    expect(deriveControlTypeFromTags(['SA-11'])).toBe(ControlType.Management);
  });
});

describe('deriveVerificationMethod', () => {
  it('non-empty code is automated', () => {
    expect(deriveVerificationMethod("control 'AC-3' do; impact 0.7; end"))
      .toBe(VerificationMethodEnum.Automated);
  });

  it('undefined returns undefined', () => {
    expect(deriveVerificationMethod(undefined)).toBeUndefined();
  });

  it('null returns undefined', () => {
    expect(deriveVerificationMethod(null)).toBeUndefined();
  });

  it('empty string returns undefined', () => {
    expect(deriveVerificationMethod('')).toBeUndefined();
  });
});
