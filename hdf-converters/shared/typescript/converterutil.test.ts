import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi } from 'vitest';
import { ControlType, Ecosystem, VerificationMethodEnum } from '@mitre/hdf-schema';
import { buildAffectedPackage, defaultOverrideExpiry, oscalSeverityFromHdf, ecosystemFromPurlType, inputChecksum, buildNistCciTags, limitArray, limitArrayWithWarning, extractCWEIDs, validateInputSize, DEFAULT_MAX_INPUT_SIZE, ensureArray, deriveControlTypeFromTags, deriveVerificationMethod, buildHdfResults, buildNoFindingsRequirement, digestToChecksums, markUnratedSeverity, firstNonEmpty, requireHdfResults, requireHdfAmendments, parseSeverity } from './converterutil.js';
import { DEFAULT_MAX_INPUT_SIZE as UTIL_DEFAULT_MAX_INPUT_SIZE } from '@mitre/hdf-utilities';

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

describe('buildHdfResults timestamp serialization', () => {
  const baseOpts = (timestamp: Date, startTime: Date) => ({
    generatorName: 'test-to-hdf',
    converterVersion: '1.0.0',
    timestamp,
    baselines: [
      {
        name: 'test',
        requirements: [buildNoFindingsRequirement('TEST-1', 'clean', startTime)],
      },
    ],
  });

  it('serializes a whole-second startTime/timestamp as trimmed-UTC (no .000)', () => {
    const doc = JSON.parse(
      buildHdfResults(baseOpts(new Date('2024-11-15T10:30:00Z'), new Date('2024-11-15T10:30:00Z'))),
    );
    expect(doc.timestamp).toBe('2024-11-15T10:30:00Z');
    expect(doc.baselines[0].requirements[0].results[0].startTime).toBe('2024-11-15T10:30:00Z');
  });

  it('trims trailing fractional zeros to match Go RFC3339Nano', () => {
    const doc = JSON.parse(
      buildHdfResults(baseOpts(new Date('2024-11-15T10:30:00.120Z'), new Date('2024-11-15T10:30:00.100Z'))),
    );
    expect(doc.timestamp).toBe('2024-11-15T10:30:00.12Z');
    expect(doc.baselines[0].requirements[0].results[0].startTime).toBe('2024-11-15T10:30:00.1Z');
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

  it('should treat a non-positive limit as the default (Go ValidateJSONSize parity)', () => {
    // 0 and negative mean "use the default" — never reject all non-empty input.
    expect(() => validateInputSize('normal input', 'test', 0)).not.toThrow();
    expect(() => validateInputSize('normal input', 'test', -1)).not.toThrow();
  });

  it('should export DEFAULT_MAX_INPUT_SIZE as 50MB', () => {
    expect(DEFAULT_MAX_INPUT_SIZE).toBe(50 * 1024 * 1024);
  });

  it('is the @mitre/hdf-utilities guard: one limit, measured in UTF-8 bytes like Go', () => {
    expect(DEFAULT_MAX_INPUT_SIZE).toBe(UTIL_DEFAULT_MAX_INPUT_SIZE);
    // 30 code units but 60 UTF-8 bytes: over a 50-byte limit for Go's []byte length.
    const multibyte = 'é'.repeat(30);
    expect(() => validateInputSize(multibyte, 'test', 50)).toThrow('test: input exceeds maximum allowed size of 50 bytes (60 bytes provided)');
    expect(() => validateInputSize(multibyte, 'test', 60)).not.toThrow();
  });
});

describe('parseSeverity', () => {
  it('maps the HDF severity vocabulary case-insensitively', () => {
    expect(parseSeverity('critical')).toBe('critical');
    expect(parseSeverity('High')).toBe('high');
    expect(parseSeverity('MEDIUM')).toBe('medium');
    expect(parseSeverity('low')).toBe('low');
    expect(parseSeverity('informational')).toBe('informational');
  });

  it('returns undefined for anything outside the vocabulary', () => {
    // Callers own whitespace handling; scanner vocabulary that is not an HDF
    // severity (XCCDF info/unknown) stays rejected.
    for (const raw of ['wibble', '', ' high', 'info', 'unknown', 'constructor']) {
      expect(parseSeverity(raw), raw).toBeUndefined();
    }
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

describe('ecosystemFromPurlType', () => {
  it.each([
    ['npm', Ecosystem.Npm],
    ['pypi', Ecosystem.Pypi],
    ['rpm', Ecosystem.RPM],
    ['deb', Ecosystem.Deb],
    ['maven', Ecosystem.Maven],
    ['gem', Ecosystem.Gem],
    ['nuget', Ecosystem.Nuget],
    ['golang', Ecosystem.Go],
    ['go', Ecosystem.Go],
    ['cargo', Ecosystem.Cargo],
  ])('maps %s to its Ecosystem enum value', (type, expected) => {
    expect(ecosystemFromPurlType(type)).toBe(expected);
  });

  it('lowercases input before lookup', () => {
    expect(ecosystemFromPurlType('NPM')).toBe(Ecosystem.Npm);
  });

  it.each([undefined, '', 'apk', 'unknown-type'])(
    'returns generic for unrecognised input %s',
    (input) => {
      expect(ecosystemFromPurlType(input)).toBe(Ecosystem.Generic);
    },
  );
});

describe('buildAffectedPackage', () => {
  it('builds an entry from a purl alone', () => {
    expect(buildAffectedPackage({ purl: 'pkg:npm/lodash@4.17.20' })).toEqual({
      purl: 'pkg:npm/lodash@4.17.20',
    });
  });

  it('builds an entry from a cpe alone', () => {
    expect(buildAffectedPackage({ cpe: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*' }))
      .toEqual({ cpe: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*' });
  });

  it('builds an entry from the full name+version+ecosystem triple', () => {
    expect(
      buildAffectedPackage({ name: 'openssl', version: '1.1.1k', ecosystem: Ecosystem.RPM }),
    ).toEqual({ name: 'openssl', version: '1.1.1k', ecosystem: 'rpm' });
  });

  it('includes fixedInVersion when provided', () => {
    expect(
      buildAffectedPackage({ purl: 'pkg:npm/x@1.0', fixedInVersion: '2.0' }),
    ).toEqual({ purl: 'pkg:npm/x@1.0', fixedInVersion: '2.0' });
  });

  it('returns undefined when only a partial triple and no identifier is provided', () => {
    expect(buildAffectedPackage({ name: 'openssl' })).toBeUndefined();
    expect(buildAffectedPackage({ name: 'openssl', version: '1.0' })).toBeUndefined();
    expect(buildAffectedPackage({ name: 'openssl', ecosystem: Ecosystem.Generic })).toBeUndefined();
    expect(buildAffectedPackage({})).toBeUndefined();
  });

  it('treats empty strings as missing', () => {
    expect(
      buildAffectedPackage({ name: '', version: '', ecosystem: Ecosystem.Generic, purl: '' }),
    ).toBeUndefined();
  });
});

describe('digestToChecksums', () => {
  it.each([
    ['sha256:abc', [{ algorithm: 'sha256', value: 'abc' }]],
    ['sha384:abc', [{ algorithm: 'sha384', value: 'abc' }]],
    ['sha512:deadbeef', [{ algorithm: 'sha512', value: 'deadbeef' }]],
    ['blake3:abc', [{ algorithm: 'blake3', value: 'abc' }]],
  ])('labels %s by its algorithm prefix', (digest, want) => {
    expect(digestToChecksums(digest as string)).toEqual(want);
  });

  it.each(['sha1:abc', 'md5:abc', 'abc123', ''])(
    'drops the unrepresentable/prefixless digest %s rather than mislabeling it',
    (digest) => {
      expect(digestToChecksums(digest)).toBeUndefined();
    },
  );
});

describe('markUnratedSeverity', () => {
  it('tags an unrated severity', () => {
    for (const sev of [undefined, null, '', 'unknown', 'UNASSIGNED', 'unSpecified']) {
      const tags: Record<string, unknown> = {nist: ['RA-5']};
      markUnratedSeverity(tags, sev);
      expect(tags.severity_rating, String(sev)).toBe('unrated');
    }
  });

  it('leaves rated severities untagged', () => {
    for (const sev of ['critical', 'low', 'info', 'none', 'negligible', 'wibble']) {
      const tags: Record<string, unknown> = {};
      markUnratedSeverity(tags, sev);
      expect(tags, sev).not.toHaveProperty('severity_rating');
    }
  });
});

// The helper is implemented twice, so the vectors live in one shared file both
// languages read — an inline copy here could drift from Go's without failing.
const FIRST_NON_EMPTY_CASES = (
  JSON.parse(
    readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'first-non-empty-cases.json'), 'utf-8'),
  ) as { cases: Array<{ name: string; candidates: string[]; want: string }> }
).cases;

describe('firstNonEmpty — shared non-empty-text fallback', () => {
  it('has a populated shared table', () => {
    expect(FIRST_NON_EMPTY_CASES.length).toBeGreaterThan(0);
  });

  for (const tc of FIRST_NON_EMPTY_CASES) {
    it(tc.name, () => {
      expect(firstNonEmpty(...tc.candidates)).toBe(tc.want);
    });
  }
});

describe('requireHdfResults / requireHdfAmendments — structural input guard', () => {
  it('rejects empty, non-JSON, top-level array, null, and missing/wrong-typed baselines', () => {
    expect(() => requireHdfResults('', 'test-conv')).toThrow('test-conv: empty input');
    expect(() => requireHdfResults('not json', 'test-conv')).toThrow();
    // A parsed null must NOT throw a TypeError — it falls through to the
    // canonical missing-field error, matching Go's nil-map no-op behavior.
    for (const input of ['[1,2]', 'null', '{}', '{"foo":1}', '{"baselines":"x"}']) {
      expect(() => requireHdfResults(input, 'test-conv')).toThrow(
        'test-conv: invalid HDF structure: missing baselines field',
      );
    }
  });

  it('accepts a valid results doc and returns the doc plus its baselines', () => {
    const { doc, items } = requireHdfResults(
      '{"baselines":[{"name":"b"}],"timestamp":"2020-01-01T00:00:00Z"}',
      'test-conv',
    );
    expect(items).toHaveLength(1);
    expect(doc.timestamp).toBe('2020-01-01T00:00:00Z');
  });

  it('amendments variant is keyed on overrides', () => {
    for (const input of ['{}', 'null', '{"overrides":5}']) {
      expect(() => requireHdfAmendments(input, 'test-conv')).toThrow(
        'test-conv: invalid HDF structure: missing overrides field',
      );
    }
    const { items } = requireHdfAmendments('{"overrides":[{"type":"waiver"}]}', 'test-conv');
    expect(items).toHaveLength(1);
  });
});

describe('defaultOverrideExpiry', () => {
  it('adds a calendar year, not 365 days, across a leap day', () => {
    const appliedAt = new Date(Date.UTC(2027, 2, 1, 12, 0, 0));
    expect(defaultOverrideExpiry(appliedAt).toISOString()).toBe('2028-03-01T12:00:00.000Z');
  });

  it('adds the year in UTC so the result does not depend on the host timezone', () => {
    // 2026-01-01T04:00:00Z is 2025-12-31 locally west of UTC; a local-time
    // rollover would land on 2026-12-31 there and 2027-01-01 elsewhere.
    const appliedAt = new Date(Date.UTC(2026, 0, 1, 4, 0, 0));
    expect(defaultOverrideExpiry(appliedAt).toISOString()).toBe('2027-01-01T04:00:00.000Z');
  });

  it('does not mutate the input', () => {
    const appliedAt = new Date(Date.UTC(2026, 5, 15, 0, 0, 0));
    defaultOverrideExpiry(appliedAt);
    expect(appliedAt.toISOString()).toBe('2026-06-15T00:00:00.000Z');
  });
});

describe('oscalSeverityFromHdf', () => {
  it('renames the HDF bands OSCAL spells differently and rejects the rest', () => {
    expect(oscalSeverityFromHdf('critical')).toBe('critical');
    expect(oscalSeverityFromHdf('high')).toBe('high');
    expect(oscalSeverityFromHdf('medium')).toBe('moderate');
    expect(oscalSeverityFromHdf('low')).toBe('low');
    expect(oscalSeverityFromHdf('informational')).toBe('info');
    expect(oscalSeverityFromHdf('')).toBe('');
    expect(oscalSeverityFromHdf('bogus')).toBe('');
    expect(oscalSeverityFromHdf('constructor')).toBe('');
  });
});
