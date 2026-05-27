import { describe, it, expect } from 'vitest';
import { parseCvssVector, validateCvssVector } from '../src/cvss/index.js';
import { cvssScoreToSeverity } from '../src/severity/index.js';

describe('cvssScoreToSeverity', () => {
  it('returns "none" for 0.0', () => {
    expect(cvssScoreToSeverity(0.0)).toBe('none');
  });

  it('returns "low" for 0.1', () => {
    expect(cvssScoreToSeverity(0.1)).toBe('low');
  });

  it('returns "low" for 3.9', () => {
    expect(cvssScoreToSeverity(3.9)).toBe('low');
  });

  it('returns "medium" for 4.0 (boundary)', () => {
    expect(cvssScoreToSeverity(4.0)).toBe('medium');
  });

  it('returns "medium" for 6.9', () => {
    expect(cvssScoreToSeverity(6.9)).toBe('medium');
  });

  it('returns "high" for 7.0 (boundary)', () => {
    expect(cvssScoreToSeverity(7.0)).toBe('high');
  });

  it('returns "high" for 8.9', () => {
    expect(cvssScoreToSeverity(8.9)).toBe('high');
  });

  it('returns "critical" for 9.0 (boundary)', () => {
    expect(cvssScoreToSeverity(9.0)).toBe('critical');
  });

  it('returns "critical" for 10.0', () => {
    expect(cvssScoreToSeverity(10.0)).toBe('critical');
  });

  it('clamps negative scores to "none"', () => {
    expect(cvssScoreToSeverity(-1)).toBe('none');
  });

  it('clamps scores > 10 to "critical"', () => {
    expect(cvssScoreToSeverity(11.5)).toBe('critical');
  });

  it('treats values just below 0.1 as "none" (band floor)', () => {
    // 0.05 is below the low-band floor of 0.1; FIRST treats only 0.0 as None.
    // Implementation choice: anything <0.1 but >=0 maps to "none" since 0.05
    // is outside the documented low band.
    expect(cvssScoreToSeverity(0.05)).toBe('none');
  });
});

describe('parseCvssVector', () => {
  it('parses a CVSS 3.1 vector', () => {
    const result = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.version).toBe('3.1');
    expect(result.metrics.size).toBe(8);
    expect(result.metrics.get('AV')).toBe('N');
    expect(result.metrics.get('AC')).toBe('L');
    expect(result.metrics.get('PR')).toBe('N');
    expect(result.metrics.get('UI')).toBe('N');
    expect(result.metrics.get('S')).toBe('U');
    expect(result.metrics.get('C')).toBe('H');
    expect(result.metrics.get('I')).toBe('H');
    expect(result.metrics.get('A')).toBe('H');
  });

  it('parses a CVSS 3.0 vector', () => {
    const result = parseCvssVector('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H');
    expect(result.version).toBe('3.0');
    expect(result.metrics.size).toBe(8);
    expect(result.metrics.get('AV')).toBe('L');
  });

  it('parses a CVSS 2.0 legacy vector (no prefix)', () => {
    const result = parseCvssVector('AV:N/AC:L/Au:N/C:N/I:P/A:N');
    expect(result.version).toBe('2.0');
    expect(result.metrics.size).toBe(6);
    expect(result.metrics.get('AV')).toBe('N');
    expect(result.metrics.get('AC')).toBe('L');
    expect(result.metrics.get('Au')).toBe('N');
    expect(result.metrics.get('C')).toBe('N');
    expect(result.metrics.get('I')).toBe('P');
    expect(result.metrics.get('A')).toBe('N');
  });

  it('parses a CVSS 4.0 vector', () => {
    const result = parseCvssVector(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    );
    expect(result.version).toBe('4.0');
    expect(result.metrics.size).toBe(11);
    expect(result.metrics.get('AT')).toBe('N');
    expect(result.metrics.get('VC')).toBe('H');
    expect(result.metrics.get('SA')).toBe('N');
  });

  it('parses vectors with Threat + Environmental tail metrics', () => {
    const result = parseCvssVector(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C/MAV:N/CR:H',
    );
    expect(result.version).toBe('3.1');
    expect(result.metrics.get('E')).toBe('U');
    expect(result.metrics.get('RL')).toBe('O');
    expect(result.metrics.get('RC')).toBe('C');
    expect(result.metrics.get('MAV')).toBe('N');
    expect(result.metrics.get('CR')).toBe('H');
  });

  it('returns version "unknown" with empty metrics for empty string', () => {
    const result = parseCvssVector('');
    expect(result.version).toBe('unknown');
    expect(result.metrics.size).toBe(0);
  });

  it('returns version "unknown" for a string with no slashes or colons', () => {
    const result = parseCvssVector('not a vector');
    expect(result.version).toBe('unknown');
    expect(result.metrics.size).toBe(0);
  });

  it('skips malformed metric segments (dangling colon, no value)', () => {
    const result = parseCvssVector('CVSS:3.1/AV:N/AC:/PR:N');
    expect(result.version).toBe('3.1');
    expect(result.metrics.get('AV')).toBe('N');
    expect(result.metrics.get('PR')).toBe('N');
    expect(result.metrics.has('AC')).toBe(false);
  });

  it('skips empty segments from leading/trailing slashes', () => {
    const result = parseCvssVector('/CVSS:3.1/AV:N/AC:L/');
    expect(result.version).toBe('3.1');
    expect(result.metrics.get('AV')).toBe('N');
    expect(result.metrics.get('AC')).toBe('L');
  });

  it('handles a known v2 metric key (Au is case-sensitive marker)', () => {
    // Validation will ensure correctness; parser is permissive.
    const result = parseCvssVector('CVSS:3.1/UnknownKey:X/AV:N');
    expect(result.metrics.get('UnknownKey')).toBe('X');
    expect(result.metrics.get('AV')).toBe('N');
  });
});

describe('validateCvssVector', () => {
  it('accepts a valid CVSS 3.1 vector', () => {
    const result = validateCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('accepts a valid CVSS 3.0 vector', () => {
    const result = validateCvssVector('CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N');
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('accepts a valid CVSS 2.0 vector', () => {
    const result = validateCvssVector('AV:N/AC:L/Au:N/C:N/I:P/A:N');
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('accepts a valid CVSS 4.0 vector', () => {
    const result = validateCvssVector(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    );
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('flags missing required metric in v3.1 (PR)', () => {
    const result = validateCvssVector('CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H');
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('PR'))).toBe(true);
  });

  it('flags missing required metric in v4 (AT)', () => {
    const result = validateCvssVector(
      'CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('AT'))).toBe(true);
  });

  it('flags missing required metric in v2 (Au)', () => {
    const result = validateCvssVector('AV:N/AC:L/C:N/I:P/A:N');
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Au'))).toBe(true);
  });

  it('flags invalid metric value (AV:Z)', () => {
    const result = validateCvssVector('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('AV') && e.includes('Z'))).toBe(true);
  });

  it('flags invalid value in CVSS 4 (VC:X is not a valid base value)', () => {
    const result = validateCvssVector(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:X/VI:H/VA:H/SC:N/SI:N/SA:N',
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('VC'))).toBe(true);
  });

  it('does not error on unknown metric (forward-compat)', () => {
    const result = validateCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y');
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('accepts explicit version override', () => {
    const result = validateCvssVector('AV:N/AC:L/Au:N/C:N/I:P/A:N', '2.0');
    expect(result.valid).toBe(true);
  });

  it('uses explicit version override even when prefix is present', () => {
    // Forces v3.1 grammar even though vector is v2-shaped; should error on Au.
    const result = validateCvssVector('AV:N/AC:L/Au:N/C:N/I:P/A:N', '3.1');
    expect(result.valid).toBe(false);
  });

  it('errors when version is unknown / unsupported', () => {
    const result = validateCvssVector('CVSS:9.9/AV:N');
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /version/i.test(e))).toBe(true);
  });

  it('errors when vector is empty', () => {
    const result = validateCvssVector('');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('accepts optional Temporal metrics in v3.1 (E:U)', () => {
    const result = validateCvssVector(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C',
    );
    expect(result.valid).toBe(true);
  });

  it('flags invalid temporal value (E:Q)', () => {
    const result = validateCvssVector(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Q',
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('E'))).toBe(true);
  });
});
