import { describe, it, expect } from 'vitest';
import { CVSSSeverity, Version as CvssVersion } from '@mitre/hdf-schema';
import { cvssVersionFromVector, cvssVersionFromString, cvssSeverityFromScore, buildCvss } from './cvss.js';

describe('cvssVersionFromVector', () => {
  it('maps recognized prefixes to the schema Version enum', () => {
    expect(cvssVersionFromVector('CVSS:2.0/AV:N/AC:L')).toBe(CvssVersion.The20);
    expect(cvssVersionFromVector('CVSS:3.0/AV:N/AC:L')).toBe(CvssVersion.The30);
    expect(cvssVersionFromVector('CVSS:4.0/AV:N/AC:L')).toBe(CvssVersion.The40);
  });

  it('defaults to 3.1 for the 3.1 prefix, empty, undefined, and unprefixed vectors', () => {
    expect(cvssVersionFromVector('CVSS:3.1/AV:N/AC:L')).toBe(CvssVersion.The31);
    expect(cvssVersionFromVector('')).toBe(CvssVersion.The31);
    expect(cvssVersionFromVector(undefined)).toBe(CvssVersion.The31);
    expect(cvssVersionFromVector('AV:N/AC:L')).toBe(CvssVersion.The31);
  });

  it('uses a caller-supplied default for absent/unrecognized prefixes; a recognized prefix wins', () => {
    // Nessus historical output defaults to 3.0.
    expect(cvssVersionFromVector('', CvssVersion.The30)).toBe(CvssVersion.The30);
    expect(cvssVersionFromVector('AV:N/AC:L', CvssVersion.The30)).toBe(CvssVersion.The30);
    expect(cvssVersionFromVector('CVSS:3.1/AV:N', CvssVersion.The30)).toBe(CvssVersion.The31);
    expect(cvssVersionFromVector('CVSS:3.0/AV:N', CvssVersion.The30)).toBe(CvssVersion.The30);
  });
});

describe('cvssVersionFromString', () => {
  it('maps recognized version numbers to the schema Version enum', () => {
    expect(cvssVersionFromString('2.0')).toBe(CvssVersion.The20);
    expect(cvssVersionFromString('3.0')).toBe(CvssVersion.The30);
    expect(cvssVersionFromString('4.0')).toBe(CvssVersion.The40);
  });

  it('defaults to 3.1 for 3.1, empty, undefined, and unrecognized values', () => {
    expect(cvssVersionFromString('3.1')).toBe(CvssVersion.The31);
    expect(cvssVersionFromString('')).toBe(CvssVersion.The31);
    expect(cvssVersionFromString(undefined)).toBe(CvssVersion.The31);
    expect(cvssVersionFromString('9.9')).toBe(CvssVersion.The31);
  });
});

describe('cvssSeverityFromScore', () => {
  it('maps scores to the correct band across every threshold', () => {
    expect(cvssSeverityFromScore(0.0)).toBe(CVSSSeverity.None);
    expect(cvssSeverityFromScore(0.1)).toBe(CVSSSeverity.Low);
    expect(cvssSeverityFromScore(3.9)).toBe(CVSSSeverity.Low);
    expect(cvssSeverityFromScore(4.0)).toBe(CVSSSeverity.Medium);
    expect(cvssSeverityFromScore(6.9)).toBe(CVSSSeverity.Medium);
    expect(cvssSeverityFromScore(7.0)).toBe(CVSSSeverity.High);
    expect(cvssSeverityFromScore(8.9)).toBe(CVSSSeverity.High);
    expect(cvssSeverityFromScore(9.0)).toBe(CVSSSeverity.Critical);
    expect(cvssSeverityFromScore(10.0)).toBe(CVSSSeverity.Critical);
  });
});

describe('buildCvss', () => {
  it('assembles all base fields when present', () => {
    const cv = buildCvss({
      version: CvssVersion.The31,
      baseScore: 9.8,
      baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      source: 'CVE-2021-44228',
    });
    expect(cv.version).toBe(CvssVersion.The31);
    expect(cv.baseScore).toBe(9.8);
    expect(cv.baseSeverity).toBe(CVSSSeverity.Critical);
    expect(cv.baseVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(cv.source).toBe('CVE-2021-44228');
  });

  it('emits a 0.0 baseScore (with none severity) but omits an empty vector/source', () => {
    const cv = buildCvss({version: CvssVersion.The20, baseScore: 0.0});
    expect(cv.version).toBe(CvssVersion.The20);
    expect(cv.baseScore).toBe(0.0);
    expect(cv.baseSeverity).toBe(CVSSSeverity.None);
    expect(cv.baseVector).toBeUndefined();
    expect(cv.source).toBeUndefined();
  });

  it('omits baseScore/baseSeverity when the score is absent or non-finite', () => {
    const nullScore = buildCvss({version: CvssVersion.The40, baseVector: 'CVSS:4.0/AV:N/AC:L', baseScore: null});
    expect(nullScore.baseScore).toBeUndefined();
    expect(nullScore.baseSeverity).toBeUndefined();
    expect(nullScore.baseVector).toBe('CVSS:4.0/AV:N/AC:L');

    const nanScore = buildCvss({version: CvssVersion.The31, baseScore: Number.NaN});
    expect(nanScore.baseScore).toBeUndefined();
    expect(nanScore.baseSeverity).toBeUndefined();
  });

  it('omits empty baseVector and source (empty string is falsy)', () => {
    const cv = buildCvss({version: CvssVersion.The31, baseScore: 5.0, baseVector: '', source: ''});
    expect(cv.baseVector).toBeUndefined();
    expect(cv.source).toBeUndefined();
    expect(cv.baseScore).toBe(5.0);
  });

  it('emits only version when all optional fields are omitted', () => {
    const cv = buildCvss({version: CvssVersion.The31});
    expect(cv.version).toBe(CvssVersion.The31);
    expect(cv.baseScore).toBeUndefined();
    expect(cv.baseSeverity).toBeUndefined();
    expect(cv.baseVector).toBeUndefined();
    expect(cv.source).toBeUndefined();
  });
});
