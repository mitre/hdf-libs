import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, msftSecureScoreFingerprint } from './fingerprint.js';

const SECURE_SCORE_GOOD = JSON.stringify({
  secureScore: {
    value: [
      {
        id: 'score-001',
        azureTenantId: 'tenant-abc',
        createdDateTime: '2024-01-01T00:00:00Z',
        controlScores: [
          {
            controlCategory: 'Identity',
            controlName: 'MFARegistrationV2',
            description: 'Register MFA',
            score: 9,
            implementationStatus: 'Implemented',
            scoreInPercentage: 100,
          },
        ],
      },
    ],
  },
  profiles: {
    value: [
      { id: 'MFARegistrationV2', title: 'MFA Registration' },
    ],
  },
});

const SECURE_SCORE_EMPTY = JSON.stringify({
  secureScore: { value: [] },
  profiles: { value: [] },
});

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('msft-secure-score-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('msft-secure-score-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Microsoft Secure Score');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(msftSecureScoreFingerprint.id).toBe('msft-secure-score-to-hdf');
    expect(msftSecureScoreFingerprint).not.toHaveProperty('convert');
  });

  it('detects Secure Score JSON at confidence 1.0', () => {
    const result = detectConverter(SECURE_SCORE_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-secure-score-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects empty secureScore/profiles at confidence 0.8', () => {
    const result = detectConverter(SECURE_SCORE_EMPTY);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-secure-score-to-hdf');
    expect(result!.confidence).toBe(0.8);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match random JSON', () => {
    const result = detectConverter(RANDOM_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match null input', () => {
    expect(msftSecureScoreFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('msft-secure-score-to-hdf')).toBeDefined();
  });
});
