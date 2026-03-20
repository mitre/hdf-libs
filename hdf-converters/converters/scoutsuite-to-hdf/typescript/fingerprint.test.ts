import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, scoutsuiteFingerprint } from './fingerprint.js';

const SCOUTSUITE_GOOD = JSON.stringify({
  account_id: '123456789012',
  last_run: {
    ruleset_name: 'default',
    time: '2024-01-01T00:00:00Z',
    version: '5.13.0',
  },
  provider_name: 'aws',
  services: {
    iam: {
      findings: {
        'iam-no-support-role': {
          checked_items: 1,
          flagged_items: 1,
          description: 'No support role',
          items: [],
          level: 'danger',
          rationale: 'Create a support role',
        },
      },
    },
  },
});

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('scoutsuite-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('scoutsuite-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('ScoutSuite');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(scoutsuiteFingerprint.id).toBe('scoutsuite-to-hdf');
    expect(scoutsuiteFingerprint).not.toHaveProperty('convert');
  });

  it('detects ScoutSuite JSON at confidence 1.0', () => {
    const result = detectConverter(SCOUTSUITE_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('scoutsuite-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match when services is an array', () => {
    const arrayServices = JSON.stringify({
      services: ['iam'],
      last_run: { time: '2024-01-01' },
    });
    const result = detectConverter(arrayServices);
    expect(result === undefined || result.fingerprint.id !== 'scoutsuite-to-hdf').toBe(true);
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
    expect(scoutsuiteFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('scoutsuite-to-hdf')).toBeDefined();
  });
});
