import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, msftDefenderCloudFingerprint } from './fingerprint.js';

const DEFENDER_CLOUD_GOOD = JSON.stringify({
  value: [
    {
      id: '/subscriptions/abc/providers/Microsoft.Security/assessments/001',
      name: '001',
      type: 'Microsoft.Security/assessments',
      properties: {
        displayName: 'Enable MFA',
        resourceDetails: { source: 'Azure', id: '/subscriptions/abc' },
        status: { code: 'Unhealthy', cause: '', description: '' },
        metadata: {
          displayName: 'Enable MFA',
          assessmentType: 'BuiltIn',
          policyDefinitionId: '',
          description: 'desc',
          remediationDescription: '',
          categories: [],
          severity: 'High',
          userImpact: 'Moderate',
          implementationEffort: 'Low',
          threats: [],
          tactics: [],
          techniques: [],
        },
      },
    },
  ],
});

const DEFENDER_CLOUD_EMPTY_VALUE = JSON.stringify({ value: [] });

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const RANDOM_JSON = JSON.stringify({ foo: 'bar' });

describe('msft-defender-cloud-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('msft-defender-cloud-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Microsoft Defender for Cloud');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(msftDefenderCloudFingerprint.id).toBe('msft-defender-cloud-to-hdf');
    expect(msftDefenderCloudFingerprint).not.toHaveProperty('convert');
  });

  it('detects Defender for Cloud JSON at confidence 1.0', () => {
    const result = detectConverter(DEFENDER_CLOUD_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-cloud-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects empty value array at confidence 0.5', () => {
    const result = detectConverterAll(DEFENDER_CLOUD_EMPTY_VALUE)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-cloud-to-hdf');
    expect(result!.confidence).toBe(0.5);
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
    expect(msftDefenderCloudFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('msft-defender-cloud-to-hdf')).toBeDefined();
  });
});
