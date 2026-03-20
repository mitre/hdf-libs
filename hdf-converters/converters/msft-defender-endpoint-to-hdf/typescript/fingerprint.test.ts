import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, msftDefenderEndpointFingerprint } from './fingerprint.js';

const MDE_GOOD = JSON.stringify({
  '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2',
  value: [
    {
      id: 'alert-001',
      severity: 'high',
      category: 'Malware',
      title: 'Suspicious process',
      description: 'A suspicious process was detected',
      status: 'new',
      evidence: [
        { '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'host1' },
      ],
    },
  ],
});

const MDE_NO_EVIDENCE = JSON.stringify({
  value: [
    {
      id: 'alert-002',
      severity: 'medium',
      category: 'Lateral Movement',
      title: 'test',
      description: 'desc',
      status: 'new',
    },
  ],
});

const DEFENDER_CLOUD = JSON.stringify({
  value: [
    {
      id: '/subscriptions/abc',
      name: '001',
      properties: { displayName: 'Enable MFA' },
    },
  ],
});

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });

describe('msft-defender-endpoint-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('msft-defender-endpoint-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Microsoft Defender for Endpoint');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(msftDefenderEndpointFingerprint.id).toBe('msft-defender-endpoint-to-hdf');
    expect(msftDefenderEndpointFingerprint).not.toHaveProperty('convert');
  });

  it('detects MDE alert JSON at confidence 1.0', () => {
    const result = detectConverter(MDE_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-endpoint-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match MDE-like JSON without evidence array', () => {
    const result = detectConverter(MDE_NO_EVIDENCE);
    expect(result).toBeUndefined();
  });

  it('does not match Defender for Cloud JSON', () => {
    const result = detectConverter(DEFENDER_CLOUD);
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
    expect(msftDefenderEndpointFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('msft-defender-endpoint-to-hdf')).toBeDefined();
  });
});
