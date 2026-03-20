import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, twistlockFingerprint } from './fingerprint.js';

const TWISTLOCK_CONTAINER = JSON.stringify({
  results: [
    {
      id: 'sha256:abc123',
      name: 'my-image:latest',
      complianceDistribution: { critical: 0, high: 2, medium: 5, low: 3, total: 10 },
      vulnerabilityDistribution: { critical: 1, high: 3, medium: 7, low: 2, total: 13 },
      vulnerabilities: [{ id: 'CVE-2024-1234', severity: 'high', description: 'test vuln' }],
    },
  ],
  consoleURL: 'https://prisma.example.com',
});

const TWISTLOCK_VULN_ONLY = JSON.stringify({
  results: [
    {
      id: 'sha256:def456',
      vulnerabilityDistribution: { critical: 0, high: 1, medium: 2, low: 0, total: 3 },
    },
  ],
});

const TWISTLOCK_CODE_REPO = JSON.stringify({
  complianceDistribution: { critical: 0, high: 0, medium: 1, low: 2, total: 3 },
  vulnerabilities: [],
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const TRUFFLEHOG_JSON = JSON.stringify({ DetectorName: 'AWS', SourceMetadata: {}, Raw: 'key', Verified: true, Redacted: '***' });

describe('twistlock-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('twistlock-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Twistlock');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(twistlockFingerprint.id).toBe('twistlock-to-hdf');
    expect(twistlockFingerprint).not.toHaveProperty('convert');
  });

  it('detects container scan with complianceDistribution at confidence 1.0', () => {
    const result = detectConverter(TWISTLOCK_CONTAINER);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('twistlock-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects scan with vulnerabilityDistribution only at confidence 0.9', () => {
    const result = detectConverter(TWISTLOCK_VULN_ONLY);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('twistlock-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects code repo scan (single result, no wrapper) at confidence 1.0', () => {
    const result = detectConverter(TWISTLOCK_CODE_REPO);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('twistlock-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match SARIF JSON', () => {
    expect(detectConverter(SARIF_JSON)).toBeUndefined();
  });

  it('does not match TruffleHog JSON', () => {
    expect(detectConverter(TRUFFLEHOG_JSON)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match object with empty results array', () => {
    expect(detectConverter(JSON.stringify({ results: [] }))).toBeUndefined();
  });

  it('does not match array input', () => {
    expect(detectConverter(JSON.stringify([{ complianceDistribution: {} }]))).toBeUndefined();
  });

  it('does not match XML input', () => {
    expect(detectConverter('<?xml version="1.0"?><results/>')).toBeUndefined();
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('twistlock-to-hdf')).toBeDefined();
  });
});
