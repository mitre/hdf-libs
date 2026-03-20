import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, jfrogXrayFingerprint } from './fingerprint.js';

const XRAY_GOOD = JSON.stringify({
  total_count: 2,
  data: [
    { id: 'XRAY-001', severity: 'High', summary: 'CVE-2023-1234' },
    { id: 'XRAY-002', severity: 'Medium', summary: 'CVE-2023-5678' },
  ],
});

const XRAY_EMPTY_DATA = JSON.stringify({
  total_count: 0,
  data: [],
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const RANDOM_JSON = JSON.stringify({ foo: 'bar', baz: 42 });

describe('jfrog-xray-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('jfrog-xray-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('JFrog Xray');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(jfrogXrayFingerprint.id).toBe('jfrog-xray-to-hdf');
    expect(jfrogXrayFingerprint).not.toHaveProperty('convert');
  });

  it('detects JFrog Xray JSON at confidence 1.0', () => {
    const result = detectConverter(XRAY_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('jfrog-xray-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects empty data array at confidence 1.0', () => {
    const result = detectConverter(XRAY_EMPTY_DATA);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('jfrog-xray-to-hdf');
    expect(result!.confidence).toBe(1.0);
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
    expect(jfrogXrayFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('jfrog-xray-to-hdf')).toBeDefined();
  });
});
