import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, hdfV2Fingerprint } from './fingerprint.js';

const HDF_V2_MINIMAL = JSON.stringify({
  baselines: [{ name: 'test-baseline', requirements: [] }],
});

const HDF_V2_FULL = JSON.stringify({
  baselines: [
    {
      name: 'my-scan',
      title: 'My Security Scan',
      requirements: [
        { id: 'V-12345', title: 'Test Control', impact: 0.7, results: [{ status: 'passed' }] },
      ],
    },
  ],
  generator: { name: 'hdf-converters', version: '1.0.0' },
  targets: [{ name: 'test-host', type: 'host' }],
  timestamp: '2024-01-15T10:00:00Z',
});

const HDF_V1 = JSON.stringify({
  version: '1.0.0',
  platform: { name: 'ubuntu', release: '20.04' },
  profiles: [{ name: 'test', controls: [] }],
  statistics: {},
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('hdf-v2-passthrough fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('hdf-v2-passthrough');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('HDF v2');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(hdfV2Fingerprint.id).toBe('hdf-v2-passthrough');
    expect(hdfV2Fingerprint).not.toHaveProperty('convert');
  });

  it('detects minimal HDF v2 at confidence 0.8', () => {
    const result = detectConverter(HDF_V2_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('hdf-v2-passthrough');
    expect(result!.confidence).toBe(0.8);
  });

  it('detects full HDF v2 at confidence 0.8', () => {
    const result = detectConverter(HDF_V2_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('hdf-v2-passthrough');
    expect(result!.confidence).toBe(0.8);
  });

  it('does not match HDF v1 (profiles[], not baselines[])', () => {
    expect(detectConverter(HDF_V1)).toBeUndefined();
  });

  it('does not match SARIF JSON', () => {
    expect(detectConverter(SARIF_JSON)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match array input', () => {
    expect(detectConverter('[]')).toBeUndefined();
  });

  it('does not match XML input', () => {
    expect(detectConverter('<?xml version="1.0"?><root/>')).toBeUndefined();
  });

  it('does not match when baselines is not an array', () => {
    expect(detectConverter(JSON.stringify({ baselines: 'invalid' }))).toBeUndefined();
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('hdf-v2-passthrough')).toBeDefined();
  });
});
