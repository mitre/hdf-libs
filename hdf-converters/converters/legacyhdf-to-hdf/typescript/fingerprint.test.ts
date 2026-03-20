import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, legacyHdfFingerprint } from './fingerprint.js';

const HDF_V1_FULL = JSON.stringify({
  version: '1.0.0',
  platform: { name: 'ubuntu', release: '20.04', target_id: '' },
  profiles: [
    {
      name: 'inspec-profile',
      version: '1.2.3',
      title: 'My Profile',
      controls: [
        { id: 'V-12345', title: 'Test Control', impact: 0.7, results: [{ status: 'passed', code_desc: 'test' }] },
      ],
    },
  ],
  statistics: { duration: 5.2 },
});

const HDF_V1_MINIMAL = JSON.stringify({
  version: '0.1.0',
  platform: { name: 'unknown' },
  profiles: [],
  statistics: {},
});

const HDF_V2 = JSON.stringify({
  baselines: [{ name: 'test-baseline', requirements: [] }],
  generator: { name: 'hdf-converters', version: '1.0.0' },
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('legacyhdf-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('legacyhdf-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('HDF v1 (Legacy)');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(legacyHdfFingerprint.id).toBe('legacyhdf-to-hdf');
    expect(legacyHdfFingerprint).not.toHaveProperty('convert');
  });

  it('detects full HDF v1 at confidence 1.0', () => {
    const result = detectConverter(HDF_V1_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('legacyhdf-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects minimal HDF v1 at confidence 1.0', () => {
    const result = detectConverter(HDF_V1_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('legacyhdf-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match HDF v2 (has baselines[], not profiles[])', () => {
    expect(detectConverter(HDF_V2)).toBeUndefined();
  });

  it('does not match SARIF JSON (has version but no profiles)', () => {
    expect(detectConverter(SARIF_JSON)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match when platform is null', () => {
    expect(detectConverter(JSON.stringify({ version: '1.0', profiles: [], platform: null }))).toBeUndefined();
  });

  it('does not match when profiles is not array', () => {
    expect(detectConverter(JSON.stringify({ version: '1.0', profiles: {}, platform: { name: 'x' } }))).toBeUndefined();
  });

  it('does not match when version is not string', () => {
    expect(detectConverter(JSON.stringify({ version: 1, profiles: [], platform: { name: 'x' } }))).toBeUndefined();
  });

  it('does not match object with both baselines and profiles (baselines takes precedence)', () => {
    const hybrid = JSON.stringify({
      version: '1.0',
      platform: { name: 'test' },
      profiles: [],
      baselines: [],
    });
    // baselines[] present -> excluded by fingerprint (v2, not v1)
    expect(detectConverter(hybrid)).toBeUndefined();
  });

  it('does not match XML input', () => {
    expect(detectConverter('<?xml version="1.0"?><root/>')).toBeUndefined();
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('legacyhdf-to-hdf')).toBeDefined();
  });
});
