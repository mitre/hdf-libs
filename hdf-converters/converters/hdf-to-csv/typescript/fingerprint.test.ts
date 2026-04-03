import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint, getFingerprints } from '../../../shared/typescript/registry.js';
import { register, hdfToCsvFingerprint } from './fingerprint.js';

const HDF_OBJECT = { baselines: [{ name: 'test', requirements: [] }] };
const HDF_EMPTY_BASELINES = { baselines: [] };
const NON_HDF_OBJECT = { version: '2.1.0', runs: [] };
const PLAIN_STRING = 'hello world';

describe('hdf-to-csv fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('hdf-to-csv');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('HDF to CSV');
    expect(fp!.direction).toBe('export');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('raw');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(hdfToCsvFingerprint.id).toBe('hdf-to-csv');
    expect(hdfToCsvFingerprint).not.toHaveProperty('convert');
  });

  it('detects HDF structure at confidence 0.5', () => {
    const confidence = hdfToCsvFingerprint.fingerprint(HDF_OBJECT);
    expect(confidence).toBe(0.5);
  });

  it('detects empty baselines array at confidence 0.5', () => {
    const confidence = hdfToCsvFingerprint.fingerprint(HDF_EMPTY_BASELINES);
    expect(confidence).toBe(0.5);
  });

  it('returns 0 for non-HDF JSON object', () => {
    const confidence = hdfToCsvFingerprint.fingerprint(NON_HDF_OBJECT);
    expect(confidence).toBe(0);
  });

  it('returns 0 for string input', () => {
    const confidence = hdfToCsvFingerprint.fingerprint(PLAIN_STRING);
    expect(confidence).toBe(0);
  });

  it('returns 0 for null', () => {
    const confidence = hdfToCsvFingerprint.fingerprint(null);
    expect(confidence).toBe(0);
  });

  it('returns 0 when baselines is not an array', () => {
    const confidence = hdfToCsvFingerprint.fingerprint({ baselines: 'not-array' });
    expect(confidence).toBe(0);
  });

  it('is marked as export (excluded from ingest detection)', () => {
    const all = getFingerprints();
    const fp = all.find(d => d.id === 'hdf-to-csv');
    expect(fp).toBeDefined();
    expect(fp!.direction).toBe('export');
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('hdf-to-csv')).toBeDefined();
  });
});
