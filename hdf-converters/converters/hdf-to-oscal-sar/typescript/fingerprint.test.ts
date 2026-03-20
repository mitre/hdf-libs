import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint, getFingerprints } from '../../../shared/typescript/registry.js';
import { register, hdfToOscalSarFingerprint } from './fingerprint.js';

const HDF_OBJECT = { baselines: [{ name: 'test', requirements: [] }] };
const HDF_EMPTY_BASELINES = { baselines: [] };
const OSCAL_SAR_OBJECT = { 'assessment-results': { uuid: 'abc', metadata: {} } };

describe('hdf-to-oscal-sar fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('hdf-to-oscal-sar');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('HDF to OSCAL SAR');
    expect(fp!.direction).toBe('export');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('raw');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(hdfToOscalSarFingerprint.id).toBe('hdf-to-oscal-sar');
    expect(hdfToOscalSarFingerprint).not.toHaveProperty('convert');
  });

  it('detects HDF structure at confidence 0.5', () => {
    const confidence = hdfToOscalSarFingerprint.fingerprint(HDF_OBJECT);
    expect(confidence).toBe(0.5);
  });

  it('detects empty baselines array at confidence 0.5', () => {
    const confidence = hdfToOscalSarFingerprint.fingerprint(HDF_EMPTY_BASELINES);
    expect(confidence).toBe(0.5);
  });

  it('returns 0 for OSCAL SAR output (not HDF input)', () => {
    const confidence = hdfToOscalSarFingerprint.fingerprint(OSCAL_SAR_OBJECT);
    expect(confidence).toBe(0);
  });

  it('returns 0 for string input', () => {
    const confidence = hdfToOscalSarFingerprint.fingerprint('some text');
    expect(confidence).toBe(0);
  });

  it('returns 0 for null', () => {
    const confidence = hdfToOscalSarFingerprint.fingerprint(null);
    expect(confidence).toBe(0);
  });

  it('returns 0 when baselines is not an array', () => {
    const confidence = hdfToOscalSarFingerprint.fingerprint({ baselines: 'nope' });
    expect(confidence).toBe(0);
  });

  it('is marked as export (excluded from ingest detection)', () => {
    const all = getFingerprints();
    const fp = all.find(d => d.id === 'hdf-to-oscal-sar');
    expect(fp).toBeDefined();
    expect(fp!.direction).toBe('export');
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('hdf-to-oscal-sar')).toBeDefined();
  });
});
