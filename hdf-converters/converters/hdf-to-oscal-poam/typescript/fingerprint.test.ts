import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint, getFingerprints } from '../../../shared/typescript/registry.js';
import { register, hdfToOscalPoamFingerprint } from './fingerprint.js';

const HDF_OBJECT = { baselines: [{ name: 'test', requirements: [] }] };
const HDF_EMPTY_BASELINES = { baselines: [] };
const OSCAL_POAM_OBJECT = { 'plan-of-action-and-milestones': { uuid: 'abc', metadata: {} } };

describe('hdf-to-oscal-poam fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('hdf-to-oscal-poam');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('HDF to OSCAL POA&M');
    expect(fp!.direction).toBe('export');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('raw');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(hdfToOscalPoamFingerprint.id).toBe('hdf-to-oscal-poam');
    expect(hdfToOscalPoamFingerprint).not.toHaveProperty('convert');
  });

  it('detects HDF structure at confidence 0.5', () => {
    const confidence = hdfToOscalPoamFingerprint.fingerprint(HDF_OBJECT);
    expect(confidence).toBe(0.5);
  });

  it('detects empty baselines array at confidence 0.5', () => {
    const confidence = hdfToOscalPoamFingerprint.fingerprint(HDF_EMPTY_BASELINES);
    expect(confidence).toBe(0.5);
  });

  it('returns 0 for OSCAL POA&M output (not HDF input)', () => {
    const confidence = hdfToOscalPoamFingerprint.fingerprint(OSCAL_POAM_OBJECT);
    expect(confidence).toBe(0);
  });

  it('returns 0 for string input', () => {
    const confidence = hdfToOscalPoamFingerprint.fingerprint('some text');
    expect(confidence).toBe(0);
  });

  it('returns 0 for null', () => {
    const confidence = hdfToOscalPoamFingerprint.fingerprint(null);
    expect(confidence).toBe(0);
  });

  it('returns 0 when baselines is not an array', () => {
    const confidence = hdfToOscalPoamFingerprint.fingerprint({ baselines: 42 });
    expect(confidence).toBe(0);
  });

  it('is marked as export (excluded from ingest detection)', () => {
    const all = getFingerprints();
    const fp = all.find(d => d.id === 'hdf-to-oscal-poam');
    expect(fp).toBeDefined();
    expect(fp!.direction).toBe('export');
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('hdf-to-oscal-poam')).toBeDefined();
  });
});
