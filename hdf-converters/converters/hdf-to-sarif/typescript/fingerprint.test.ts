import { beforeEach, describe, expect, it } from 'vitest';
import { _resetRegistry, getFingerprint, getFingerprints } from '../../../shared/typescript/registry.js';
import { hdfToSarifFingerprint, register } from './fingerprint.js';

const HDF_OBJECT = { baselines: [{ name: 'test', requirements: [] }] };
const SARIF_LOG = { version: '2.1.0', runs: [] };

describe('hdf-to-sarif fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('hdf-to-sarif');
    expect(fp).toBeDefined();
    expect(fp?.label).toBe('HDF to SARIF');
    expect(fp?.direction).toBe('export');
    expect(fp?.inputFamily).toBe('json');
    expect(fp?.outputType).toBe('raw');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(hdfToSarifFingerprint.id).toBe('hdf-to-sarif');
    expect(hdfToSarifFingerprint).not.toHaveProperty('convert');
  });

  it('detects HDF structure at confidence 0.5', () => {
    expect(hdfToSarifFingerprint.fingerprint(HDF_OBJECT)).toBe(0.5);
  });

  it('detects an empty baselines array at confidence 0.5', () => {
    expect(hdfToSarifFingerprint.fingerprint({ baselines: [] })).toBe(0.5);
  });

  it("returns 0 for a SARIF log, which is this converter's output", () => {
    expect(hdfToSarifFingerprint.fingerprint(SARIF_LOG)).toBe(0);
  });

  it.each([
    ['string input', 'some text'],
    ['null', null],
    ['a non-array baselines', { baselines: 'nope' }],
  ])('returns 0 for %s', (_name, input) => {
    expect(hdfToSarifFingerprint.fingerprint(input)).toBe(0);
  });

  it('is marked as export (excluded from ingest detection)', () => {
    expect(getFingerprints().find((d) => d.id === 'hdf-to-sarif')?.direction).toBe('export');
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('hdf-to-sarif')).toBeDefined();
  });
});
