import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprints, getFingerprint } from './registry.js';
import { registerAllFingerprints } from './register-all.js';

describe('registerAllFingerprints', () => {
  beforeEach(() => {
    _resetRegistry();
  });

  it('registers the SARIF fingerprint', () => {
    registerAllFingerprints();
    const sarif = getFingerprint('sarif-to-hdf');
    expect(sarif).toBeDefined();
    expect(sarif!.label).toBe('SARIF');
    expect(sarif!.outputType).toBe('results');
  });

  it('registers at least one fingerprint', () => {
    registerAllFingerprints();
    expect(getFingerprints().length).toBeGreaterThanOrEqual(1);
  });

  it('is idempotent — calling twice does not duplicate', () => {
    registerAllFingerprints();
    const countFirst = getFingerprints().length;
    registerAllFingerprints();
    const countSecond = getFingerprints().length;
    expect(countSecond).toBe(countFirst);
  });

  it('works after registry reset + re-call', () => {
    registerAllFingerprints();
    expect(getFingerprints().length).toBeGreaterThanOrEqual(1);
    _resetRegistry();
    expect(getFingerprints()).toHaveLength(0);
    registerAllFingerprints();
    expect(getFingerprints().length).toBeGreaterThanOrEqual(1);
  });
});
