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

  it('registers all 59 fingerprints (46 ingest + 7 OSCAL sub-types + 6 export)', () => {
    registerAllFingerprints();
    // 46 single ingest + 7 OSCAL + 6 export = 59 total
    expect(getFingerprints().length).toBe(59);
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
