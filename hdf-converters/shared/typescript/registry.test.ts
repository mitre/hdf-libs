import { describe, it, expect, beforeEach } from 'vitest';
import {
  registerFingerprint,
  getFingerprints,
  getIngestFingerprints,
  getFingerprint,
  _resetRegistry,
  type ConverterFingerprint,
} from './registry.js';

function makeFP(overrides: Partial<ConverterFingerprint> = {}): ConverterFingerprint {
  return {
    id: 'test-converter',
    label: 'Test',
    direction: 'ingest',
    inputFamily: 'json',
    outputType: 'results',
    fingerprint: () => 1.0,
    ...overrides,
  };
}

describe('registry', () => {
  beforeEach(() => {
    _resetRegistry();
  });

  describe('registerFingerprint', () => {
    it('registers a fingerprint', () => {
      registerFingerprint(makeFP());
      expect(getFingerprints()).toHaveLength(1);
    });

    it('registers multiple fingerprints', () => {
      registerFingerprint(makeFP({ id: 'a' }));
      registerFingerprint(makeFP({ id: 'b' }));
      expect(getFingerprints()).toHaveLength(2);
    });

    it('throws on duplicate ID', () => {
      registerFingerprint(makeFP({ id: 'dup' }));
      expect(() => registerFingerprint(makeFP({ id: 'dup' }))).toThrow(
        'Duplicate fingerprint: dup'
      );
    });
  });

  describe('getFingerprints', () => {
    it('returns empty array when no fingerprints registered', () => {
      expect(getFingerprints()).toHaveLength(0);
    });

    it('returns all registered fingerprints', () => {
      registerFingerprint(makeFP({ id: 'a', direction: 'ingest' }));
      registerFingerprint(makeFP({ id: 'b', direction: 'export' }));
      expect(getFingerprints()).toHaveLength(2);
    });
  });

  describe('getIngestFingerprints', () => {
    it('filters to ingest-only', () => {
      registerFingerprint(makeFP({ id: 'in', direction: 'ingest' }));
      registerFingerprint(makeFP({ id: 'out', direction: 'export' }));
      const ingest = getIngestFingerprints();
      expect(ingest).toHaveLength(1);
      expect(ingest[0].id).toBe('in');
    });
  });

  describe('getFingerprint', () => {
    it('returns fingerprint by ID', () => {
      registerFingerprint(makeFP({ id: 'sarif-to-hdf', label: 'SARIF' }));
      const result = getFingerprint('sarif-to-hdf');
      expect(result).toBeDefined();
      expect(result!.label).toBe('SARIF');
    });

    it('returns undefined for unknown ID', () => {
      expect(getFingerprint('nonexistent')).toBeUndefined();
    });
  });

  describe('outputType', () => {
    it('stores outputType on registered fingerprint', () => {
      registerFingerprint(makeFP({ id: 'oscal-sar', outputType: 'results' }));
      registerFingerprint(makeFP({ id: 'oscal-poam', outputType: 'amendments' }));
      expect(getFingerprint('oscal-sar')!.outputType).toBe('results');
      expect(getFingerprint('oscal-poam')!.outputType).toBe('amendments');
    });
  });

  describe('_resetRegistry', () => {
    it('clears all registered fingerprints', () => {
      registerFingerprint(makeFP({ id: 'a' }));
      registerFingerprint(makeFP({ id: 'b' }));
      expect(getFingerprints()).toHaveLength(2);
      _resetRegistry();
      expect(getFingerprints()).toHaveLength(0);
    });
  });
});
