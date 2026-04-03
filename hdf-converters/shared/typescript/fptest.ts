/**
 * Shared fingerprint test runner.
 *
 * Each converter defines a FingerprintSpec and calls runFingerprintTests
 * to get standard metadata, positive detection, and negative rejection tests.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint, type ConverterFingerprint } from './registry.js';
import { detectConverter, detectConverterAll } from './fingerprint.js';

export interface DetectionCase {
  /** Test name */
  name: string;
  /** JSON string input for detection */
  input: string;
  /** Expected confidence (0 for negative cases) */
  confidence: number;
}

export interface FingerprintSpec {
  /** Fingerprint ID, e.g. 'gosec-to-hdf' */
  id: string;
  /** Human-readable label, e.g. 'GoSec' */
  label: string;
  /** Expected direction */
  direction: 'ingest' | 'export';
  /** Expected input family */
  inputFamily: 'json' | 'xml' | 'csv' | 'text';
  /** Expected output type */
  outputType: string;
  /** The fingerprint object (for direct function tests) */
  fingerprint: ConverterFingerprint;
  /** Function that registers the fingerprint */
  register: () => void;
  /** Inputs that should match with the given confidence */
  positive: DetectionCase[];
  /** Inputs that should not match */
  negative: DetectionCase[];
}

/**
 * Run a standard suite of fingerprint tests from a spec.
 */
export function runFingerprintTests(spec: FingerprintSpec): void {
  describe(`${spec.id} fingerprint`, () => {
    beforeEach(() => {
      _resetRegistry();
      spec.register();
    });

    it('is registered with correct metadata', () => {
      const fp = getFingerprint(spec.id);
      expect(fp).toBeDefined();
      expect(fp!.label).toBe(spec.label);
      expect(fp!.direction).toBe(spec.direction);
      expect(fp!.inputFamily).toBe(spec.inputFamily);
      expect(fp!.outputType).toBe(spec.outputType);
    });

    it('exports fingerprint as data (no convert function)', () => {
      expect(spec.fingerprint.id).toBe(spec.id);
      expect(spec.fingerprint).not.toHaveProperty('convert');
    });

    for (const tc of spec.positive) {
      it(tc.name, () => {
        if (tc.confidence >= 0.8) {
          const result = detectConverter(tc.input);
          expect(result).toBeDefined();
          expect(result!.fingerprint.id).toBe(spec.id);
          expect(result!.confidence).toBe(tc.confidence);
        } else {
          const results = detectConverterAll(tc.input);
          const match = results.find(r => r.fingerprint.id === spec.id);
          expect(match).toBeDefined();
          expect(match!.confidence).toBe(tc.confidence);
        }
      });
    }

    for (const tc of spec.negative) {
      it(tc.name, () => {
        const result = detectConverter(tc.input);
        if (result) {
          expect(result.fingerprint.id).not.toBe(spec.id);
        }
      });
    }

    it('returns 0 for empty object', () => {
      expect(detectConverter('{}')).toBeUndefined();
    });

    it('returns 0 for null input', () => {
      expect(spec.fingerprint.fingerprint(null)).toBe(0);
    });

    it('returns 0 for non-object input', () => {
      expect(spec.fingerprint.fingerprint('string')).toBe(0);
    });

    it('register is idempotent', () => {
      spec.register();
      expect(getFingerprint(spec.id)).toBeDefined();
    });
  });
}
