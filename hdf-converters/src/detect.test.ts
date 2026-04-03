/**
 * Tests for the @mitre/hdf-converters/detect sub-path export.
 * Verifies that consumers can import detection functions from this path.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  detectConverter,
  detectConverterAll,
  detectFamily,
  registerAllFingerprints,
  type DetectionResult,
} from './detect.js';
import { _resetRegistry } from '../shared/typescript/registry.js';

describe('@mitre/hdf-converters/detect entry point', () => {
  beforeEach(() => {
    _resetRegistry();
  });

  it('exports detectConverter function', () => {
    expect(typeof detectConverter).toBe('function');
  });

  it('exports detectConverterAll function', () => {
    expect(typeof detectConverterAll).toBe('function');
  });

  it('exports detectFamily function', () => {
    expect(typeof detectFamily).toBe('function');
  });

  it('exports registerAllFingerprints function', () => {
    expect(typeof registerAllFingerprints).toBe('function');
  });

  it('detectConverter works after registerAllFingerprints', () => {
    registerAllFingerprints();
    const sarif = JSON.stringify({ version: '2.1.0', runs: [] });
    const result = detectConverter(sarif);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
  });

  it('detectConverter returns undefined without registration', () => {
    const sarif = JSON.stringify({ version: '2.1.0', runs: [] });
    expect(detectConverter(sarif)).toBeUndefined();
  });
});
