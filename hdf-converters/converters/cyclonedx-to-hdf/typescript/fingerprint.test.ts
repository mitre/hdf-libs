import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, cyclonedxFingerprint } from './fingerprint.js';

// Known-good CycloneDX fixture
const CYCLONEDX_BOM = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  metadata: { timestamp: '2024-01-01T00:00:00Z' },
  components: [{ type: 'library', name: 'lodash', version: '4.17.21' }],
  vulnerabilities: [],
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

// Known-bad: Grype format
const GRYPE_JSON = JSON.stringify({
  matches: [],
  source: { target: { userInput: 'alpine:3.14' } },
  descriptor: { name: 'grype', version: '0.62.0' },
});

describe('cyclonedx-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('cyclonedx-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('CycloneDX');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(cyclonedxFingerprint.id).toBe('cyclonedx-to-hdf');
    expect(cyclonedxFingerprint).not.toHaveProperty('convert');
  });

  it('detects CycloneDX BOM at confidence 1.0', () => {
    const result = detectConverter(CYCLONEDX_BOM);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('cyclonedx-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match Grype JSON', () => {
    const result = detectConverter(GRYPE_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(cyclonedxFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(cyclonedxFingerprint.fingerprint('string')).toBe(0);
  });

  it('returns 0 for wrong bomFormat value', () => {
    expect(cyclonedxFingerprint.fingerprint({ bomFormat: 'SPDX' })).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('cyclonedx-to-hdf')).toBeDefined();
  });
});
