import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, grypeFingerprint } from './fingerprint.js';

// Known-good Grype fixture: matches + source + descriptor
const GRYPE_FULL = JSON.stringify({
  matches: [
    {
      vulnerability: {
        id: 'CVE-2021-44228',
        severity: 'Critical',
        description: 'Log4Shell',
      },
      matchDetails: [{ type: 'exact-direct-match', matcher: 'java-matcher' }],
      artifact: { name: 'log4j-core', version: '2.14.1', type: 'java-archive' },
    },
  ],
  source: { target: { userInput: 'docker:myimage:latest' } },
  descriptor: { name: 'grype', version: '0.62.0' },
});

// Partial Grype: descriptor.name === 'grype' but no source
const GRYPE_DESCRIPTOR_ONLY = JSON.stringify({
  matches: [],
  descriptor: { name: 'grype', version: '0.60.0' },
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

// Known-bad: GoSec format
const GOSEC_JSON = JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } });

describe('grype-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('grype-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Grype');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(grypeFingerprint.id).toBe('grype-to-hdf');
    expect(grypeFingerprint).not.toHaveProperty('convert');
  });

  it('detects full Grype report at confidence 1.0', () => {
    const result = detectConverter(GRYPE_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('grype-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects Grype with descriptor.name at confidence 0.8', () => {
    const result = detectConverter(GRYPE_DESCRIPTOR_ONLY);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('grype-to-hdf');
    expect(result!.confidence).toBe(0.8);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match GoSec JSON', () => {
    const result = detectConverter(GOSEC_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(grypeFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(grypeFingerprint.fingerprint('string')).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('grype-to-hdf')).toBeDefined();
  });
});
