import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, gosecFingerprint } from './fingerprint.js';

// Known-good GoSec fixture: full report with GosecVersion + Issues + Stats
const GOSEC_FULL = JSON.stringify({
  GosecVersion: '2.18.2',
  Issues: [
    {
      severity: 'HIGH',
      confidence: 'HIGH',
      cwe: { id: '326', url: 'https://cwe.mitre.org/data/definitions/326.html' },
      rule_id: 'G101',
      details: 'Potential hardcoded credentials',
      file: '/path/to/file.go',
      code: 'password := "secret"',
      line: '10',
      column: '5',
      nosec: false,
      suppressions: null,
    },
  ],
  Stats: { files: 10, lines: 500, nosec: 0, found: 1 },
});

// Partial GoSec: Issues + Stats but no GosecVersion
const GOSEC_NO_VERSION = JSON.stringify({
  Issues: [
    {
      severity: 'MEDIUM',
      rule_id: 'G201',
      details: 'SQL string concatenation',
      file: '/path/to/db.go',
    },
  ],
  Stats: { files: 5, lines: 200, nosec: 0, found: 1 },
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

// Known-bad: CycloneDX format
const CYCLONEDX_JSON = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5' });

describe('gosec-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('gosec-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('GoSec');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(gosecFingerprint.id).toBe('gosec-to-hdf');
    expect(gosecFingerprint).not.toHaveProperty('convert');
  });

  it('detects full GoSec report at confidence 1.0', () => {
    const result = detectConverter(GOSEC_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gosec-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects GoSec without version at confidence 0.6', () => {
    const result = detectConverterAll(GOSEC_NO_VERSION)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gosec-to-hdf');
    expect(result!.confidence).toBe(0.6);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match CycloneDX JSON', () => {
    const result = detectConverter(CYCLONEDX_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(gosecFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(gosecFingerprint.fingerprint('string')).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('gosec-to-hdf')).toBeDefined();
  });
});
