import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, trufflehogFingerprint } from './fingerprint.js';

const TRUFFLEHOG_FULL = JSON.stringify({
  SourceMetadata: { Data: { Git: { commit: 'abc123', file: 'config.yml', email: 'dev@example.com', repository: 'https://github.com/org/repo', timestamp: '2024-01-15T10:00:00Z', line: 42 } } },
  SourceID: 1,
  SourceType: 16,
  SourceName: 'trufflehog - git',
  DetectorType: 1,
  DetectorName: 'AWS',
  DecoderName: 'PLAIN',
  Verified: true,
  Raw: 'AKIAIOSFODNN7EXAMPLE',
  Redacted: 'AKIA***EXAMPLE',
});

const TRUFFLEHOG_MINIMAL = JSON.stringify({
  Raw: 'some-secret-value',
  Verified: false,
  DetectorName: 'Generic',
  DecoderName: 'PLAIN',
  Redacted: '***',
});

const TRUFFLEHOG_ARRAY = JSON.stringify([
  { SourceMetadata: { Data: {} }, DetectorName: 'AWS', DecoderName: 'PLAIN', Verified: true, Raw: 'key1', Redacted: '***' },
  { SourceMetadata: { Data: {} }, DetectorName: 'GitHub', DecoderName: 'PLAIN', Verified: false, Raw: 'key2', Redacted: '***' },
]);

const TRUFFLEHOG_RAW_ONLY = JSON.stringify({
  Raw: 'secret-token-123',
  Verified: true,
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const GOSEC_JSON = JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } });

describe('trufflehog-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('trufflehog-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('TruffleHog');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(trufflehogFingerprint.id).toBe('trufflehog-to-hdf');
    expect(trufflehogFingerprint).not.toHaveProperty('convert');
  });

  it('detects full TruffleHog finding at confidence 1.0', () => {
    const result = detectConverter(TRUFFLEHOG_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trufflehog-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects minimal TruffleHog finding (Raw + Verified, no SourceMetadata) at confidence 0.7', () => {
    const result = detectConverterAll(TRUFFLEHOG_MINIMAL)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trufflehog-to-hdf');
    expect(result!.confidence).toBe(0.7);
  });

  it('detects TruffleHog array input', () => {
    const result = detectConverter(TRUFFLEHOG_ARRAY);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trufflehog-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects Raw + Verified (no SourceMetadata) at confidence 0.7', () => {
    const result = detectConverterAll(TRUFFLEHOG_RAW_ONLY)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trufflehog-to-hdf');
    expect(result!.confidence).toBe(0.7);
  });

  it('does not match SARIF JSON', () => {
    expect(detectConverter(SARIF_JSON)).toBeUndefined();
  });

  it('does not match GoSec JSON', () => {
    expect(detectConverter(GOSEC_JSON)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match empty array', () => {
    expect(detectConverter('[]')).toBeUndefined();
  });

  it('does not match XML input', () => {
    expect(detectConverter('<?xml version="1.0"?><root/>')).toBeUndefined();
  });

  it('does not match when Raw is present but Verified is not boolean', () => {
    expect(detectConverter(JSON.stringify({ Raw: 'secret', Verified: 'yes' }))).toBeUndefined();
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('trufflehog-to-hdf')).toBeDefined();
  });
});
