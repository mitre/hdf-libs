import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, zapFingerprint } from './fingerprint.js';

const ZAP_FULL = JSON.stringify({
  '@generated': '2024-01-01T00:00:00Z',
  '@version': '2.14.0',
  site: [{ '@host': 'example.com', alerts: [] }],
});

const ZAP_MINIMAL = JSON.stringify({
  site: [{ '@host': 'example.com' }],
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const XML_INPUT = '<?xml version="1.0"?><root><child/></root>';
const EMPTY_INPUT = '';

describe('zap-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('zap-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('OWASP ZAP');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('detects full ZAP JSON at confidence 0.95', () => {
    const result = detectConverter(ZAP_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('zap-to-hdf');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects minimal ZAP JSON at confidence 0.85', () => {
    const result = detectConverter(ZAP_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('zap-to-hdf');
    expect(result!.confidence).toBe(0.85);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match XML input', () => {
    const result = detectConverter(XML_INPUT);
    expect(result).toBeUndefined();
  });

  it('does not match empty input', () => {
    const result = detectConverter(EMPTY_INPUT);
    expect(result).toBeUndefined();
  });

  it('does not match object with non-array site', () => {
    const result = detectConverter(JSON.stringify({ site: 'example.com' }));
    expect(result).toBeUndefined();
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('zap-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(zapFingerprint.id).toBe('zap-to-hdf');
    expect(zapFingerprint).not.toHaveProperty('convert');
  });
});
