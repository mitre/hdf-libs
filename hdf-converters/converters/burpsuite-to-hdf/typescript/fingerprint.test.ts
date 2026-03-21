import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, burpsuiteFingerprint } from './fingerprint.js';

const BURP_XML = '<?xml version="1.0"?><issues burpVersion="2024.1" exportTime="2024-01-01"><issue><serialNumber>1</serialNumber></issue></issues>';
const BURP_MINIMAL = '<?xml version="1.0"?><issues><issue/></issues>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('burpsuite-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('burpsuite-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Burp Suite');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects Burp Suite XML with burpVersion at confidence 1.0', () => {
    const result = detectConverter(BURP_XML);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('burpsuite-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects minimal Burp Suite XML (no burpVersion) at confidence 0.7', () => {
    const result = detectConverter(BURP_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('burpsuite-to-hdf');
    expect(result!.confidence).toBe(0.7);
  });

  it('does not match XML with wrong root element', () => {
    const result = detectConverter(WRONG_ROOT_XML);
    expect(result).toBeUndefined();
  });

  it('does not match JSON input', () => {
    const result = detectConverter(JSON_INPUT);
    expect(result).toBeUndefined();
  });

  it('does not match empty input', () => {
    const result = detectConverter(EMPTY_INPUT);
    expect(result).toBeUndefined();
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('burpsuite-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(burpsuiteFingerprint.id).toBe('burpsuite-to-hdf');
    expect(burpsuiteFingerprint).not.toHaveProperty('convert');
  });
});
