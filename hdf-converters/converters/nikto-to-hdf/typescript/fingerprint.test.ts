import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, niktoFingerprint } from './fingerprint.js';

const NIKTO_FULL = JSON.stringify({
  host: '10.0.0.1',
  port: '80',
  banner: 'Apache/2.4',
  vulnerabilities: [{ id: '1', msg: 'test vuln' }],
});

const NIKTO_MINIMAL = JSON.stringify({
  vulnerabilities: [{ id: '1', msg: 'test vuln' }],
});

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const XML_INPUT = '<?xml version="1.0"?><root><child/></root>';
const EMPTY_INPUT = '';

describe('nikto-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('nikto-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Nikto');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('detects full Nikto JSON at confidence 0.95', () => {
    const result = detectConverter(NIKTO_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('nikto-to-hdf');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects minimal Nikto JSON at confidence 0.85', () => {
    const result = detectConverter(NIKTO_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('nikto-to-hdf');
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

  it('does not match object without vulnerabilities array', () => {
    const result = detectConverter(JSON.stringify({ host: '10.0.0.1', findings: [] }));
    expect(result).toBeUndefined();
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('nikto-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(niktoFingerprint.id).toBe('nikto-to-hdf');
    expect(niktoFingerprint).not.toHaveProperty('convert');
  });
});
