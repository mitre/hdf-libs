import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, fortifyFingerprint } from './fingerprint.js';

const FORTIFY_XML = '<?xml version="1.0"?><FVDL xmlns="xmlns.fortify.com/schema/fvdl"><CreatedTS date="2024-01-01"/></FVDL>';
const FORTIFY_MINIMAL = '<?xml version="1.0"?><FVDL><Vulnerabilities/></FVDL>';
const FORTIFY_NS_PREFIX = '<?xml version="1.0"?><f:FVDL xmlns:f="xmlns.fortify.com/schema/fvdl"><f:CreatedTS/></f:FVDL>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('fortify-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('fortify-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Fortify');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects Fortify FVDL with namespace at confidence 1.0', () => {
    const result = detectConverter(FORTIFY_XML);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('fortify-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects Fortify FVDL without namespace at confidence 0.95', () => {
    const result = detectConverter(FORTIFY_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('fortify-to-hdf');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Fortify FVDL with namespace prefix', () => {
    const result = detectConverter(FORTIFY_NS_PREFIX);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('fortify-to-hdf');
    expect(result!.confidence).toBe(1.0);
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
    expect(getFingerprint('fortify-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(fortifyFingerprint.id).toBe('fortify-to-hdf');
    expect(fortifyFingerprint).not.toHaveProperty('convert');
  });
});
