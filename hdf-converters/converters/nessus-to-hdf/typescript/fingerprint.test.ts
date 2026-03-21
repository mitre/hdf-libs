import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, nessusFingerprint } from './fingerprint.js';

const NESSUS_XML = '<?xml version="1.0"?><NessusClientData_v2><Policy><policyName>test</policyName></Policy></NessusClientData_v2>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('nessus-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('nessus-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Nessus');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects Nessus XML at confidence 1.0', () => {
    const result = detectConverter(NESSUS_XML);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('nessus-to-hdf');
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
    expect(getFingerprint('nessus-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(nessusFingerprint.id).toBe('nessus-to-hdf');
    expect(nessusFingerprint).not.toHaveProperty('convert');
  });
});
