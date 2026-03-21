import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, dbprotectFingerprint } from './fingerprint.js';

const DBPROTECT_XML = '<?xml version="1.0"?><dataset><metadata><item><name>col1</name><type>string</type></item></metadata><data><row><value>v1</value></row></data></dataset>';
const DBPROTECT_MINIMAL = '<?xml version="1.0"?><dataset><other/></dataset>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('dbprotect-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('dbprotect-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('DBProtect');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects DBProtect XML with metadata/data at confidence 1.0', () => {
    const result = detectConverter(DBPROTECT_XML);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('dbprotect-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects minimal dataset XML at confidence 0.8', () => {
    const result = detectConverter(DBPROTECT_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('dbprotect-to-hdf');
    expect(result!.confidence).toBe(0.8);
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
    expect(getFingerprint('dbprotect-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(dbprotectFingerprint.id).toBe('dbprotect-to-hdf');
    expect(dbprotectFingerprint).not.toHaveProperty('convert');
  });
});
