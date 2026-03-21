import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, netsparkerFingerprint } from './fingerprint.js';

const NETSPARKER_XML = '<?xml version="1.0"?><netsparker-enterprise><generated>2024-01-01</generated></netsparker-enterprise>';
const INVICTI_XML = '<?xml version="1.0"?><invicti-enterprise><generated>2024-01-01</generated></invicti-enterprise>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('netsparker-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('netsparker-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Netsparker');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects netsparker-enterprise XML at confidence 1.0', () => {
    const result = detectConverter(NETSPARKER_XML);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('netsparker-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects invicti-enterprise XML at confidence 1.0', () => {
    const result = detectConverter(INVICTI_XML);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('netsparker-to-hdf');
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
    expect(getFingerprint('netsparker-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(netsparkerFingerprint.id).toBe('netsparker-to-hdf');
    expect(netsparkerFingerprint).not.toHaveProperty('convert');
  });
});
