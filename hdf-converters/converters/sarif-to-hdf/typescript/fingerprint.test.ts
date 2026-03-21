import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, sarifFingerprint } from './fingerprint.js';

const SARIF_MINIMAL = JSON.stringify({ version: '2.1.0', runs: [] });

const SARIF_WITH_SCHEMA = JSON.stringify({
  $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
  version: '2.1.0',
  runs: [{ tool: { driver: { name: 'eslint' } }, results: [] }],
});

const GOSEC_JSON = JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } });
const JUNIT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';

describe('sarif-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('sarif-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('SARIF');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(sarifFingerprint.id).toBe('sarif-to-hdf');
    expect(sarifFingerprint).not.toHaveProperty('convert');
  });

  it('detects minimal SARIF at confidence 0.9', () => {
    const result = detectConverter(SARIF_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects SARIF with $schema field', () => {
    const result = detectConverter(SARIF_WITH_SCHEMA);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
  });

  it('does not match GoSec JSON', () => {
    expect(detectConverter(GOSEC_JSON)).toBeUndefined();
  });

  it('does not match XML input', () => {
    expect(detectConverter(JUNIT_XML)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match when version is number', () => {
    expect(detectConverter(JSON.stringify({ version: 2, runs: [] }))).toBeUndefined();
  });

  it('does not match when runs is object', () => {
    expect(detectConverter(JSON.stringify({ version: '2.1.0', runs: {} }))).toBeUndefined();
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('sarif-to-hdf')).toBeDefined();
  });
});
