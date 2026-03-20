import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, junitFingerprint } from './fingerprint.js';

const JUNIT_TESTSUITES = '<?xml version="1.0"?><testsuites><testsuite name="suite1"><testcase name="test1"/></testsuite></testsuites>';
const JUNIT_TESTSUITE = '<?xml version="1.0"?><testsuite name="suite1"><testcase name="test1"/></testsuite>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><Benchmark id="test"><title>Test</title></Benchmark>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('junit-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('junit-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('JUnit');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects testsuites root at confidence 1.0', () => {
    const result = detectConverter(JUNIT_TESTSUITES);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('junit-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects testsuite root at confidence 1.0', () => {
    const result = detectConverter(JUNIT_TESTSUITE);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('junit-to-hdf');
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
    expect(getFingerprint('junit-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(junitFingerprint.id).toBe('junit-to-hdf');
    expect(junitFingerprint).not.toHaveProperty('convert');
  });
});
