import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, xccdfFingerprint } from './fingerprint.js';

const XCCDF_BENCHMARK = '<?xml version="1.0"?><Benchmark id="xccdf_test"><title>Test Benchmark</title></Benchmark>';
const ARF_COLLECTION = '<?xml version="1.0"?><asset-report-collection><report-requests/></asset-report-collection>';
const XCCDF_NS_PREFIX = '<?xml version="1.0"?><xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="test"><xccdf:title>Test</xccdf:title></xccdf:Benchmark>';
const WRONG_ROOT_XML = '<?xml version="1.0"?><testsuites><testsuite/></testsuites>';
const JSON_INPUT = JSON.stringify({ version: '2.1.0', runs: [] });
const EMPTY_INPUT = '';

describe('xccdf-results-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('xccdf-results-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('XCCDF/ARF');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('detects XCCDF Benchmark XML at confidence 1.0', () => {
    const result = detectConverter(XCCDF_BENCHMARK);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects ARF asset-report-collection XML at confidence 1.0', () => {
    const result = detectConverter(ARF_COLLECTION);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects XCCDF with namespace prefix (xccdf:Benchmark)', () => {
    const result = detectConverter(XCCDF_NS_PREFIX);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
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
    expect(getFingerprint('xccdf-results-to-hdf')).toBeDefined();
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(xccdfFingerprint.id).toBe('xccdf-results-to-hdf');
    expect(xccdfFingerprint).not.toHaveProperty('convert');
  });
});
