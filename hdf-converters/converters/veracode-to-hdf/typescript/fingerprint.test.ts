import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, veracodeFingerprint } from './fingerprint.js';

const VERACODE_DETAILED = '<?xml version="1.0" encoding="UTF-8"?><detailedreport report_format_version="1.5" app_name="TestApp" build_id="12345"><severity level="5"><category categoryid="18" categoryname="CRLF Injection"/></severity></detailedreport>';

const VERACODE_WITH_NS = '<?xml version="1.0"?><ns:detailedreport xmlns:ns="https://www.veracode.com/schema/reports/export/1.0" app_name="TestApp"/>';

const VERACODE_SUMMARY = '<?xml version="1.0"?><summaryreport app_name="TestApp"><severity level="5"/></summaryreport>';

const JUNIT_XML = '<?xml version="1.0"?><testsuites><testsuite name="s1"><testcase name="t1"/></testsuite></testsuites>';
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('veracode-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('veracode-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Veracode');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('xml');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(veracodeFingerprint.id).toBe('veracode-to-hdf');
    expect(veracodeFingerprint).not.toHaveProperty('convert');
  });

  it('detects Veracode DetailedReport at confidence 1.0', () => {
    const result = detectConverter(VERACODE_DETAILED);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('veracode-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects namespaced detailedreport', () => {
    const result = detectConverter(VERACODE_WITH_NS);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('veracode-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match Veracode summaryreport', () => {
    expect(detectConverter(VERACODE_SUMMARY)).toBeUndefined();
  });

  it('does not match JUnit XML', () => {
    expect(detectConverter(JUNIT_XML)).toBeUndefined();
  });

  it('does not match JSON input', () => {
    expect(detectConverter(SARIF_JSON)).toBeUndefined();
  });

  it('does not match empty string', () => {
    expect(detectConverter('')).toBeUndefined();
  });

  it('does not match plain text', () => {
    expect(detectConverter('just some plain text')).toBeUndefined();
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('veracode-to-hdf')).toBeDefined();
  });
});
