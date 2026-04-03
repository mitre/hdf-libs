import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, oscalFingerprints } from './fingerprint.js';

const OSCAL_SSP = JSON.stringify({ 'system-security-plan': { uuid: 'ssp-1', metadata: {} } });
const OSCAL_SAP = JSON.stringify({ 'assessment-plan': { uuid: 'sap-1', metadata: {} } });
const OSCAL_SAR = JSON.stringify({ 'assessment-results': { uuid: 'sar-1', metadata: {} } });
const OSCAL_POAM = JSON.stringify({ 'plan-of-action-and-milestones': { uuid: 'poam-1', metadata: {} } });
const OSCAL_PROFILE = JSON.stringify({ profile: { uuid: 'prof-1', metadata: {} } });
const OSCAL_CATALOG = JSON.stringify({ catalog: { uuid: 'cat-1', metadata: {} } });
const OSCAL_COMPONENT = JSON.stringify({ 'component-definition': { uuid: 'comp-1', metadata: {} } });

const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });
const PLAIN_JSON = JSON.stringify({ name: 'test', items: [] });

describe('oscal-to-hdf fingerprints', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('registers all 7 OSCAL fingerprints', () => {
    expect(oscalFingerprints).toHaveLength(7);
    expect(getFingerprint('oscal-ssp-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-sap-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-sar-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-poam-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-profile-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-catalog-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-component-to-hdf')).toBeDefined();
  });

  it('all fingerprints have direction ingest and inputFamily json', () => {
    for (const fp of oscalFingerprints) {
      expect(fp.direction).toBe('ingest');
      expect(fp.inputFamily).toBe('json');
    }
  });

  // SSP
  it('detects OSCAL SSP at confidence 1.0 with outputType raw', () => {
    const result = detectConverter(OSCAL_SSP);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-ssp-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('raw');
  });

  // SAP
  it('detects OSCAL SAP at confidence 1.0 with outputType plan', () => {
    const result = detectConverter(OSCAL_SAP);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-sap-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('plan');
  });

  // SAR
  it('detects OSCAL SAR at confidence 1.0 with outputType results', () => {
    const result = detectConverter(OSCAL_SAR);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-sar-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('results');
  });

  // POA&M
  it('detects OSCAL POA&M at confidence 1.0 with outputType amendments', () => {
    const result = detectConverter(OSCAL_POAM);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-poam-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('amendments');
  });

  // Profile
  it('detects OSCAL Profile at confidence 1.0 with outputType baseline', () => {
    const result = detectConverter(OSCAL_PROFILE);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-profile-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('baseline');
  });

  // Catalog
  it('detects OSCAL Catalog at confidence 1.0 with outputType baseline', () => {
    const result = detectConverter(OSCAL_CATALOG);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-catalog-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('baseline');
  });

  // Component Definition
  it('detects OSCAL Component Definition at confidence 1.0 with outputType baseline', () => {
    const result = detectConverter(OSCAL_COMPONENT);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('oscal-component-to-hdf');
    expect(result!.confidence).toBe(1.0);
    expect(result!.fingerprint.outputType).toBe('baseline');
  });

  // Negative cases
  it('does not match SARIF JSON', () => {
    expect(detectConverter(SARIF_JSON)).toBeUndefined();
  });

  it('does not match plain JSON object', () => {
    expect(detectConverter(PLAIN_JSON)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match array input', () => {
    expect(detectConverter('[]')).toBeUndefined();
  });

  it('does not match XML input', () => {
    expect(detectConverter('<?xml version="1.0"?><catalog/>')).toBeUndefined();
  });

  it('each OSCAL type matches exactly one fingerprint', () => {
    const inputs = [OSCAL_SSP, OSCAL_SAP, OSCAL_SAR, OSCAL_POAM, OSCAL_PROFILE, OSCAL_CATALOG, OSCAL_COMPONENT];
    for (const input of inputs) {
      const results = detectConverterAll(input);
      expect(results).toHaveLength(1);
      expect(results[0]!.confidence).toBe(1.0);
    }
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('oscal-ssp-to-hdf')).toBeDefined();
    expect(getFingerprint('oscal-catalog-to-hdf')).toBeDefined();
  });

  describe('version detection', () => {
    it('detects oscal-version from SAR metadata', () => {
      const sarWithVersion = JSON.stringify({
        'assessment-results': { uuid: 'sar-1', metadata: { 'oscal-version': '1.0.4', title: 'Test' } },
      });
      const result = detectConverter(sarWithVersion);
      expect(result).toBeDefined();
      expect(result!.fingerprint.id).toBe('oscal-sar-to-hdf');
      expect(result!.version).toBe('1.0.4');
    });

    it('detects oscal-version from catalog metadata', () => {
      const catWithVersion = JSON.stringify({
        catalog: { uuid: 'cat-1', metadata: { 'oscal-version': '1.1.3', title: 'NIST 800-53' } },
      });
      const result = detectConverter(catWithVersion);
      expect(result).toBeDefined();
      expect(result!.version).toBe('1.1.3');
    });

    it('returns empty version when metadata has no oscal-version', () => {
      const result = detectConverter(OSCAL_SSP);
      expect(result).toBeDefined();
      expect(result!.version).toBe('');
    });

    it('returns empty version when metadata is missing', () => {
      const noMeta = JSON.stringify({ catalog: { uuid: 'cat-1' } });
      const result = detectConverter(noMeta);
      expect(result).toBeDefined();
      expect(result!.version).toBe('');
    });
  });
});
