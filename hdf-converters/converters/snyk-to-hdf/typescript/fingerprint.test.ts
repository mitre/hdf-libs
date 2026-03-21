import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, snykFingerprint } from './fingerprint.js';

const SNYK_FULL = JSON.stringify({
  ok: false,
  vulnerabilities: [
    {
      id: 'SNYK-JS-LODASH-590103',
      title: 'Prototype Pollution',
      description: 'desc',
      severity: 'high',
      identifiers: { CVE: ['CVE-2020-8203'], CWE: ['CWE-400'] },
      from: ['app@1.0.0', 'lodash@4.17.15'],
    },
  ],
  packageManager: 'npm',
  projectName: 'my-app',
});

const SNYK_MINIMAL = JSON.stringify({
  ok: true,
  vulnerabilities: [],
  packageManager: 'pip',
});

const SNYK_NO_PKG_MGR = JSON.stringify({
  ok: false,
  vulnerabilities: [
    { id: 'SNYK-001', title: 'test', description: '', severity: 'low', identifiers: {}, from: [] },
  ],
});

const SNYK_MULTI_PROJECT = JSON.stringify([
  {
    ok: false,
    vulnerabilities: [
      { id: 'SNYK-001', title: 'test', description: '', severity: 'low', identifiers: {}, from: [] },
    ],
    packageManager: 'maven',
  },
]);

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('snyk-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('snyk-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Snyk');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(snykFingerprint.id).toBe('snyk-to-hdf');
    expect(snykFingerprint).not.toHaveProperty('convert');
  });

  it('detects Snyk JSON with packageManager at confidence 1.0', () => {
    const result = detectConverter(SNYK_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('snyk-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects Snyk JSON with empty vulnerabilities and packageManager at confidence 1.0', () => {
    const result = detectConverter(SNYK_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('snyk-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects Snyk JSON without packageManager at confidence 0.5', () => {
    const result = detectConverter(SNYK_NO_PKG_MGR);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('snyk-to-hdf');
    expect(result!.confidence).toBe(0.5);
  });

  it('detects multi-project Snyk array at confidence 1.0', () => {
    const result = detectConverter(SNYK_MULTI_PROJECT);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('snyk-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match random JSON', () => {
    const result = detectConverter(RANDOM_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match null input', () => {
    expect(snykFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('snyk-to-hdf')).toBeDefined();
  });
});
