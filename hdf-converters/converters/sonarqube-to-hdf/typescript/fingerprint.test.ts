import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, sonarqubeFingerprint } from './fingerprint.js';

const SONARQUBE_GOOD = JSON.stringify({
  total: 1,
  p: 1,
  ps: 100,
  paging: { pageIndex: 1, pageSize: 100, total: 1 },
  issues: [
    {
      key: 'issue-001',
      rule: 'java:S1135',
      severity: 'MAJOR',
      component: 'com.example:app:src/Main.java',
      project: 'com.example:app',
      status: 'OPEN',
      message: 'Complete the task associated to this TODO comment.',
      creationDate: '2024-01-01T00:00:00+0000',
      updateDate: '2024-01-01T00:00:00+0000',
      type: 'CODE_SMELL',
    },
  ],
});

const SONARQUBE_EMPTY_ISSUES = JSON.stringify({
  total: 0,
  issues: [],
});

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('sonarqube-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('sonarqube-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('SonarQube');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(sonarqubeFingerprint.id).toBe('sonarqube-to-hdf');
    expect(sonarqubeFingerprint).not.toHaveProperty('convert');
  });

  it('detects SonarQube JSON at confidence 1.0', () => {
    const result = detectConverter(SONARQUBE_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sonarqube-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects SonarQube with empty issues at confidence 0.5', () => {
    const result = detectConverterAll(SONARQUBE_EMPTY_ISSUES)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sonarqube-to-hdf');
    expect(result!.confidence).toBe(0.5);
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
    expect(sonarqubeFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('sonarqube-to-hdf')).toBeDefined();
  });
});
