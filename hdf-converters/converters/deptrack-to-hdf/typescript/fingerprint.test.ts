import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, deptrackFingerprint } from './fingerprint.js';

// Known-good Dependency-Track FPF fixture
const DEPTRACK_FULL = JSON.stringify({
  version: '1.0',
  meta: {
    application: 'Dependency-Track',
    version: '4.8.0',
    timestamp: '2024-01-01T00:00:00Z',
  },
  project: {
    uuid: 'proj-uuid-123',
    name: 'test-project',
    version: '1.0.0',
  },
  findings: [
    {
      component: { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
      vulnerability: {
        vulnId: 'CVE-2021-23337',
        source: 'NVD',
        severity: 'HIGH',
      },
      matrix: 'proj-uuid:comp-uuid:vuln-uuid',
    },
  ],
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

// Known-bad: CycloneDX format
const CYCLONEDX_JSON = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5' });

describe('deptrack-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('deptrack-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Dependency-Track');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(deptrackFingerprint.id).toBe('deptrack-to-hdf');
    expect(deptrackFingerprint).not.toHaveProperty('convert');
  });

  it('detects full Dependency-Track FPF at confidence 1.0', () => {
    const result = detectConverter(DEPTRACK_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('deptrack-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects findings with vulnId at confidence 0.9', () => {
    const partial = JSON.stringify({
      findings: [
        {
          vulnerability: { vulnId: 'CVE-2021-12345', severity: 'MEDIUM' },
          component: { name: 'foo' },
        },
      ],
    });
    const result = detectConverter(partial);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('deptrack-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match CycloneDX JSON', () => {
    const result = detectConverter(CYCLONEDX_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(deptrackFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(deptrackFingerprint.fingerprint('string')).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('deptrack-to-hdf')).toBeDefined();
  });
});
