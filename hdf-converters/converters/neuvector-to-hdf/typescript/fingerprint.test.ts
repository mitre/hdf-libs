import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, neuvectorFingerprint } from './fingerprint.js';

const NEUVECTOR_GOOD = JSON.stringify({
  error_message: '',
  report: {
    image_id: 'sha256:abc',
    registry: 'docker.io',
    repository: 'library/nginx',
    tag: 'latest',
    digest: 'sha256:xyz',
    size: 12345,
    author: '',
    base_os: 'debian',
    created_at: '2024-01-01T00:00:00Z',
    cvedb_version: '1.0',
    cvedb_create_time: '2024-01-01T00:00:00Z',
    layers: [],
    vulnerabilities: [
      {
        name: 'CVE-2024-0001',
        score: 7.5,
        severity: 'High',
        vectors: '',
        description: 'A vulnerability',
        file_name: 'libssl.so',
        package_name: 'openssl',
        package_version: '1.1.1',
        fixed_version: '1.1.2',
        link: 'https://nvd.nist.gov/',
        score_v3: 7.5,
        vectors_v3: '',
        published_timestamp: 0,
        last_modified_timestamp: 0,
        feed_rating: '',
      },
    ],
  },
});

const NEUVECTOR_EMPTY_VULNS = JSON.stringify({
  error_message: '',
  report: {
    image_id: 'sha256:abc',
    registry: 'docker.io',
    repository: 'library/alpine',
    tag: '3.18',
    digest: '',
    size: 5000,
    author: '',
    base_os: 'alpine',
    created_at: '',
    cvedb_version: '',
    cvedb_create_time: '',
    layers: [],
    vulnerabilities: [],
  },
});

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });
const SNYK_JSON = JSON.stringify({ vulnerabilities: [], packageManager: 'npm' });

describe('neuvector-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('neuvector-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('NeuVector');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(neuvectorFingerprint.id).toBe('neuvector-to-hdf');
    expect(neuvectorFingerprint).not.toHaveProperty('convert');
  });

  it('detects NeuVector JSON at confidence 1.0', () => {
    const result = detectConverter(NEUVECTOR_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('neuvector-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects NeuVector with empty vulnerabilities at confidence 0.7', () => {
    const result = detectConverter(NEUVECTOR_EMPTY_VULNS);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('neuvector-to-hdf');
    expect(result!.confidence).toBe(0.7);
  });

  it('does not match Snyk JSON (top-level vulnerabilities)', () => {
    const result = detectConverter(SNYK_JSON);
    // Snyk has top-level vulnerabilities, not nested under report
    expect(result === undefined || result.fingerprint.id !== 'neuvector-to-hdf').toBe(true);
  });

  it('does not match random JSON', () => {
    const result = detectConverter(RANDOM_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match null input', () => {
    expect(neuvectorFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('neuvector-to-hdf')).toBeDefined();
  });
});
