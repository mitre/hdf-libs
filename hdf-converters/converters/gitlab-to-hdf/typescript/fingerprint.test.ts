import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, gitlabFingerprint } from './fingerprint.js';

// Known-good GitLab Security Report fixture (v14+ schema with scan.type)
const GITLAB_FULL = JSON.stringify({
  version: '14.0.0',
  scan: {
    analyzer: { id: 'gemnasium', name: 'Gemnasium', version: '3.0' },
    scanner: { id: 'gemnasium', name: 'Gemnasium' },
    type: 'dependency_scanning',
    start_time: '2024-01-01T00:00:00',
    end_time: '2024-01-01T00:01:00',
    status: 'success',
  },
  vulnerabilities: [
    {
      id: 'vuln-001',
      name: 'Test Vulnerability',
      severity: 'High',
      description: 'A test vulnerability',
    },
  ],
});

// Minimal GitLab: just vulnerabilities array (older format)
const GITLAB_MINIMAL = JSON.stringify({
  vulnerabilities: [
    { id: 'vuln-002', severity: 'Medium' },
  ],
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

// Known-bad: GoSec format
const GOSEC_JSON = JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } });

describe('gitlab-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('gitlab-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('GitLab');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(gitlabFingerprint.id).toBe('gitlab-to-hdf');
    expect(gitlabFingerprint).not.toHaveProperty('convert');
  });

  it('detects full GitLab report with scan.type at confidence 0.9', () => {
    const result = detectConverter(GITLAB_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gitlab-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects minimal GitLab report (vulnerabilities only) at confidence 0.5', () => {
    const result = detectConverterAll(GITLAB_MINIMAL)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gitlab-to-hdf');
    expect(result!.confidence).toBe(0.5);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match GoSec JSON', () => {
    const result = detectConverter(GOSEC_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(gitlabFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(gitlabFingerprint.fingerprint('string')).toBe(0);
  });

  it('returns 0 for object without vulnerabilities array', () => {
    expect(gitlabFingerprint.fingerprint({ scan: { type: 'sast' } })).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('gitlab-to-hdf')).toBeDefined();
  });
});
