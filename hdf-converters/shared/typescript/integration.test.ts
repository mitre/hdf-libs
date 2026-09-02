/**
 * Integration test: feed real fixtures through detectConverter()
 * and verify each is detected as the correct converter.
 *
 * EVERY fixture MUST exist. Missing fixtures FAIL the test (no silent skips).
 * EVERY ingest converter with fixtures MUST be represented here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { results } from '@mitre/hdf-fixtures';
import { detectConverter, detectConverterAll } from './fingerprint.js';
import { registerAllFingerprints } from './register-all.js';
import { _resetRegistry, getFingerprints } from './registry.js';

const root = resolve(__dirname, '../..');

function fixture(converter: string, filename: string): string {
  const path = resolve(root, 'converters', converter, 'fixtures', 'input', filename);
  return readFileSync(path, 'utf-8'); // throws if missing — that's intentional
}

beforeAll(() => {
  _resetRegistry();
  registerAllFingerprints();
});

describe('integration: detectConverter with real fixtures', () => {

  it('has 40+ fingerprints registered', () => {
    expect(getFingerprints().length).toBeGreaterThanOrEqual(40);
  });

  // === JSON ingest converters ===

  it('detects aws-config', () => {
    const result = detectConverter(fixture('aws-config-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('aws-config-to-hdf');
  });

  it('detects cyclonedx', () => {
    const result = detectConverter(fixture('cyclonedx-to-hdf', 'minimal-vulns.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('cyclonedx-to-hdf');
  });

  it('detects conveyor', () => {
    const result = detectConverter(fixture('conveyor-to-hdf', 'sample-results.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('conveyor-to-hdf');
  });

  it('detects deptrack', () => {
    const result = detectConverter(fixture('deptrack-to-hdf', 'fpf-default.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('deptrack-to-hdf');
  });

  it('detects gitlab', () => {
    const result = detectConverter(fixture('gitlab-to-hdf', 'minimal-sast.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gitlab-to-hdf');
  });

  it('detects gosec', () => {
    const result = detectConverter(fixture('gosec-to-hdf', 'real.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gosec-to-hdf');
  });

  it('detects semgrep', () => {
    const result = detectConverter(fixture('semgrep-to-hdf', 'real.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('semgrep-to-hdf');
  });

  it('detects grype', () => {
    const result = detectConverter(fixture('grype-to-hdf', 'anchore_grype.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('grype-to-hdf');
  });

  it('detects jfrog-xray', () => {
    const result = detectConverter(fixture('jfrog-xray-to-hdf', 'jfrog_xray_sample.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('jfrog-xray-to-hdf');
  });

  it('detects kics', () => {
    const result = detectConverter(fixture('kics-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('kics-to-hdf');
  });

  it('detects msft-defender-cloud', () => {
    const result = detectConverter(fixture('msft-defender-cloud-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-cloud-to-hdf');
  });

  it('detects msft-defender-devops (SARIF tier: outranks generic SARIF)', () => {
    const results = detectConverterAll(fixture('msft-defender-devops-to-hdf', 'minimal.sarif'));
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].fingerprint.id).toBe('msft-defender-devops-to-hdf');
    if (results.length > 1) {
      expect(results[0].confidence).toBeGreaterThan(results[1].confidence);
    }
  });

  it('detects msft-defender-endpoint', () => {
    const result = detectConverter(fixture('msft-defender-endpoint-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-endpoint-to-hdf');
  });

  it('detects msft-secure-score', () => {
    const result = detectConverter(fixture('msft-secure-score-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-secure-score-to-hdf');
  });

  it('detects neuvector', () => {
    const result = detectConverter(fixture('neuvector-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('neuvector-to-hdf');
  });

  it('detects nikto', () => {
    const result = detectConverter(fixture('nikto-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('nikto-to-hdf');
  });

  it('detects snyk', () => {
    const result = detectConverter(fixture('snyk-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('snyk-to-hdf');
  });

  it('detects sonarqube', () => {
    const result = detectConverter(fixture('sonarqube-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sonarqube-to-hdf');
  });

  it('detects splunk', () => {
    const result = detectConverter(fixture('splunk-to-hdf', 'splunk-minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('splunk-to-hdf');
  });

  it('detects trufflehog', () => {
    const result = detectConverter(fixture('trufflehog-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trufflehog-to-hdf');
  });

  it('detects twistlock', () => {
    const result = detectConverter(fixture('twistlock-to-hdf', 'twistlock-twistcli-sample-1.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('twistlock-to-hdf');
  });

  it('detects zap', () => {
    const result = detectConverter(fixture('zap-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('zap-to-hdf');
  });

  // === SARIF ===

  it('detects generic SARIF at confidence 0.9', () => {
    const result = detectConverter(fixture('sarif-to-hdf', 'sarif_input.sarif'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  // === XML converters ===

  it('detects nessus', () => {
    const result = detectConverter(fixture('nessus-to-hdf', 'sample.nessus'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('nessus-to-hdf');
  });

  it('detects netsparker', () => {
    const result = detectConverter(fixture('netsparker-to-hdf', 'sample-netsparker-invicti.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('netsparker-to-hdf');
  });

  it('detects burpsuite', () => {
    const result = detectConverter(fixture('burpsuite-to-hdf', 'zero.webappsecurity.com.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('burpsuite-to-hdf');
  });

  it('detects fortify', () => {
    const result = detectConverter(fixture('fortify-to-hdf', 'fortify_webgoat_results.fvdl'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('fortify-to-hdf');
  });

  it('detects dbprotect', () => {
    const result = detectConverter(fixture('dbprotect-to-hdf', 'sample-check-results.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('dbprotect-to-hdf');
  });

  it('detects xccdf (Benchmark)', () => {
    const result = detectConverter(fixture('xccdf-results-to-hdf', 'minimal.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
  });

  it('detects xccdf (ARF)', () => {
    const result = detectConverter(fixture('xccdf-results-to-hdf', 'arf-minimal.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
  });

  it('detects veracode', () => {
    const result = detectConverter(fixture('veracode-to-hdf', 'veracode.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('veracode-to-hdf');
  });

  it('detects junit', () => {
    const result = detectConverter(fixture('junit-to-hdf', 'testsuites-mixed.xml'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('junit-to-hdf');
  });

  // === Text/CSV ===

  it('detects prisma', () => {
    const result = detectConverter(fixture('prisma-to-hdf', 'minimal.csv'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('prisma-to-hdf');
  });

  // === HDF native ===

  it('detects legacyhdf v1', () => {
    const result = detectConverter(fixture('legacyhdf-to-hdf', 'minimal.json'));
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('legacyhdf-to-hdf');
  });

  it('detects native HDF (passthrough)', () => {
    const result = detectConverter(results.minimal.read());
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('hdf-passthrough');
  });

  // === Edge cases ===

  it('returns undefined for empty input', () => {
    expect(detectConverter('')).toBeUndefined();
  });

  it('returns undefined for plain text', () => {
    expect(detectConverter('hello world this is plain text')).toBeUndefined();
  });

  it('returns undefined for invalid JSON', () => {
    expect(detectConverter('{broken json')).toBeUndefined();
  });

  // === No false positives ===

  it('no two ingest converters claim the same fixture at confidence 1.0', () => {
    const allFixtures: [string, string][] = [
      ['aws-config-to-hdf', 'minimal.json'],
      ['cyclonedx-to-hdf', 'minimal-vulns.json'],
      ['conveyor-to-hdf', 'sample-results.json'],
      ['deptrack-to-hdf', 'fpf-default.json'],
      ['gitlab-to-hdf', 'minimal-sast.json'],
      ['gosec-to-hdf', 'real.json'],
      ['grype-to-hdf', 'anchore_grype.json'],
      ['jfrog-xray-to-hdf', 'jfrog_xray_sample.json'],
      ['msft-defender-cloud-to-hdf', 'minimal.json'],
      ['msft-defender-endpoint-to-hdf', 'minimal.json'],
      ['msft-secure-score-to-hdf', 'minimal.json'],
      ['neuvector-to-hdf', 'minimal.json'],
      ['nikto-to-hdf', 'minimal.json'],
      ['snyk-to-hdf', 'minimal.json'],
      ['sonarqube-to-hdf', 'minimal.json'],
      ['splunk-to-hdf', 'splunk-minimal.json'],
      ['trufflehog-to-hdf', 'minimal.json'],
      ['twistlock-to-hdf', 'twistlock-twistcli-sample-1.json'],
      ['zap-to-hdf', 'minimal.json'],
      // XML
      ['nessus-to-hdf', 'sample.nessus'],
      ['netsparker-to-hdf', 'sample-netsparker-invicti.xml'],
      ['burpsuite-to-hdf', 'zero.webappsecurity.com.xml'],
      ['fortify-to-hdf', 'fortify_webgoat_results.fvdl'],
      ['dbprotect-to-hdf', 'sample-check-results.xml'],
      ['xccdf-results-to-hdf', 'minimal.xml'],
      ['veracode-to-hdf', 'veracode.xml'],
      ['junit-to-hdf', 'testsuites-mixed.xml'],
    ];

    for (const [converter, file] of allFixtures) {
      const input = fixture(converter, file);
      const results = detectConverterAll(input);
      const topConfidence = results.filter(r => r.confidence >= 1.0);
      expect(
        topConfidence.length,
        `${converter}/${file}: ${topConfidence.length} converters at 1.0: ${topConfidence.map(r => r.fingerprint.id).join(', ')}`
      ).toBeLessThanOrEqual(1);
    }
  });
});
