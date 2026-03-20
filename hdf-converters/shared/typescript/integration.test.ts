/**
 * Integration test: feed real fixtures through detectConverter()
 * and verify each is detected as the correct converter.
 *
 * This catches false positives (two converters claiming the same input)
 * and missed detections (a fixture returning undefined).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { detectConverter, detectConverterAll } from './fingerprint.js';
import { registerAllFingerprints } from './register-all.js';
import { _resetRegistry, getFingerprints } from './registry.js';

// Resolve fixture path relative to hdf-converters root
const root = resolve(__dirname, '../..');

function fixture(converter: string, filename: string): string {
  const path = resolve(root, 'converters', converter, 'fixtures', 'input', filename);
  if (!existsSync(path)) return '';
  return readFileSync(path, 'utf-8');
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

  it('detects aws-config fixture', () => {
    const input = fixture('aws-config-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('aws-config-to-hdf');
  });

  it('detects cyclonedx fixture', () => {
    const input = fixture('cyclonedx-to-hdf', 'minimal-vulns.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('cyclonedx-to-hdf');
  });

  it('detects conveyor fixture', () => {
    const input = fixture('conveyor-to-hdf', 'sample-results.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('conveyor-to-hdf');
  });

  it('detects deptrack fixture', () => {
    const input = fixture('deptrack-to-hdf', 'fpf-default.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('deptrack-to-hdf');
  });

  it('detects gitlab fixture', () => {
    const input = fixture('gitlab-to-hdf', 'minimal-sast.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gitlab-to-hdf');
  });

  it('detects gosec fixture', () => {
    const input = fixture('gosec-to-hdf', 'minimal.json');
    if (!input) return; // skip if no fixture
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gosec-to-hdf');
  });

  it('detects grype fixture', () => {
    const input = fixture('grype-to-hdf', 'anchore_grype.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('grype-to-hdf');
  });

  it('detects jfrog-xray fixture', () => {
    const input = fixture('jfrog-xray-to-hdf', 'minimal.json');
    if (!input) return;
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('jfrog-xray-to-hdf');
  });

  it('detects msft-defender-cloud fixture', () => {
    const input = fixture('msft-defender-cloud-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-cloud-to-hdf');
  });

  it('detects msft-defender-devops fixture (SARIF tier: should outrank generic SARIF)', () => {
    const input = fixture('msft-defender-devops-to-hdf', 'minimal.sarif');
    expect(input).toBeTruthy();
    const results = detectConverterAll(input);
    expect(results.length).toBeGreaterThanOrEqual(1);
    // MSDO should be first (0.95), generic SARIF second (0.9)
    expect(results[0].fingerprint.id).toBe('msft-defender-devops-to-hdf');
    if (results.length > 1) {
      expect(results[0].confidence).toBeGreaterThan(results[1].confidence);
    }
  });

  it('detects msft-defender-endpoint fixture', () => {
    const input = fixture('msft-defender-endpoint-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-endpoint-to-hdf');
  });

  it('detects msft-secure-score fixture', () => {
    const input = fixture('msft-secure-score-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-secure-score-to-hdf');
  });

  it('detects neuvector fixture', () => {
    const input = fixture('neuvector-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('neuvector-to-hdf');
  });

  it('detects scoutsuite fixture', () => {
    const input = fixture('scoutsuite-to-hdf', 'minimal.json');
    if (!input) return;
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('scoutsuite-to-hdf');
  });

  it('detects snyk fixture', () => {
    const input = fixture('snyk-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('snyk-to-hdf');
  });

  it('detects sonarqube fixture', () => {
    const input = fixture('sonarqube-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sonarqube-to-hdf');
  });

  it('detects splunk fixture', () => {
    const input = fixture('splunk-to-hdf', 'splunk-minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('splunk-to-hdf');
  });

  it('detects trufflehog fixture', () => {
    const input = fixture('trufflehog-to-hdf', 'minimal.json');
    if (!input) return;
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trufflehog-to-hdf');
  });

  it('detects twistlock fixture', () => {
    const input = fixture('twistlock-to-hdf', 'twistlock-twistcli-sample-1.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('twistlock-to-hdf');
  });

  // === SARIF ===

  it('detects generic SARIF fixture', () => {
    const input = fixture('sarif-to-hdf', 'sarif_input.sarif');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  // === XML converters ===

  it('detects nessus fixture', () => {
    const input = fixture('nessus-to-hdf', 'minimal.xml');
    if (!input) return;
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('nessus-to-hdf');
  });

  it('detects netsparker fixture', () => {
    const input = fixture('netsparker-to-hdf', 'sample-netsparker-invicti.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('netsparker-to-hdf');
  });

  it('detects burpsuite fixture', () => {
    const input = fixture('burpsuite-to-hdf', 'zero.webappsecurity.com.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('burpsuite-to-hdf');
  });

  it('detects fortify fixture', () => {
    const input = fixture('fortify-to-hdf', 'fortify_webgoat_results.fvdl');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('fortify-to-hdf');
  });

  it('detects dbprotect fixture', () => {
    const input = fixture('dbprotect-to-hdf', 'sample-check-results.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('dbprotect-to-hdf');
  });

  it('detects xccdf fixture (Benchmark)', () => {
    const input = fixture('xccdf-results-to-hdf', 'minimal.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
  });

  it('detects xccdf ARF fixture', () => {
    const input = fixture('xccdf-results-to-hdf', 'arf-minimal.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
  });

  it('detects veracode fixture', () => {
    const input = fixture('veracode-to-hdf', 'veracode.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('veracode-to-hdf');
  });

  it('detects junit fixture', () => {
    const input = fixture('junit-to-hdf', 'testsuites-mixed.xml');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('junit-to-hdf');
  });

  // === HDF native ===

  it('detects legacyhdf v1 fixture', () => {
    const input = fixture('legacyhdf-to-hdf', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('legacyhdf-to-hdf');
  });

  it('detects hdf-v2 fixture (from hdf-to-xml input)', () => {
    const input = fixture('hdf-to-xml', 'minimal.json');
    expect(input).toBeTruthy();
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('hdf-v2-passthrough');
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
    const fixtures = [
      ['aws-config-to-hdf', 'minimal.json'],
      ['cyclonedx-to-hdf', 'minimal-vulns.json'],
      ['grype-to-hdf', 'anchore_grype.json'],
      ['snyk-to-hdf', 'minimal.json'],
      ['gitlab-to-hdf', 'minimal-sast.json'],
      ['sonarqube-to-hdf', 'minimal.json'],
      ['neuvector-to-hdf', 'minimal.json'],
      ['twistlock-to-hdf', 'twistlock-twistcli-sample-1.json'],
    ] as const;

    for (const [converter, file] of fixtures) {
      const input = fixture(converter, file);
      if (!input) continue;
      const results = detectConverterAll(input);
      const topConfidence = results.filter(r => r.confidence >= 1.0);
      // At most ONE converter should claim 1.0 confidence
      expect(
        topConfidence.length,
        `${converter}/${file}: ${topConfidence.length} converters at 1.0: ${topConfidence.map(r => r.fingerprint.id).join(', ')}`
      ).toBeLessThanOrEqual(1);
    }
  });
});
