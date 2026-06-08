import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cyclonedxVexFingerprint } from './fingerprint.js';

describe('cyclonedx-vex-to-hdf fingerprint', () => {
  it('matches a real CycloneDX VEX BOM', () => {
    const data = JSON.parse(
      readFileSync(
        join(__dirname, '..', 'fixtures', 'input', 'case1-vex-not_affected.json'),
        'utf-8',
      ),
    );
    expect(cyclonedxVexFingerprint.fingerprint(data)).toBe(1.0);
  });

  it('rejects plain CycloneDX SBOM without analysis', () => {
    expect(
      cyclonedxVexFingerprint.fingerprint({
        bomFormat: 'CycloneDX',
        vulnerabilities: [{ id: 'CVE-2024-1' }],
      }),
    ).toBe(0);
  });

  it('rejects non-CycloneDX', () => {
    expect(cyclonedxVexFingerprint.fingerprint({ bomFormat: 'SPDX' })).toBe(0);
    expect(cyclonedxVexFingerprint.fingerprint({ bomFormat: 'CycloneDX' })).toBe(0);
    expect(cyclonedxVexFingerprint.fingerprint('not-a-map')).toBe(0);
    expect(cyclonedxVexFingerprint.fingerprint(null)).toBe(0);
  });
});
