/**
 * CycloneDX VEX format fingerprint.
 *
 * Detects a CycloneDX BOM that carries VEX analysis statements
 * (vulnerabilities[].analysis present). Plain SBOMs without analysis
 * fall through to cyclonedx-to-hdf.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';

export const cyclonedxVexFingerprint: ConverterFingerprint = {
  id: 'cyclonedx-vex-to-hdf',
  label: 'CycloneDX VEX',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'amendments',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (obj.bomFormat !== 'CycloneDX') return 0;
    const vulns = obj.vulnerabilities;
    if (!Array.isArray(vulns) || vulns.length === 0) return 0;
    for (const v of vulns) {
      if (typeof v === 'object' && v !== null && 'analysis' in v) return 1.0;
    }
    return 0;
  },
};

export function register(): void {
  if (!getFingerprint('cyclonedx-vex-to-hdf')) registerFingerprint(cyclonedxVexFingerprint);
}
