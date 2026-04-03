/**
 * Dependency-Track format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with findings[] containing vulnerability.vulnId fields.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const deptrackFingerprint: ConverterFingerprint = {
  id: 'deptrack-to-hdf',
  label: 'Dependency-Track',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Primary: findings array with vulnerability.vulnId + project + meta
    if (Array.isArray(obj.findings)) {
      // Strong signal: has project and meta (standard FPF shape)
      if (typeof obj.project === 'object' && obj.project !== null &&
          typeof obj.meta === 'object' && obj.meta !== null) {
        return 1.0;
      }
      // Medium signal: findings with vulnerability sub-objects
      const findings = obj.findings as unknown[];
      if (findings.length > 0) {
        const first = findings[0] as Record<string, unknown>;
        if (typeof first === 'object' && first !== null &&
            typeof first.vulnerability === 'object' && first.vulnerability !== null) {
          const vuln = first.vulnerability as Record<string, unknown>;
          if (typeof vuln.vulnId === 'string') return 0.9;
        }
      }
      return 0.5;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('deptrack-to-hdf')) return;
  registerFingerprint(deptrackFingerprint);
}
