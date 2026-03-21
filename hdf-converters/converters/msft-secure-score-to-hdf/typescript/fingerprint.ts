/**
 * Microsoft Secure Score format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects the combined input format: `secureScore.value[]` + `profiles.value[]`
 * with controlScores inside secureScore entries.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const msftSecureScoreFingerprint: ConverterFingerprint = {
  id: 'msft-secure-score-to-hdf',
  label: 'Microsoft Secure Score',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    const secureScore = obj.secureScore as Record<string, unknown> | undefined;
    const profiles = obj.profiles as Record<string, unknown> | undefined;
    if (!secureScore || typeof secureScore !== 'object') return 0;
    if (!profiles || typeof profiles !== 'object') return 0;
    if (!Array.isArray(secureScore.value) || !Array.isArray(profiles.value)) return 0;
    // Check for controlScores in the first secureScore entry
    if (secureScore.value.length > 0) {
      const first = secureScore.value[0] as Record<string, unknown> | undefined;
      if (first && Array.isArray(first.controlScores)) return 1.0;
    }
    return 0.8;
  },
};

export function register(): void {
  if (getFingerprint('msft-secure-score-to-hdf')) return;
  registerFingerprint(msftSecureScoreFingerprint);
}
