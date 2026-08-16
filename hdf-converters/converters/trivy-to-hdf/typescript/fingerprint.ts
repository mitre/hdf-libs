/**
 * Trivy native-JSON fingerprint.
 *
 * Matches native Trivy JSON only, keying on markers the delegate formats
 * (SARIF, CycloneDX, ASFF, GitLab) lack: a numeric SchemaVersion plus
 * ArtifactName + ArtifactType. TypeScript peer of go/fingerprint.go.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const trivyFingerprint: ConverterFingerprint = {
  id: 'trivy-to-hdf',
  label: 'Trivy',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (typeof obj.SchemaVersion !== 'number') return 0;
    if ('ArtifactName' in obj && 'ArtifactType' in obj) return 0.95;
    return 0;
  },
  detectVersion: (input: unknown): string => {
    if (typeof input === 'object' && input !== null) {
      const sv = (input as Record<string, unknown>).SchemaVersion;
      if (typeof sv === 'number') return String(sv);
    }
    return '';
  },
};

export function register(): void {
  if (getFingerprint('trivy-to-hdf')) return;
  registerFingerprint(trivyFingerprint);
}
