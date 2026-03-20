/**
 * GitLab Security Report format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with vulnerabilities[] + scan.type (v0.9) or just vulnerabilities[] (v0.5).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const gitlabFingerprint: ConverterFingerprint = {
  id: 'gitlab-to-hdf',
  label: 'GitLab',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (!Array.isArray(obj.vulnerabilities)) return 0;
    // Strong signal: scan object with type field (GitLab Security Report schema)
    if (typeof obj.scan === 'object' && obj.scan !== null) {
      const scan = obj.scan as Record<string, unknown>;
      if (typeof scan.type === 'string') return 0.9;
      // Has scan but no type — still likely GitLab
      return 0.7;
    }
    // Weak signal: just vulnerabilities[] (could be GitLab or other tools)
    return 0.5;
  },
};

export function register(): void {
  if (getFingerprint('gitlab-to-hdf')) return;
  registerFingerprint(gitlabFingerprint);
}
