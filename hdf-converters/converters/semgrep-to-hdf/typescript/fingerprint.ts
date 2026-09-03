/**
 * Semgrep format fingerprint.
 *
 * Detects the native `semgrep scan --json` document. The distinguishing signals
 * are semgrep-specific container names -- paths.scanned and engine_requested --
 * rather than the generic results/errors/version triple, which also matches
 * bare arrays of HDF requirements and several other tools' output.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';

export const semgrepFingerprint: ConverterFingerprint = {
  id: 'semgrep-to-hdf',
  label: 'Semgrep',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    const obj = input as Record<string, unknown>;

    // Both containers are always emitted, including by a scan with no findings.
    if (!Array.isArray(obj.results) || !Array.isArray(obj.errors)) return 0;

    const paths = obj.paths;
    if (typeof paths !== 'object' || paths === null) return 0;
    if (!Array.isArray((paths as Record<string, unknown>).scanned)) return 0;

    // Strong signal: a finding carrying semgrep's own extra/metadata envelope.
    const first = obj.results[0];
    if (typeof first === 'object' && first !== null) {
      const result = first as Record<string, unknown>;
      const extra = result.extra;
      if (typeof result.check_id === 'string' && typeof extra === 'object' && extra !== null) {
        return 1.0;
      }
    }

    // Empty scan: no finding to corroborate, so lean on the engine marker.
    if (typeof obj.engine_requested === 'string') return 0.9;

    return 0.7;
  },
  detectVersion: (input: unknown): string => {
    const version = (input as { version?: unknown } | null)?.version;
    return typeof version === 'string' ? version : '';
  },
};

export function register(): void {
  if (getFingerprint('semgrep-to-hdf')) return;
  registerFingerprint(semgrepFingerprint);
}
