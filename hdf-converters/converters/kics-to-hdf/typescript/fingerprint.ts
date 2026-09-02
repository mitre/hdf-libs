/**
 * KICS format fingerprint.
 *
 * Keys on container names unique to KICS — `kics_version` and
 * `severity_counters` alongside `queries` — rather than the generic
 * results/version pair, which matches several other tools and bare arrays of
 * HDF requirements.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';

export const kicsFingerprint: ConverterFingerprint = {
  id: 'kics-to-hdf',
  label: 'KICS',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    const obj = input as Record<string, unknown>;

    // Emitted by every scan, including one that found nothing.
    if (!Array.isArray(obj.queries)) return 0;
    if (typeof obj.kics_version !== 'string') return 0;

    // Strong signal: the severity histogram KICS always reports.
    if (typeof obj.severity_counters === 'object' && obj.severity_counters !== null) {
      return 1.0;
    }
    return 0.8;
  },
  detectVersion: (input: unknown): string => {
    const v = (input as { kics_version?: unknown } | null)?.kics_version;
    return typeof v === 'string' ? v : '';
  },
};

export function register(): void {
  if (getFingerprint('kics-to-hdf')) return;
  registerFingerprint(kicsFingerprint);
}
