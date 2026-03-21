/**
 * NeuVector format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects NeuVector scan JSON by the presence of `report.vulnerabilities[]`
 * where vulnerability items have `name` + `package_name`.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const neuvectorFingerprint: ConverterFingerprint = {
  id: 'neuvector-to-hdf',
  label: 'NeuVector',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    const report = obj.report as Record<string, unknown> | undefined;
    if (!report || typeof report !== 'object') return 0;
    if (!Array.isArray(report.vulnerabilities)) return 0;
    if (report.vulnerabilities.length === 0) return 0.7;
    const first = report.vulnerabilities[0] as Record<string, unknown> | undefined;
    if (first && typeof first.name === 'string' && typeof first.package_name === 'string') return 1.0;
    return 0.5;
  },
};

export function register(): void {
  if (getFingerprint('neuvector-to-hdf')) return;
  registerFingerprint(neuvectorFingerprint);
}
