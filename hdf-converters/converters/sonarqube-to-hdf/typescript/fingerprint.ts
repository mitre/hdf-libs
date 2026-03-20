/**
 * SonarQube format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects SonarQube issues JSON by `issues[]` where items have `rule` + `component`.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const sonarqubeFingerprint: ConverterFingerprint = {
  id: 'sonarqube-to-hdf',
  label: 'SonarQube',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (!Array.isArray(obj.issues)) return 0;
    if (obj.issues.length === 0) return 0.5;
    const first = obj.issues[0] as Record<string, unknown> | undefined;
    if (!first || typeof first !== 'object') return 0;
    if (typeof first.rule === 'string' && typeof first.component === 'string') return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('sonarqube-to-hdf')) return;
  registerFingerprint(sonarqubeFingerprint);
}
