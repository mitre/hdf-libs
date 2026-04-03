/**
 * AWS Config format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with ConfigRules[] array or individual ConfigRuleName fields.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const awsConfigFingerprint: ConverterFingerprint = {
  id: 'aws-config-to-hdf',
  label: 'AWS Config',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Primary: ConfigRules array (the standard export shape)
    if (Array.isArray(obj.ConfigRules)) return 1.0;
    // Secondary: individual config rule object with ConfigRuleName
    if (typeof obj.ConfigRuleName === 'string') return 0.7;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('aws-config-to-hdf')) return;
  registerFingerprint(awsConfigFingerprint);
}
