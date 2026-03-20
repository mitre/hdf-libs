/**
 * Microsoft Defender for Cloud format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects Defender for Cloud JSON by `value[]` with items containing
 * `properties.displayName` (Azure Security Assessment structure).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const msftDefenderCloudFingerprint: ConverterFingerprint = {
  id: 'msft-defender-cloud-to-hdf',
  label: 'Microsoft Defender for Cloud',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (!Array.isArray(obj.value)) return 0;
    if (obj.value.length === 0) return 0.5;
    const first = obj.value[0] as Record<string, unknown> | undefined;
    if (!first || typeof first !== 'object') return 0;
    const props = first.properties as Record<string, unknown> | undefined;
    if (props && typeof props === 'object' && typeof props.displayName === 'string') return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('msft-defender-cloud-to-hdf')) return;
  registerFingerprint(msftDefenderCloudFingerprint);
}
