/**
 * Microsoft Defender for Endpoint format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects MDE alert response JSON by `value[]` with items containing
 * `severity` + `category` + `evidence` (Microsoft Graph Security v2 alert structure).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const msftDefenderEndpointFingerprint: ConverterFingerprint = {
  id: 'msft-defender-endpoint-to-hdf',
  label: 'Microsoft Defender for Endpoint',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (!Array.isArray(obj.value)) return 0;
    if (obj.value.length === 0) return 0;
    const first = obj.value[0] as Record<string, unknown> | undefined;
    if (!first || typeof first !== 'object') return 0;
    // MDE alerts have severity + category + evidence array
    if (
      typeof first.severity === 'string' &&
      typeof first.category === 'string' &&
      Array.isArray(first.evidence)
    ) return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('msft-defender-endpoint-to-hdf')) return;
  registerFingerprint(msftDefenderEndpointFingerprint);
}
