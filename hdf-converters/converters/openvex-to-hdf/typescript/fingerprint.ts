/**
 * OpenVEX format fingerprint.
 *
 * Detects an OpenVEX document by the openvex.dev context URI and the
 * presence of a statements array.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';

export const openvexFingerprint: ConverterFingerprint = {
  id: 'openvex-to-hdf',
  label: 'OpenVEX',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'amendments',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    const ctx = obj['@context'];
    if (typeof ctx !== 'string' || !ctx.includes('openvex.dev')) return 0;
    if (!('statements' in obj)) return 0;
    return 1.0;
  },
};

export function register(): void {
  if (!getFingerprint('openvex-to-hdf')) registerFingerprint(openvexFingerprint);
}
