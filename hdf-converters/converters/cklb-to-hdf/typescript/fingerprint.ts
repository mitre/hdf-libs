/**
 * CKLB (DISA STIG Viewer 3.x JSON) format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects .cklb JSON by the presence of both a `cklb_version` key and a
 * `stigs` array.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const cklbFingerprint: ConverterFingerprint = {
  id: 'cklb-to-hdf',
  label: 'CKLB (DISA STIG Viewer 3.x JSON)',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    const obj = input as Record<string, unknown>;
    if (!('cklb_version' in obj)) return 0;
    if (!Array.isArray(obj.stigs)) return 0;
    return 1.0;
  },
};

export function register(): void {
  if (getFingerprint('cklb-to-hdf')) return;
  registerFingerprint(cklbFingerprint);
}
