/**
 * CSAF VEX format fingerprint.
 *
 * Detects CSAF VEX by document.category=='csaf_vex' + csaf_version.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';

export const csafVexFingerprint: ConverterFingerprint = {
  id: 'csaf-vex-to-hdf',
  label: 'CSAF VEX',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'amendments',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    const doc = obj.document as Record<string, unknown> | undefined;
    if (!doc) return 0;
    if (doc.category !== 'csaf_vex') return 0;
    if (typeof doc.csaf_version !== 'string') return 0;
    return 1.0;
  },
};

export function register(): void {
  if (!getFingerprint('csaf-vex-to-hdf')) registerFingerprint(csafVexFingerprint);
}
