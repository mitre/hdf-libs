/**
 * Veracode DetailedReport XML format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 *
 * Veracode reports are XML with a <detailedreport> root element in the
 * Veracode namespace. The fingerprint checks for the <detailedreport> tag.
 *
 * Key structural markers:
 * - <detailedreport> root element → confidence 1.0
 * - <summaryreport> (unsupported variant) → confidence 0.0
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const veracodeFingerprint: ConverterFingerprint = {
  id: 'veracode-to-hdf',
  label: 'Veracode',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    if (input.match(/<(?:[a-zA-Z_][\w.-]*:)?detailedreport[\s>]/)) return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('veracode-to-hdf')) return;
  registerFingerprint(veracodeFingerprint);
}
