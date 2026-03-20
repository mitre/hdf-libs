/**
 * Nessus format fingerprint.
 *
 * Detects Nessus XML files by checking for <NessusClientData_v2> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const nessusFingerprint: ConverterFingerprint = {
  id: 'nessus-to-hdf',
  label: 'Nessus',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    // Extract root element: match first opening tag after XML declaration/comments
    // Handle namespace prefixes: <ns:ElementName or <ElementName
    const rootMatch = input.match(/<(?:\?[^?]*\?>[\s]*)*(?:!--[\s\S]*?-->[\s]*)*<(?:[a-zA-Z_][\w.-]*:)?([a-zA-Z_][\w.-]*)/);
    if (!rootMatch) return 0;
    const root = rootMatch[1];
    return root === 'NessusClientData_v2' ? 1.0 : 0;
  },
};

export function register(): void {
  if (getFingerprint('nessus-to-hdf')) return;
  registerFingerprint(nessusFingerprint);
}
