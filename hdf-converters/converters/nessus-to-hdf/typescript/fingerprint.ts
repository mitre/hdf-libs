/**
 * Nessus format fingerprint.
 *
 * Detects Nessus XML files by checking for <NessusClientData_v2> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const nessusFingerprint: ConverterFingerprint = {
  id: 'nessus-to-hdf',
  label: 'Nessus',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    const root = extractXmlRootElement(input);
    if (!root) return 0;
    return root === 'NessusClientData_v2' ? 1.0 : 0;
  },
  detectVersion: (input: unknown): string => {
    if (typeof input !== 'string') return '';
    const root = extractXmlRootElement(input);
    return root === 'NessusClientData_v2' ? '2' : '';
  },
};

export function register(): void {
  if (getFingerprint('nessus-to-hdf')) return;
  registerFingerprint(nessusFingerprint);
}
