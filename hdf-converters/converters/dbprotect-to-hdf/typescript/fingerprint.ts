/**
 * DBProtect format fingerprint.
 *
 * Detects DBProtect XML files by checking for <dataset> root element
 * with metadata/data child structure.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const dbprotectFingerprint: ConverterFingerprint = {
  id: 'dbprotect-to-hdf',
  label: 'DBProtect',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    const root = extractXmlRootElement(input);
    if (!root) return 0;
    if (root === 'dataset') {
      // Higher confidence if metadata/data children present (DBProtect-specific)
      if (input.includes('<metadata') && input.includes('<data')) return 1.0;
      return 0.8;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('dbprotect-to-hdf')) return;
  registerFingerprint(dbprotectFingerprint);
}
