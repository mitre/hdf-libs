/**
 * DBProtect format fingerprint.
 *
 * Detects DBProtect XML files by checking for <dataset> root element
 * with metadata/data child structure.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const dbprotectFingerprint: ConverterFingerprint = {
  id: 'dbprotect-to-hdf',
  label: 'DBProtect',
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
