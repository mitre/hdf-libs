/**
 * Fortify FVDL format fingerprint.
 *
 * Detects Fortify XML files by checking for <FVDL> root element.
 * Fortify uses the FVDL (Fortify Vulnerability Description Language) format
 * with xmlns="xmlns.fortify.com/schema/fvdl" namespace.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const fortifyFingerprint: ConverterFingerprint = {
  id: 'fortify-to-hdf',
  label: 'Fortify',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    const root = extractXmlRootElement(input);
    if (!root) return 0;
    if (root === 'FVDL') {
      // Higher confidence with Fortify namespace
      if (input.includes('xmlns.fortify.com')) return 1.0;
      return 0.95;
    }
    return 0;
  },
  detectVersion: (input: unknown): string => {
    if (typeof input !== 'string') return '';
    const m = input.match(/<FVDL\b[^>]*\bversion="([^"]+)"/);
    return m?.[1] ?? '';
  },
};

export function register(): void {
  if (getFingerprint('fortify-to-hdf')) return;
  registerFingerprint(fortifyFingerprint);
}
