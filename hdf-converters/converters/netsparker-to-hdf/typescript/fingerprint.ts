/**
 * Netsparker/Invicti format fingerprint.
 *
 * Detects Netsparker XML files by checking for <netsparker-enterprise>
 * or <invicti-enterprise> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const netsparkerFingerprint: ConverterFingerprint = {
  id: 'netsparker-to-hdf',
  label: 'Netsparker',
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
    return (root === 'netsparker-enterprise' || root === 'invicti-enterprise') ? 1.0 : 0;
  },
};

export function register(): void {
  if (getFingerprint('netsparker-to-hdf')) return;
  registerFingerprint(netsparkerFingerprint);
}
