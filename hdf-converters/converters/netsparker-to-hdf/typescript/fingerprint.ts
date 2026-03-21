/**
 * Netsparker/Invicti format fingerprint.
 *
 * Detects Netsparker XML files by checking for <netsparker-enterprise>
 * or <invicti-enterprise> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const netsparkerFingerprint: ConverterFingerprint = {
  id: 'netsparker-to-hdf',
  label: 'Netsparker',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    const root = extractXmlRootElement(input);
    if (!root) return 0;
    return (root === 'netsparker-enterprise' || root === 'invicti-enterprise') ? 1.0 : 0;
  },
};

export function register(): void {
  if (getFingerprint('netsparker-to-hdf')) return;
  registerFingerprint(netsparkerFingerprint);
}
