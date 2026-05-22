/**
 * CKL (DISA STIG Viewer checklist) format fingerprint.
 *
 * Detects .ckl XML files by their <CHECKLIST> root element.
 * Handles namespace prefixes via extractXmlRootElement.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const cklFingerprint: ConverterFingerprint = {
  id: 'ckl-to-hdf',
  label: 'CKL (DISA STIG Viewer checklist)',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    return extractXmlRootElement(input) === 'CHECKLIST' ? 1.0 : 0;
  },
};

export function register(): void {
  if (getFingerprint('ckl-to-hdf')) return;
  registerFingerprint(cklFingerprint);
}
