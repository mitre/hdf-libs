/**
 * JUnit format fingerprint.
 *
 * Detects JUnit XML files by checking for <testsuites> or <testsuite> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const junitFingerprint: ConverterFingerprint = {
  id: 'junit-to-hdf',
  label: 'JUnit',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    const root = extractXmlRootElement(input);
    if (!root) return 0;
    return (root === 'testsuites' || root === 'testsuite') ? 1.0 : 0;
  },
};

export function register(): void {
  if (getFingerprint('junit-to-hdf')) return;
  registerFingerprint(junitFingerprint);
}
