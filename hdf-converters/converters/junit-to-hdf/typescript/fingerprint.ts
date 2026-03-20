/**
 * JUnit format fingerprint.
 *
 * Detects JUnit XML files by checking for <testsuites> or <testsuite> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const junitFingerprint: ConverterFingerprint = {
  id: 'junit-to-hdf',
  label: 'JUnit',
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
    return (root === 'testsuites' || root === 'testsuite') ? 1.0 : 0;
  },
};

export function register(): void {
  if (getFingerprint('junit-to-hdf')) return;
  registerFingerprint(junitFingerprint);
}
