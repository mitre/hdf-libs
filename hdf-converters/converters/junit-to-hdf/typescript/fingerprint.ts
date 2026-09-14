/**
 * JUnit format fingerprint.
 *
 * Detects JUnit XML files by checking for <testsuites> or <testsuite> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

// Matches the "[SEVERITY][CHECK_ID]" prefix Checkov packs into JUnit testcase names
// (a CKV/CKV2 check id for IaC, a CVE id for SCA). Only the prefix is keyed on, so
// reworded check descriptions still match. Mirrors Go's checkovTestCaseName.
const CHECKOV_TEST_CASE_NAME = /^\[[A-Z]+\]\[(?:CKV2?_[A-Z0-9_]+|CVE-\d{4}-\d+)\]/;

/** Reports whether a JUnit testcase name carries Checkov's bracketed severity and check id prefix. */
export function isCheckovTestCaseName(name: string): boolean {
  return CHECKOV_TEST_CASE_NAME.test(name);
}

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
