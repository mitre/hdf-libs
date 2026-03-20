/**
 * XCCDF/ARF format fingerprint.
 *
 * Detects XCCDF and ARF XML files by checking for:
 * - <Benchmark> root element (XCCDF)
 * - <asset-report-collection> root element (ARF)
 * Handles namespace prefixes (e.g., <xccdf:Benchmark>).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const xccdfFingerprint: ConverterFingerprint = {
  id: 'xccdf-results-to-hdf',
  label: 'XCCDF/ARF',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    const root = extractXmlRootElement(input);
    if (!root) return 0;
    if (root === 'Benchmark' || root === 'asset-report-collection') return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('xccdf-results-to-hdf')) return;
  registerFingerprint(xccdfFingerprint);
}
