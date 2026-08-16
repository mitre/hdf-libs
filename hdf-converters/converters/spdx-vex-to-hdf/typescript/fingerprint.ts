/**
 * SPDX 3.0 security / VEX format fingerprint.
 *
 * Detects an SPDX-3 JSON-LD document whose @graph carries at least one
 * security_Vex*VulnAssessmentRelationship element. Reuses the shared BOM-package
 * detector so detection logic lives in one place. Disjoint from the SPDX-3
 * AI/Dataset detector and from SPDX 2.x by construction.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';
import { detectSPDX3Security } from '../../../shared/typescript/bom/fingerprints.js';

export const spdxVexFingerprint: ConverterFingerprint = {
  id: 'spdx-vex-to-hdf',
  label: 'SPDX 3.0 Security VEX',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'amendments',
  fingerprint: (input: unknown): number => detectSPDX3Security(input),
};

export function register(): void {
  if (!getFingerprint('spdx-vex-to-hdf')) registerFingerprint(spdxVexFingerprint);
}
