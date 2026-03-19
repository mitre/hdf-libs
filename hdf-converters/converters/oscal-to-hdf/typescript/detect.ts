/**
 * OSCAL document type detection.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/detect.go.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import type { Oscal } from './types.js';

/** The 7 valid OSCAL document type strings. */
export type OscalDocumentType =
  | 'catalog'
  | 'profile'
  | 'component-definition'
  | 'system-security-plan'
  | 'assessment-plan'
  | 'assessment-results'
  | 'plan-of-action-and-milestones';

/**
 * Parses the input JSON just enough to determine which OSCAL document type
 * it contains. Returns one of the 7 OSCAL root key strings.
 *
 * @throws Error if the input is not valid OSCAL
 */
export function detectOscalDocumentType(input: string): OscalDocumentType {
  const doc = parseJSON<Oscal>(input);

  if (doc.catalog) return 'catalog';
  if (doc.profile) return 'profile';
  if (doc['component-definition']) return 'component-definition';
  if (doc['system-security-plan']) return 'system-security-plan';
  if (doc['assessment-plan']) return 'assessment-plan';
  if (doc['assessment-results']) return 'assessment-results';
  if (doc['plan-of-action-and-milestones']) return 'plan-of-action-and-milestones';

  throw new Error(
    'unrecognized OSCAL document: expected one of catalog, profile, ' +
    'component-definition, system-security-plan, assessment-plan, ' +
    'assessment-results, plan-of-action-and-milestones as root key',
  );
}
