/**
 * TypeScript types for Hipcheck analysis to NIST 800-53 mappings.
 */

export interface HipcheckNistMapping {
  Analysis: string;
  'NIST-ID': string;
  Rev: number;
  Rationale: string;
}

export type HipcheckNistMappings = HipcheckNistMapping[];
