/**
 * TypeScript types for CWE to NIST mappings
 */

export interface CweNistMapping {
  'CWE-ID': number;
  'CWE Name': string;
  'NIST-ID': string;
  Rev: number;
  'NIST Name': string;
}

export type CweNistMappings = CweNistMapping[];
