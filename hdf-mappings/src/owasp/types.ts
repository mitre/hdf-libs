/**
 * TypeScript types for OWASP Top 10 to NIST mappings
 */

export interface OwaspNistMapping {
  'OWASP-ID': string;
  'OWASP Name': string;
  'NIST-ID': string;
  Rev: number;
  'NIST Name': string;
}

export type OwaspNistMappings = OwaspNistMapping[];
