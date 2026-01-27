/**
 * TypeScript types for ScoutSuite to NIST mappings
 */

export interface ScoutsuiteNistMapping {
  RULE: string;
  'NIST-ID': string;
}

export type ScoutsuiteNistMappings = ScoutsuiteNistMapping[];
