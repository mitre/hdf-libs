/**
 * TypeScript types for Nessus to NIST mappings
 */

export interface NessusNistMapping {
  pluginFamily: string;
  pluginID: string;
  'NIST-ID': string;
}

export type NessusNistMappings = NessusNistMapping[];
