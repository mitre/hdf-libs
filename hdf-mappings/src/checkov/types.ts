/**
 * TypeScript types for Checkov check ID to CCI/NIST mappings
 */

export interface CheckovCciNistMapping {
  cci: string[];
  nist: string[];
}

export type CheckovCciNistMappings = Record<string, CheckovCciNistMapping>;

export interface CheckovMappingProvenance {
  source: {
    package: string;
    version: string;
    path: string;
    integrity: string;
  };
  checkovVersion: string;
  updated: string;
  nistRevision: number;
}

export interface CheckovMappingDataset extends CheckovMappingProvenance {
  $comment: string[];
  mappings: CheckovCciNistMappings;
}
