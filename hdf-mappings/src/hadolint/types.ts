/**
 * TypeScript types for hadolint rule code to NIST mappings
 */

export interface HadolintNistMapping {
  nist: string[];
}

export type HadolintNistMappings = Record<string, HadolintNistMapping>;

export interface HadolintMappingProvenance {
  source: {
    repository: string;
    path: string;
    commit: string;
    sha256: string;
  };
  updated: string;
  nistRevision: number;
}

export interface HadolintMappingDataset extends HadolintMappingProvenance {
  $comment: string[];
  mappings: HadolintNistMappings;
}
