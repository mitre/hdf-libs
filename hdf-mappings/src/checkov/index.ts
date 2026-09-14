/**
 * Query functions for Checkov check ID to CCI/NIST mappings.
 *
 * The dataset is the JSON file the Go loader embeds (go/checkov/), imported
 * directly so both languages read one file; the bundler inlines it into dist.
 */

import type { CheckovCciNistMapping, CheckovMappingDataset, CheckovMappingProvenance } from './types.js';
import { getCurrentNistRevision, nistControlsAtRevision } from '../nist/index.js';
import rawDataset from '../../go/checkov/checkov-cci-nist-mappings.json';

const dataset = rawDataset as CheckovMappingDataset;

// A Map, not the raw object, so ids like "constructor" never hit the prototype.
const byCheckId = new Map<string, CheckovCciNistMapping>(Object.entries(dataset.mappings));

/**
 * Get the CCI and NIST controls for a Checkov check ID, with NIST controls
 * translated to the given revision. CCIs are revision-independent.
 * @returns copies of both lists, or undefined if the check is unmapped
 */
export function getCheckovCciNistMapping(
  checkId: string,
  rev: number = getCurrentNistRevision()
): CheckovCciNistMapping | undefined {
  const m = byCheckId.get(checkId);
  if (!m) return undefined;
  return {
    cci: [...m.cci],
    nist: nistControlsAtRevision([...m.nist], dataset.nistRevision, rev),
  };
}

/** Check whether a Checkov check ID has a mapping. */
export function checkovCheckExists(checkId: string): boolean {
  return byCheckId.has(checkId);
}

/** Get all mapped Checkov check IDs, sorted. */
export function getAllCheckovCheckIds(): string[] {
  return Array.from(byCheckId.keys()).sort();
}

/** Get the dataset's source package, Checkov version and native NIST revision. */
export function getCheckovMappingProvenance(): CheckovMappingProvenance {
  return {
    source: { ...dataset.source },
    checkovVersion: dataset.checkovVersion,
    updated: dataset.updated,
    nistRevision: dataset.nistRevision,
  };
}
