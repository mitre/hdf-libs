/**
 * Query functions for hadolint rule code to NIST mappings.
 *
 * One table covers both hadolint's own DL rules and the SC rules it surfaces
 * from its embedded shellcheck. The dataset is the JSON file the Go loader
 * embeds (go/hadolint/), imported directly so both languages read one file;
 * the bundler inlines it into dist.
 */

import type { HadolintMappingDataset, HadolintMappingProvenance, HadolintNistMapping } from './types.js';
import { getCurrentNistRevision, nistControlsAtRevision } from '../nist/index.js';
import rawDataset from '../../go/hadolint/hadolint-nist-mappings.json';

const dataset = rawDataset as HadolintMappingDataset;

// A Map, not the raw object, so ids like "constructor" never hit the prototype.
const byRuleId = new Map<string, HadolintNistMapping>(Object.entries(dataset.mappings));

/**
 * Get the NIST controls for a hadolint rule code, translated to the given
 * revision.
 *
 * A rule whose controls do not survive translation comes back mapped but with
 * an empty list — SR-4 has no Rev 4 equivalent — so a caller must treat an
 * empty list the same as an absent mapping and apply its own fallback.
 *
 * @returns a copy of the control list, or undefined if the rule is unmapped
 */
export function getHadolintNistMapping(
  ruleId: string,
  rev: number = getCurrentNistRevision()
): HadolintNistMapping | undefined {
  const m = byRuleId.get(ruleId);
  if (!m) return undefined;
  return {nist: nistControlsAtRevision([...m.nist], dataset.nistRevision, rev)};
}

/** Check whether a hadolint rule code has a mapping. */
export function hadolintRuleExists(ruleId: string): boolean {
  return byRuleId.has(ruleId);
}

/** Get all mapped hadolint rule codes, sorted. */
export function getAllHadolintRuleIds(): string[] {
  return [...byRuleId.keys()].sort();
}

/** Get the dataset's upstream source and native NIST revision. */
export function getHadolintMappingProvenance(): HadolintMappingProvenance {
  return {
    source: {...dataset.source},
    updated: dataset.updated,
    nistRevision: dataset.nistRevision,
  };
}
