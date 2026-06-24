/**
 * Query functions for AWS Config to NIST mappings.
 *
 * Lookups are revision-aware: each accepts an optional `rev` defaulting to the
 * module-global current revision, so existing callers keep getting the default.
 */

import type { AwsConfigNistMapping, AwsConfigNistMappings } from './types.js';
import { getCurrentNistRevision, SUPPORTED_NIST_REVISIONS } from '../nist/index.js';
import rawMappings from '../data/awsconfig-mappings.json';

const mappings = rawMappings as AwsConfigNistMappings;

// revision → (key → mapping), for both source-identifier and rule-name lookup
const byIdentifier = new Map<number, Map<string, AwsConfigNistMapping>>();
const byRuleName = new Map<number, Map<string, AwsConfigNistMapping>>();
for (const m of mappings) {
  if (!byIdentifier.has(m.Rev)) {
    byIdentifier.set(m.Rev, new Map());
    byRuleName.set(m.Rev, new Map());
  }
  byIdentifier.get(m.Rev)!.set(m.AwsConfigRuleSourceIdentifier, m);
  byRuleName.get(m.Rev)!.set(m.AwsConfigRuleName, m);
}

function idIndex(rev: number): Map<string, AwsConfigNistMapping> {
  return byIdentifier.get(rev) ?? new Map();
}
function nameIndex(rev: number): Map<string, AwsConfigNistMapping> {
  return byRuleName.get(rev) ?? new Map();
}

/** Get the full mapping for an AWS Config rule by source identifier. */
export function getAwsConfigNistMappingByIdentifier(
  identifier: string,
  rev: number = getCurrentNistRevision()
): AwsConfigNistMapping | undefined {
  return idIndex(rev).get(identifier);
}

/** Get the full mapping for an AWS Config rule by rule name. */
export function getAwsConfigNistMappingByName(
  ruleName: string,
  rev: number = getCurrentNistRevision()
): AwsConfigNistMapping | undefined {
  return nameIndex(rev).get(ruleName);
}

/** Get the NIST control ID for an AWS Config rule by source identifier. */
export function getAwsConfigNistControlByIdentifier(
  identifier: string,
  rev: number = getCurrentNistRevision()
): string | undefined {
  return getAwsConfigNistMappingByIdentifier(identifier, rev)?.['NIST-ID'];
}

/** Get the NIST control ID for an AWS Config rule by rule name. */
export function getAwsConfigNistControlByName(
  ruleName: string,
  rev: number = getCurrentNistRevision()
): string | undefined {
  return getAwsConfigNistMappingByName(ruleName, rev)?.['NIST-ID'];
}

/** Get all AWS Config rule source identifiers present at the given revision. */
export function getAllAwsConfigIdentifiers(rev: number = getCurrentNistRevision()): string[] {
  return Array.from(idIndex(rev).keys());
}

/** Get all AWS Config rule names present at the given revision. */
export function getAllAwsConfigRuleNames(rev: number = getCurrentNistRevision()): string[] {
  return Array.from(nameIndex(rev).keys());
}

/** Check if an AWS Config rule exists by source identifier at the given revision. */
export function awsConfigIdentifierExists(identifier: string, rev: number = getCurrentNistRevision()): boolean {
  return idIndex(rev).has(identifier);
}

/** Check if an AWS Config rule exists by rule name at the given revision. */
export function awsConfigRuleNameExists(ruleName: string, rev: number = getCurrentNistRevision()): boolean {
  return nameIndex(rev).has(ruleName);
}

/**
 * Get the supported NIST revisions at which the rule resolves (by source
 * identifier or rule name), sorted ascending. Mirrors the resolution
 * buildNistTags performs, so a revision is included exactly when a conversion
 * at that revision would emit NIST tags. Empty means unmapped everywhere — a
 * coverage gap, not a revision mismatch.
 */
export function awsConfigMappedRevisions(identifier: string, ruleName: string): number[] {
  const revs: number[] = [];
  for (const rev of SUPPORTED_NIST_REVISIONS) {
    const byId = identifier ? getAwsConfigNistControlByIdentifier(identifier, rev) : undefined;
    const byName = ruleName ? getAwsConfigNistControlByName(ruleName, rev) : undefined;
    if (byId || byName) {
      revs.push(rev);
    }
  }
  return revs;
}

/** Get all AWS Config to NIST mappings (all revisions). */
export function getAllAwsConfigMappings(): AwsConfigNistMappings {
  return [...mappings];
}
