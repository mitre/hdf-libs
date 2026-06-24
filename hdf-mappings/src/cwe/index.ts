/**
 * Query functions for CWE to NIST mappings.
 *
 * Lookups are revision-aware: each accepts an optional `rev` defaulting to the
 * module-global current revision, so existing callers keep getting the default.
 */

import type { CweNistMapping, CweNistMappings } from './types.js';
import { getCurrentNistRevision } from '../nist/index.js';
import rawMappings from '../data/cwe-nist-mappings.json';

const mappings = rawMappings as CweNistMappings;

// revision → (CWE-ID → mapping)
const byRev = new Map<number, Map<number, CweNistMapping>>();
for (const m of mappings) {
  let idx = byRev.get(m.Rev);
  if (!idx) {
    idx = new Map<number, CweNistMapping>();
    byRev.set(m.Rev, idx);
  }
  idx.set(m['CWE-ID'], m);
}

function indexFor(rev: number): Map<number, CweNistMapping> {
  return byRev.get(rev) ?? new Map<number, CweNistMapping>();
}

/** Get the full mapping for a CWE ID at the given NIST revision. */
export function getCweNistMapping(
  cweId: number,
  rev: number = getCurrentNistRevision()
): CweNistMapping | undefined {
  return indexFor(rev).get(cweId);
}

/** Get the NIST control ID for a CWE ID at the given NIST revision. */
export function getCweNistControl(cweId: number, rev: number = getCurrentNistRevision()): string | undefined {
  return getCweNistMapping(cweId, rev)?.['NIST-ID'];
}

/** Get the CWE name for a CWE ID at the given NIST revision. */
export function getCweName(cweId: number, rev: number = getCurrentNistRevision()): string | undefined {
  return getCweNistMapping(cweId, rev)?.['CWE Name'];
}

/** Get all CWE IDs present at the given NIST revision. */
export function getAllCweIds(rev: number = getCurrentNistRevision()): number[] {
  return Array.from(indexFor(rev).keys());
}

/** Check whether a CWE ID exists at the given NIST revision. */
export function cweExists(cweId: number, rev: number = getCurrentNistRevision()): boolean {
  return indexFor(rev).has(cweId);
}

/** Get all CWE to NIST mappings (all revisions). */
export function getAllCweMappings(): CweNistMappings {
  return [...mappings];
}
