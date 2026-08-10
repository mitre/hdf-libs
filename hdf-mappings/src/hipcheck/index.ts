/**
 * Query functions for Hipcheck analysis to NIST 800-53 Rev 5 mappings.
 *
 * The mapping is a hand-curated, RMF-reviewed table (Hipcheck publishes no
 * analysis-to-controls crosswalk). The data file is byte-identical to its Go
 * peer at hdf-mappings/go/hipcheck/hipcheck-nist-mappings.json.
 */

import type { HipcheckNistMapping, HipcheckNistMappings } from './types.js';
import rawMappings from '../data/hipcheck-nist-mappings.json';
import { getCurrentNistRevision, nistControlsAtRevision } from '../nist/index.js';

// Authored against Rev 5 (declared Rev: 5 in the data; it carries SR-family
// controls that do not exist at Rev 4). Lookups translate to the current
// module-global revision.
const NATIVE_REVISION = 5;

const mappings = rawMappings as HipcheckNistMappings;

const byAnalysis = new Map<string, HipcheckNistMapping>();
for (const m of mappings) {
  byAnalysis.set(m.Analysis, m);
}

/**
 * Strip a plugin publisher prefix ("mitre/binary" -> "binary") so lookups key
 * on the analysis name regardless of publisher.
 */
function bareName(analysis: string): string {
  const i = analysis.lastIndexOf('/');
  return i >= 0 ? analysis.slice(i + 1) : analysis;
}

/**
 * Get the NIST 800-53 controls for a Hipcheck analysis name.
 * Accepts bare ("binary") or publisher-prefixed ("mitre/binary") names.
 * @returns array of control IDs, or [] if the analysis has no mapping
 */
export function getHipcheckNistControls(analysis: string): string[] {
  const m = byAnalysis.get(bareName(analysis));
  if (!m) return [];
  const controls = m['NIST-ID']
    .split('|')
    .map((s) => s.trim())
    .filter(Boolean);
  return nistControlsAtRevision(controls, NATIVE_REVISION, getCurrentNistRevision());
}

/** Check whether a Hipcheck analysis name has a NIST mapping. */
export function hipcheckAnalysisExists(analysis: string): boolean {
  return byAnalysis.has(bareName(analysis));
}

/** Get all mapped Hipcheck analysis names, sorted. */
export function getAllHipcheckAnalyses(): string[] {
  return Array.from(byAnalysis.keys()).sort();
}

/** Get all Hipcheck to NIST mappings. */
export function getAllHipcheckMappings(): HipcheckNistMappings {
  return [...mappings];
}
