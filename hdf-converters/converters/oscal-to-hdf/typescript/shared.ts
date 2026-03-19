/**
 * Shared helper functions for OSCAL-to-HDF converters.
 *
 * Mirrors the Go helpers in converters/oscal-to-hdf/go/shared.go.
 */

import type { Property, Part, Characterization, Metadata } from './types.js';

const controlEnhancementRe = /^([a-z]{2}-\d+)\.(\d+)$/;
const objectiveIDRe = /^([a-z]{2}-\d+(?:\.\d+)?)/;

/**
 * Converts an OSCAL control ID to NIST 800-53 notation.
 * "ac-1" -> "AC-1", "ac-2.3" -> "AC-2 (3)"
 */
export function controlIdToNistTag(id: string): string {
  const m = controlEnhancementRe.exec(id);
  if (m) {
    return `${m[1]!.toUpperCase()} (${m[2]!})`;
  }
  return id.toUpperCase();
}

/**
 * Converts a list of OSCAL control IDs to NIST tags, deduplicating.
 */
export function controlIdsToNistTags(ids: string[]): string[] {
  const tags: string[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const tag = controlIdToNistTag(id);
    if (!seen.has(tag)) {
      seen.add(tag);
      tags.push(tag);
    }
  }
  return tags;
}

/**
 * Extracts the base control ID from a SAR objective ID.
 * "ac-1.a.1_obj.1" -> "ac-1"
 */
export function extractControlIdFromObjectiveId(objectiveId: string): string {
  const m = objectiveIDRe.exec(objectiveId);
  if (m) {
    return m[1]!;
  }
  return objectiveId;
}

/**
 * Maps OSCAL finding/risk status strings to HDF-compatible status strings.
 * "satisfied"/"closed" -> "passed", "not-satisfied"/"open" -> "failed"
 */
export function oscalStatusToHdf(state: string): string | undefined {
  switch (state.toLowerCase().trim()) {
    case 'satisfied':
    case 'closed':
      return 'passed';
    case 'not-satisfied':
    case 'open':
      return 'failed';
    default:
      return undefined;
  }
}

/**
 * Finds the first property with the given name and returns its value.
 * If ns is non-empty, the property must also match that namespace.
 */
export function extractPropValue(
  props: Property[] | undefined,
  name: string,
  ns?: string,
): string | undefined {
  if (!props) return undefined;
  for (const p of props) {
    if (p.name === name && (!ns || p.ns === ns)) {
      return p.value;
    }
  }
  return undefined;
}

/**
 * Returns all property values matching the given name.
 */
export function extractAllPropValues(
  props: Property[] | undefined,
  name: string,
  ns?: string,
): string[] {
  if (!props) return [];
  const values: string[] = [];
  for (const p of props) {
    if (p.name === name && (!ns || p.ns === ns)) {
      values.push(p.value);
    }
  }
  return values;
}

/**
 * Recursively concatenates prose from a Part tree, joining with newlines.
 */
export function flattenParts(parts: Part[] | undefined): string {
  if (!parts) return '';
  const pieces: string[] = [];
  flattenPartsRecursive(parts, pieces);
  return pieces.join('\n').trim();
}

function flattenPartsRecursive(parts: Part[], pieces: string[]): void {
  for (const p of parts) {
    if (p.prose) {
      pieces.push(p.prose);
    }
    if (p.parts && p.parts.length > 0) {
      flattenPartsRecursive(p.parts, pieces);
    }
  }
}

/**
 * Like flattenParts but only includes top-level parts matching the given name.
 * Nested parts are included regardless of their name.
 */
export function flattenPartsByName(
  parts: Part[] | undefined,
  name: string,
): string {
  if (!parts) return '';
  const pieces: string[] = [];
  for (const p of parts) {
    if (p.name === name) {
      if (p.prose) {
        pieces.push(p.prose);
      }
      if (p.parts && p.parts.length > 0) {
        flattenPartsRecursive(p.parts, pieces);
      }
    }
  }
  return pieces.join('\n').trim();
}

/**
 * Extracts impact/severity from risk characterization facets.
 * Returns a normalized 0.0-1.0 impact value. Falls back to defaultImpact.
 */
export function extractRiskSeverity(
  characterizations: Characterization[] | undefined,
  defaultImpact: number,
): number {
  if (!characterizations) return defaultImpact;
  for (const c of characterizations) {
    if (!c.facets) continue;
    for (const f of c.facets) {
      if (f.name === 'impact' || f.name === 'risk' || f.name === 'likelihood') {
        switch (f.value.toLowerCase()) {
          case 'critical':
            return 0.9;
          case 'high':
            return 0.7;
          case 'moderate':
          case 'medium':
            return 0.5;
          case 'low':
            return 0.3;
          case 'info':
          case 'informational':
          case 'none':
            return 0.0;
        }
      }
    }
  }
  return defaultImpact;
}

/** Holds extracted metadata common to all OSCAL documents. */
export interface MetadataInfo {
  title: string;
  version: string;
  oscalVersion: string;
  lastModified: string;
}

/** Pulls common fields from OSCAL metadata. */
export function extractMetadata(m: Metadata): MetadataInfo {
  return {
    title: m.title,
    version: m.version,
    oscalVersion: m['oscal-version'],
    lastModified: m['last-modified'],
  };
}

/**
 * Converts a title to kebab-case, truncated to 80 characters.
 * Shared utility used by multiple converters for deriving names.
 */
export function toKebabCase(title: string, fallback: string): string {
  if (!title) return fallback;
  let name = title.toLowerCase();
  name = name.replace(/[^a-z0-9]/g, '-');
  // Collapse consecutive dashes
  while (name.includes('--')) {
    name = name.replace(/--/g, '-');
  }
  name = name.replace(/^-+|-+$/g, '');
  if (name.length > 80) {
    name = name.slice(0, 80);
  }
  return name;
}
