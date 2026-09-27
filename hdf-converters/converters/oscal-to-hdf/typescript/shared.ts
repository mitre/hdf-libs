/**
 * Shared helper functions for OSCAL-to-HDF converters.
 *
 * Mirrors the Go helpers in converters/oscal-to-hdf/go/shared.go.
 */

import { SUPPORTED_NIST_REVISIONS, nistExists, normalizeNistId } from '@mitre/hdf-mappings';
import { impactToSeverity as sharedImpactToSeverity, severityToImpactWithAliases } from '@mitre/hdf-utilities';
import { oscalSeverityFromHdf } from '../../../shared/typescript/converterutil.js';
import type { Property, Part, Characterization, DocumentMetadata, Oscal } from './types.js';
import { findVocabularyProp, vocabularyProp } from './vocabulary.js';

const controlEnhancementRe = /^([a-z]{2}-\d+)\.(\d+)$/;
// The OSCAL control id a SAP objective id or lowercased SAR target-id starts with, as in "ac-1.a.1_obj.1".
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
 * Extracts the base control ID from an assessment-plan objective ID.
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

/** The one OSCAL spelling the standard severity map does not know; every other
 *  facet value is standard vocabulary. */
const RISK_FACET_SEVERITY_ALIASES: Record<string, number> = { moderate: 0.5 };

/** Sentinel for "this facet's value is not a severity" — impact is 0.0-1.0, so
 *  a negative can never be a real reading. */
const UNRECOGNIZED_FACET_IMPACT = -1;

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
      if (f.name !== 'impact' && f.name !== 'risk' && f.name !== 'likelihood') continue;
      const impact = severityToImpactWithAliases(f.value, RISK_FACET_SEVERITY_ALIASES, UNRECOGNIZED_FACET_IMPACT);
      if (impact >= 0) return impact;
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
export function extractMetadata(m: DocumentMetadata): MetadataInfo {
  return {
    title: m.title,
    version: m.version,
    oscalVersion: m['oscal-version'],
    lastModified: String(m['last-modified']),
  };
}

/**
 * Returns the canonical OSCAL id of the NIST control a target-id names, when the
 * target, ignoring ASCII letter case, is a control ("ac-2", "ac-2.3"), optionally
 * followed by dot-separated parts and an objective or statement suffix
 * ("ac-2.3_obj.a", "au-1_smt.a", "ac-1.a.1_obj.1"), and NIST defines that control
 * at any supported revision; otherwise undefined, including for a target shaped
 * like a control NIST does not define. Mirrors Go's ConfirmedControlID.
 */
export function confirmedControlId(targetId: string): string | undefined {
  const target = asciiLower(targetId);
  const controlId = objectiveIDRe.exec(target)?.[0];
  if (controlId === undefined || !isObjectiveOrStatementSuffix(target.slice(controlId.length))) {
    return undefined;
  }
  const tag = controlIdToNistTag(controlId);
  return SUPPORTED_NIST_REVISIONS.some((rev) => nistExists(tag, rev)) ? nistTagToControlId(tag) : undefined;
}

/** Lowercases only ASCII letters, so Go and TypeScript fold identically. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/**
 * Whether rest, what follows a control id in a lowercased target-id, is empty or
 * names an objective or statement of that control: optional dot-separated
 * letter-and-digit parts, then "_obj" or "_smt", alone or followed by non-empty
 * dot-separated parts.
 */
function isObjectiveOrStatementSuffix(rest: string): boolean {
  if (rest === '') {
    return true;
  }
  const cut = rest.indexOf('_');
  if (cut < 0) {
    return false;
  }
  const parts = rest.slice(0, cut);
  if (parts !== '') {
    if (!parts.startsWith('.')) {
      return false;
    }
    if (parts.slice(1).split('.').some((part) => part === '' || !isLowerAlphanumeric(part))) {
      return false;
    }
  }
  const [kind, ...after] = rest.slice(cut + 1).split('.');
  return (kind === 'obj' || kind === 'smt') && !after.includes('');
}

function isLowerAlphanumeric(part: string): boolean {
  return [...part].every((c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
}

/**
 * Converts NIST 800-53 notation, in any spelling normalizeNistId accepts, to the
 * OSCAL id of the control it names; a statement part names its control. Anything
 * else is returned trimmed and lowercased.
 * "AC-1" -> "ac-1", "ac-2 (3)" -> "ac-2.3", "AC-8 c 1" -> "ac-8"
 */
export function nistTagToControlId(tag: string): string {
  return nistTagToControlRef(tag).controlId;
}

/**
 * Converts NIST 800-53 notation to the OSCAL control id and, for a statement
 * part, the OSCAL statement id ("AC-8 c 1" -> "ac-8", "ac-8_smt.c.1";
 * "AC-2 (3) (a)" -> "ac-2.3", "ac-2.3_smt.a"). statementId is empty when the tag
 * names a whole control. A tag that is not a NIST spelling is returned trimmed and
 * lowercased as controlId. Mirrors Go's NistTagToControlRef.
 */
export function nistTagToControlRef(tag: string): { controlId: string; statementId: string } {
  const trimmed = tag.trim();
  const normalized = normalizeNistId(trimmed.split(/\s+/).join(' '));
  if (normalized === undefined) {
    return { controlId: trimmed.toLowerCase(), statementId: '' };
  }
  // The normalized spelling is "AC-02", then space-separated padded numbers and
  // lowercase statement letters. Only a number directly after the control is an
  // enhancement; every NIST statement part begins with a letter.
  const [head, ...parts] = normalized.split(' ');
  const [family, number] = head!.split('-');
  let controlId = `${family!.toLowerCase()}-${unpadNistNumber(number!)}`;
  if (parts.length > 0 && parts[0]![0]! >= '0' && parts[0]![0]! <= '9') {
    controlId += `.${unpadNistNumber(parts.shift()!)}`;
  }
  if (parts.length === 0) {
    return { controlId, statementId: '' };
  }
  return { controlId, statementId: `${controlId}_smt.${parts.map(unpadNistNumber).join('.')}` };
}

/** Strips the zero normalizeNistId pads a one-digit number with. */
function unpadNistNumber(part: string): string {
  return part.length === 2 && part.startsWith('0') ? part.slice(1) : part;
}

/**
 * Converts a 0.0-1.0 impact value to an OSCAL severity string.
 * This is the reverse of extractRiskSeverity.
 */
export function impactToSeverity(impact: number): string {
  return oscalSeverityFromHdf(sharedImpactToSeverity(impact));
}

/**
 * Maps an HDF status string to an OSCAL risk status string.
 * "passed"/"notApplicable" -> "closed", everything else -> "open".
 */
export function hdfStatusToOscalRiskStatus(status: string): string {
  if (status === 'passed' || status === 'notApplicable') {
    return 'closed';
  }
  return 'open';
}

/** OSCAL specification version used in reverse converter output documents. */
export const OSCAL_VERSION = '1.1.2';

/**
 * Builds the description-label prop that marks an OSCAL prose home with the HDF
 * description label whose text it carries.
 */
export function descriptionLabelProp(label: string): Property {
  const prop = vocabularyProp('description-label', label);
  if (!prop) {
    throw new Error(`oscal: description label ${JSON.stringify(label)} yields no description-label prop`);
  }
  return prop;
}

/**
 * Returns props' description-label, or '' when there is none; a
 * description-label in any other namespace is foreign.
 */
export function descriptionLabel(props: Property[] | undefined): string {
  return findVocabularyProp(props, 'description-label')?.value ?? '';
}

/**
 * Parses an OSCAL document from JSON input, validates the document type.
 * Throws if input is empty, invalid JSON, or not the expected type.
 */
export function parseOscalDocument<T extends keyof Oscal>(
  input: string,
  expectedKey: T,
  converterName: string,
): NonNullable<Oscal[T]> {
  if (!input || input.trim().length === 0) {
    throw new Error(`${converterName}: empty input`);
  }

  let doc: Oscal;
  try {
    doc = JSON.parse(input) as Oscal;
  } catch {
    throw new Error(`${converterName}: failed to parse JSON`);
  }

  const value = doc[expectedKey];
  if (!value) {
    throw new Error(`${converterName}: expected ${String(expectedKey)} document`);
  }

  return value as NonNullable<Oscal[T]>;
}

/**
 * Converts a title to kebab-case, truncated to 80 characters.
 * Shared utility used by multiple converters for deriving names.
 */
export function toKebabCase(title: string, fallback: string): string {
  if (!title) return fallback;
  let name = title.toLowerCase();
  name = name.replace(/[^a-z0-9]/g, '-');
  // Collapse consecutive dashes (single pass; /-+/ is unambiguous, unlike the
  // anchored /^-+|-+$/ trim, whose backtracking is quadratic on dash runs)
  name = name.replace(/-+/g, '-');
  let start = 0;
  while (start < name.length && name[start] === '-') start++;
  let end = name.length;
  while (end > start && name[end - 1] === '-') end--;
  name = name.slice(start, end);
  if (name.length > 80) {
    name = name.slice(0, 80);
  }
  return name;
}

/**
 * Encode an arbitrary identifier into OSCAL's TokenDatatype shape:
 * `^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$`
 *
 * HDF requirement ids come from whatever the source tool numbers its rules with,
 * and only some of those shapes are already tokens. Measured across this
 * package's converter fixtures, 46% are not (57% of the distinct ids): package-style ids
 * carrying '/', CIS control numbers starting with a digit, advisory ids carrying
 * ':'. Copying one of those into a token-typed OSCAL field produces a document
 * the target schema rejects while the converter resolves successfully.
 *
 * The kept set is deliberately ASCII — [A-Za-z0-9._-] — rather than the wider
 * \p{L}/\p{N} the pattern permits. Delegating to each platform's Unicode tables
 * looked equivalent and was not: V8's \p{L}/\p{N} and Go's unicode package are
 * built from different Unicode versions, and comparing the two implementations
 * across the whole code-point range turned up 4657 characters they disagree on.
 * An explicit ASCII set has no such dependency and is identical in both languages
 * by construction. It costs nothing on real data: no requirement id in this
 * package's converter fixtures is non-ASCII, and a non-ASCII one
 * is preserved in full by the caller's source-id prop regardless.
 *
 * Every character outside that set becomes '_', and a leading '_' is prepended
 * when the result would not start with a letter or '_'. An id built only from
 * the kept characters is returned unchanged; note that this is narrower than
 * token shape, so a token-valid non-ASCII id such as "café" is still rewritten.
 *
 * Two different ids can encode to the same token ('a/b' and 'a:b' both yield
 * 'a_b'), which is why callers must also record the source id in the emitted
 * document — for SAR that is the finding's hdf-requirement-id prop.
 */
export function oscalToken(s: string): string {
  if (s === '') return '';

  const out = [...s].map((ch) => (/[A-Za-z0-9.\-_]/.test(ch) ? ch : '_')).join('');
  const [first = ''] = [...out];
  return /[A-Za-z_]/.test(first) ? out : `_${out}`;
}

/**
 * Render a value for a field OSCAL types as StringDatatype, whose pattern
 * `^\S(.*\S)?$` forbids an empty value and any leading or trailing whitespace.
 * HDF constrains none of the strings that feed those fields — no minLength
 * anywhere in hdf-amendments — so a padded or empty value is valid HDF that
 * would otherwise produce a document the target schema rejects at exit 0.
 *
 * Returns '' when nothing survives trimming, which callers treat as "omit this
 * field" rather than substituting a placeholder: OSCAL marks most of these
 * fields optional, so leaving one out says exactly as much as the source did.
 * The companion for token-typed fields is oscalToken.
 *
 * Mirrors OSCALString in the Go peer.
 */
export function oscalString(s: string): string {
  return s.trim();
}
