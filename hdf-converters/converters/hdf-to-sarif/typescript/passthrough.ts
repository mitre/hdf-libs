/**
 * Carriage of SARIF property bags through HDF, and of the HDF data SARIF has no
 * field for. The Go peer is ../go/passthrough.go.
 */
import { type Obj, asArr, asMap, getStr } from '../../../shared/typescript/exportmap.js';

/**
 * The single reserved property-bag key under which HDF data that SARIF has no
 * field for is carried. One key rather than many prefixed ones keeps the
 * collision surface minimal and groups the block for a consumer.
 */
export const HDF_BAG_KEY = 'hdf';

/**
 * The requirement tag carrying SARIF region precision
 * (startColumn/endLine/endColumn/offsets/snippet). HDF's Source_Location is
 * {ref, line} and closed, so the rest of a region lives in this documented tag
 * convention rather than in a schema field.
 */
export const REGION_TAG = 'sarif-region';

/** The version of the extensions.passthrough.sarif carriage block this reads. */
export const PASSTHROUGH_SCHEMA_VERSION = 1;

/**
 * The objects a carried SARIF property bag can be addressed to. SARIF §3.8.1
 * puts a properties bag on every object, so carriage cannot enumerate bag KEYS —
 * Appendix D tells producers to name them after the native tool's own fields.
 * What it can enumerate is the objects THIS exporter emits, which is what an
 * address names.
 */
export type BagTarget = 'log' | 'run' | 'driver' | 'conversion' | 'rule' | 'result' | 'location';

/**
 * Identifies the SARIF object a carried bag belongs to by the HDF identities
 * that survive a conversion, never by array position: HDF groups, deduplicates
 * and reorders, so /runs/0/results/3 would silently reattach a bag to a
 * different finding. Baseline name addresses the run, requirement id the rule,
 * and the result's index WITHIN its requirement the individual result.
 */
export interface BagAddress {
  on: BagTarget;
  baseline?: string;
  ruleId?: string;
  ordinal?: number;
  index?: number;
}

/**
 * The SARIF property bags a document retained, keyed by address. The entry shape
 * mirrors ADR-0014 §3's oscal-props convention — a flat array in source order,
 * each entry naming the object its payload came from — widened to a tuple
 * because SARIF nests deeper than OSCAL's three objects.
 */
export class CarriedBags {
  private readonly bags = new Map<string, Obj>();

  add(address: BagAddress, props: Obj): void {
    this.bags.set(key(address), props);
  }

  find(address: BagAddress): Obj | undefined {
    return this.bags.get(key(address));
  }
}

function key(a: BagAddress): string {
  return [a.on, a.baseline ?? '', a.ruleId ?? '', a.ordinal ?? 0, a.index ?? 0].join('\u0000');
}

/**
 * Reads extensions.passthrough.sarif.propertyBags[].
 *
 * extensions is closed to passthrough and rawSourceArtifacts, so a namespaced
 * key inside passthrough is the only place SARIF-specific carriage can live. A
 * malformed entry is skipped rather than failing the conversion: carriage is
 * bookkeeping, and losing a bag must not cost the document its findings.
 */
export function readCarriedBags(doc: Obj): CarriedBags {
  const block = asMap(asMap(asMap(doc.extensions)?.passthrough)?.sarif);
  const bags = new CarriedBags();
  for (const raw of asArr(block?.propertyBags) ?? []) {
    const entry = asMap(raw);
    if (!entry) continue;
    const props = asMap(entry.properties);
    if (!props || Object.keys(props).length === 0) continue;
    bags.add(
      {
        on: getStr(entry, 'on') as BagTarget,
        baseline: getStr(entry, 'baseline'),
        ruleId: getStr(entry, 'ruleId'),
        ordinal: typeof entry.ordinal === 'number' ? entry.ordinal : 0,
        index: typeof entry.index === 'number' ? entry.index : 0,
      },
      props,
    );
  }
  return bags;
}

/**
 * Writes an object's properties bag: this exporter's own keys first, then the
 * carried ones, skipping any key the exporter already set.
 *
 * The exporter wins deliberately — verbatim carriage buys bookkeeping fidelity
 * and mapping buys semantic fidelity, so a carried value never overwrites one
 * this converter derived from an HDF field. Mirrors ADR-0014 §3.4.
 */
export function setBag(obj: Obj, own: Obj | undefined, carried: Obj | undefined): void {
  if (!own && !carried) return;
  const props: Obj = { ...(own ?? {}) };
  for (const [k, v] of Object.entries(carried ?? {})) {
    // tags is merged below; the schema requires the array be distinct.
    if (k === 'tags') continue;
    if (!(k in props)) props[k] = v;
  }
  const tags = mergeTags(own?.tags, carried?.tags);
  if (tags.length > 0) props.tags = tags;
  if (Object.keys(props).length > 0) obj.properties = props;
}

/**
 * Unions two propertyBag tags arrays. Sorted and deduplicated because the schema
 * puts uniqueItems on the array and the two languages must agree on the order.
 */
function mergeTags(own: unknown, carried: unknown): string[] {
  const tags = new Set<string>();
  for (const side of [own, carried]) {
    for (const raw of asArr(side) ?? []) if (typeof raw === 'string') tags.add(raw);
  }
  return [...tags].sort();
}

/**
 * The producer data in extensions.passthrough that this converter did not
 * consume.
 *
 * rawSourceArtifacts is dropped deliberately: it holds the bytes the document
 * was converted FROM, not data about the findings, and echoing a whole source
 * artifact back into the output both multiplies its size and invites a consumer
 * to replay those bytes instead of reading the fields this exporter mapped.
 */
export function remainingExtensions(doc: Obj): Obj | undefined {
  const passthrough = asMap(asMap(doc.extensions)?.passthrough);
  if (!passthrough || Object.keys(passthrough).length === 0) return undefined;
  const kept: Obj = {};
  for (const [k, v] of Object.entries(passthrough)) {
    // Consumed by readCarriedBags. A bag whose address matches an emitted object is
    // re-emitted onto it; one whose address matches nothing is dropped from the output
    // entirely rather than preserved here. It survives in the INPUT document, which is
    // not the same as surviving the export.
    if (k === 'sarif') continue;
    kept[k] = v;
  }
  return Object.keys(kept).length > 0 ? { passthrough: kept } : undefined;
}

/**
 * The baseline-level counterpart: its passthrough only, for the same reason
 * rawSourceArtifacts is dropped at document level.
 */
export function baselineExtensions(baseline: Obj): Obj | undefined {
  const passthrough = asMap(asMap(baseline.extensions)?.passthrough);
  if (!passthrough || Object.keys(passthrough).length === 0) return undefined;
  return { passthrough };
}

/**
 * Copies a result row without its rawSourceRecord.
 *
 * The record holds the native finding's own bytes — the converter's input, not
 * data about the finding — and this exporter re-derives every SARIF result from
 * the mapped HDF fields. Carrying the bytes alongside would roughly double the
 * output for a SARIF-sourced document and offer a consumer a byte-replay that
 * bypasses the mapping, which is exactly the shortcut that makes a round-trip
 * test prove nothing.
 */
export function withoutRawSourceRecord(row: Obj): Obj {
  if (!('rawSourceRecord' in row)) return row;
  const kept: Obj = {};
  for (const [k, v] of Object.entries(row)) if (k !== 'rawSourceRecord') kept[k] = v;
  return kept;
}
