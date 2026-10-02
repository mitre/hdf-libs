/**
 * Foreign-prop carriage through HDF for OSCAL SAR (ADR-0014 §3). The importer
 * stores every OSCAL prop it does not consume in the reserved requirement tag
 * `oscal-props`, and the exporter re-emits them. Mirrors the Go peer in
 * converters/oscal-to-hdf/go/carriage.go.
 */

import { emitConverterWarning } from '../../../shared/typescript/converterutil.js';
import type { Property } from './types.js';
import { consumedVocabularyProp, vocabularyDefaultNamespace } from './vocabulary.js';

/** The reserved HDF requirement tag that carries unconsumed OSCAL SAR props. */
export const OSCAL_PROPS_TAG = 'oscal-props';

/** The OSCAL object a carried prop was attached to. */
export type CarriageOn = 'finding' | 'observation' | 'risk';

/**
 * One entry of the oscal-props tag (ADR-0014 §3.3). `on`, `name` and `value`
 * are always present; the rest are present exactly when the source prop has them.
 */
export interface CarriedProp {
  on: CarriageOn;
  name: string;
  value: string;
  ns?: string;
  class?: string;
  group?: string;
  uuid?: string;
  remarks?: string;
}

/**
 * Appends a carriage entry for every prop that HDF does not consume (ADR-0014
 * §3.1). `on` is the OSCAL object the props hang on. Source order is preserved.
 */
export function carryForeignProps(entries: CarriedProp[], on: CarriageOn, props: Property[] | undefined): void {
  for (const p of props ?? []) {
    if (consumedVocabularyProp(p)) continue;
    const entry: CarriedProp = { on, name: p.name, value: p.value };
    // An empty optional is absent, as the Go peer's omitempty makes it.
    if (p.ns) entry.ns = p.ns;
    if (p.class) entry.class = p.class;
    if (p.group) entry.group = p.group;
    if (p.uuid) entry.uuid = p.uuid;
    if (p.remarks) entry.remarks = p.remarks;
    entries.push(entry);
  }
}

const isStr = (v: unknown): v is string => typeof v === 'string';

const CARRIAGE_ON: readonly string[] = ['finding', 'observation', 'risk'];
const CARRIAGE_OPTIONAL_MEMBERS: readonly string[] = ['ns', 'class', 'group', 'uuid', 'remarks'];
const CARRIAGE_MEMBERS = new Set<string>(['on', 'name', 'value', ...CARRIAGE_OPTIONAL_MEMBERS]);

/**
 * Whether one decoded oscal-props entry conforms to
 * shared/oscal-props.schema.json. A foreign document may put anything in the tag,
 * and an entry the emitter would turn into a non-string OSCAL prop member, or
 * place on no object at all, is not carriage but corruption. Mirrors the Go peer.
 */
export function validCarriedProp(entry: unknown): entry is CarriedProp {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return false;
  const o = entry as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!CARRIAGE_MEMBERS.has(k)) return false;
  if (!isStr(o.on) || !CARRIAGE_ON.includes(o.on)) return false;
  if (!isStr(o.name) || o.name.length === 0) return false;
  if (!isStr(o.value)) return false;
  for (const k of CARRIAGE_OPTIONAL_MEMBERS) {
    if (k in o && !isStr(o[k])) return false;
  }
  return true;
}

/**
 * Reads the oscal-props entries stored on requirement `requirementId`'s tags.
 * Carriage is best-effort preservation, so reading is per-entry tolerant: a
 * conforming entry is kept, a malformed one is dropped, and the requirement's
 * drops are reported once. Mirrors the Go peer.
 */
export function readCarriedProps(tags: Record<string, unknown> | undefined, requirementId: string): CarriedProp[] {
  const raw = tags?.[OSCAL_PROPS_TAG];
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    emitConverterWarning(`Dropping the oscal-props tag on requirement ${JSON.stringify(requirementId)}: it is not an array`);
    return [];
  }
  const entries = raw.filter(validCarriedProp);
  const dropped = raw.length - entries.length;
  if (dropped > 0) {
    emitConverterWarning(
      `Dropping ${dropped} malformed oscal-props ${dropped === 1 ? 'entry' : 'entries'} on requirement ${JSON.stringify(requirementId)}`,
    );
  }
  return entries;
}

/** The entries whose `on` matches, in carried order. */
export function carriedFor(entries: CarriedProp[], on: CarriageOn): CarriedProp[] {
  return entries.filter((e) => e.on === on);
}

/**
 * Re-emits carried entries onto an object's props after its own props (ADR-0014
 * §3.4), skipping any entry whose (ns, name, value) is already present — an
 * absent ns compares equal to NIST's default namespace.
 */
export function appendCarriedProps(props: Property[], entries: CarriedProp[]): Property[] {
  const seen = new Set<string>();
  for (const p of props) seen.add(carriageKey(p.ns, p.name, p.value));
  for (const e of entries) {
    const key = carriageKey(e.ns, e.name, e.value);
    if (seen.has(key)) continue;
    seen.add(key);
    const prop: Property = { name: e.name, value: e.value };
    if (e.ns) prop.ns = e.ns;
    if (e.class) prop.class = e.class;
    if (e.group) prop.group = e.group;
    if (e.uuid) prop.uuid = e.uuid;
    if (e.remarks) prop.remarks = e.remarks;
    props.push(prop);
  }
  return props;
}

function carriageKey(ns: string | undefined, name: string, value: string): string {
  const namespace = ns === undefined || ns === '' ? vocabularyDefaultNamespace() : ns;
  return JSON.stringify([namespace, name, value]);
}
