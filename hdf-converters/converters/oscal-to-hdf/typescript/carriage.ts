/**
 * Foreign-prop carriage through HDF for OSCAL SAR (ADR-0014 §3). The importer
 * stores every OSCAL prop it does not consume in the reserved requirement tag
 * `oscal-props`, and the exporter re-emits them. Mirrors the Go peer in
 * converters/oscal-to-hdf/go/carriage.go.
 */

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
    if (p.ns !== undefined) entry.ns = p.ns;
    if (p.class !== undefined) entry.class = p.class;
    if (p.group !== undefined) entry.group = p.group;
    if (p.uuid !== undefined) entry.uuid = p.uuid;
    if (p.remarks !== undefined) entry.remarks = p.remarks;
    entries.push(entry);
  }
}

const isStr = (v: unknown): v is string => typeof v === 'string';

/** Reads the oscal-props entries stored on an HDF requirement's tags. */
export function readCarriedProps(tags: Record<string, unknown> | undefined): CarriedProp[] {
  const raw = tags?.[OSCAL_PROPS_TAG];
  if (!Array.isArray(raw)) return [];
  return raw.filter((e): e is CarriedProp => {
    if (typeof e !== 'object' || e === null) return false;
    const o = e as Record<string, unknown>;
    return isStr(o.on) && isStr(o.name) && isStr(o.value);
  });
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
    if (e.ns !== undefined) prop.ns = e.ns;
    if (e.class !== undefined) prop.class = e.class;
    if (e.group !== undefined) prop.group = e.group;
    if (e.uuid !== undefined) prop.uuid = e.uuid;
    if (e.remarks !== undefined) prop.remarks = e.remarks;
    props.push(prop);
  }
  return props;
}

function carriageKey(ns: string | undefined, name: string, value: string): string {
  const namespace = ns === undefined || ns === '' ? vocabularyDefaultNamespace() : ns;
  return JSON.stringify([namespace, name, value]);
}
