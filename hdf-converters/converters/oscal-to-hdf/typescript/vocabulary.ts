/**
 * The HDF OSCAL extension vocabulary (ADR-0014 §1.5) and the helpers that emit
 * and read its props. The table is the JSON file the Go peer embeds, imported
 * directly so both languages read one file; the bundler inlines it into dist.
 */

import rawVocabulary from '../go/oscal-vocabulary.json';
import type { Property } from './types.js';

/** One prop of the OSCAL vocabulary hdf-libs exporters emit or read. */
export interface VocabularyRow {
  name: string;
  ns: string;
  objects: string[];
  meaning: string;
  valueFormat: string;
  hdfField: string | null;
  legacy: boolean;
}

interface VocabularyTable {
  namespace: string;
  defaultNamespace: string;
  props: VocabularyRow[];
}

/** A validated vocabulary table with its rows indexed by name. */
export interface Vocabulary extends VocabularyTable {
  byName: Map<string, VocabularyRow>;
}

/**
 * Validates a decoded vocabulary table and indexes its rows by name, throwing on
 * a malformed table. Mirrors newVocabulary in Go.
 */
export function validateVocabularyTable(raw: unknown): Vocabulary {
  const table = (raw ?? {}) as Partial<VocabularyTable>;
  if (typeof table.namespace !== 'string' || table.namespace === '') {
    throw new Error('oscal: the OSCAL vocabulary table has no namespace');
  }
  if (typeof table.defaultNamespace !== 'string' || table.defaultNamespace === '') {
    throw new Error('oscal: the OSCAL vocabulary table has no defaultNamespace');
  }
  if (!Array.isArray(table.props) || table.props.length === 0) {
    throw new Error('oscal: the OSCAL vocabulary table has no rows');
  }
  // A Map, not the raw object, so names like "constructor" never hit the prototype.
  const byName = new Map<string, VocabularyRow>();
  for (const row of table.props) {
    if (byName.has(row.name)) {
      throw new Error(`oscal: the OSCAL vocabulary table defines "${row.name}" twice`);
    }
    byName.set(row.name, row);
  }
  return { namespace: table.namespace, defaultNamespace: table.defaultNamespace, props: table.props, byName };
}

const table = validateVocabularyTable(rawVocabulary);
const byName = table.byName;

/** The ns URI of every prop HDF defines. */
export function vocabularyNamespace(): string {
  return table.namespace;
}

/** NIST's default namespace, which a prop with no ns belongs to. */
export function vocabularyDefaultNamespace(): string {
  return table.defaultNamespace;
}

/** A copy of every row of the vocabulary table. */
export function vocabularyRows(): VocabularyRow[] {
  return table.props.map((row) => ({ ...row, objects: [...row.objects] }));
}

function mustVocabularyRow(name: string): VocabularyRow {
  const row = byName.get(name);
  if (!row) {
    throw new Error(`oscal: "${name}" is not a row of the OSCAL vocabulary`);
  }
  return row;
}

/** Whether a UTF-16 code unit is ECMAScript \s whitespace, which is BMP-only. */
function isWhitespace(unit: string): boolean {
  return /\s/.test(unit);
}

/**
 * Renders an HDF value as an OSCAL StringDatatype (ADR-0014 §1.7.1): each run of
 * line terminators becomes one space, ECMAScript whitespace is trimmed from both
 * edges, and a value with nothing left becomes "_". An empty value stays empty;
 * carrying it is the caller's decision (§1.7.3). Mirrors NormalizePropValue in Go.
 */
export function normalizePropValue(value: string): string {
  if (value === '') return '';
  const joined = value.replace(/[\r\n\u2028\u2029]+/g, ' ');
  let start = 0;
  while (start < joined.length && isWhitespace(joined[start]!)) start++;
  let end = joined.length;
  while (end > start && isWhitespace(joined[end - 1]!)) end--;
  const normalized = joined.slice(start, end);
  return normalized === '' ? '_' : normalized;
}

/**
 * Builds the prop a vocabulary row names, in that row's namespace (omitted for
 * NIST's default namespace). The value is normalized (§1.7.1), and an HDF prop
 * whose value changed carries the exact value in remarks (§1.7.2). Returns
 * undefined for an empty value, which writes no prop. An unknown name throws:
 * every prop an exporter emits must be a row. Mirrors VocabularyProp in Go.
 */
export function vocabularyProp(name: string, value: string): Property | undefined {
  const row = mustVocabularyRow(name);
  if (value === '') return undefined;
  const prop: Property = { name: row.name, value: normalizePropValue(value) };
  if (row.ns !== table.defaultNamespace) {
    prop.ns = row.ns;
  }
  if (row.ns === table.namespace && prop.value !== value) {
    prop.remarks = value;
  }
  return prop;
}

/** Pushes vocabularyProp(name, value) onto props when it writes a prop. */
export function pushVocabularyProp(props: Property[], name: string, value: string): void {
  const prop = vocabularyProp(name, value);
  if (prop) props.push(prop);
}

/** Marks an optional HDF string field that is present but empty (§1.7.3). */
export function emptyFieldProp(field: string): Property {
  return mustFieldProp('empty-field', field);
}

/** Marks an HDF field OSCAL required a display fallback for (§1.7.4). */
export function absentFieldProp(field: string): Property {
  return mustFieldProp('absent-field', field);
}

function mustFieldProp(name: string, field: string): Property {
  const prop = vocabularyProp(name, field);
  if (!prop) {
    throw new Error(`oscal: ${name} needs the name of an HDF field`);
  }
  return prop;
}

/** A prop the read helpers matched to a vocabulary row. */
export interface PropMatch {
  /** The prop's position in the array searched. */
  index: number;
  /** The HDF value: an HDF prop's remarks when present (§1.7.2), otherwise its value. */
  value: string;
  /** A match through the pre-ADR fallback: a prop with no ns whose name is a legacy row (§1.4). */
  legacy: boolean;
}

/**
 * Matches a prop to a row by name and namespace. An absent ns is NIST's default
 * namespace, except that for a legacy row it is also accepted as the row's own prop.
 */
function matchVocabularyProp(row: VocabularyRow, index: number, p: Property): PropMatch | undefined {
  if (p.name !== row.name) return undefined;
  const ns = p.ns ?? '';
  let legacy = false;
  if ((ns === '' ? table.defaultNamespace : ns) !== row.ns) {
    if (ns !== '' || !row.legacy) return undefined;
    legacy = true;
  }
  const value = row.ns === table.namespace && p.remarks ? p.remarks : p.value;
  return { index, value, legacy };
}

/** The first prop in props that is the named row's prop. Mirrors FindVocabularyProp in Go. */
export function findVocabularyProp(props: Property[] | undefined, name: string): PropMatch | undefined {
  return findVocabularyProps(props, name)[0];
}

/** Every prop in props that is the named row's prop, in order. Mirrors FindVocabularyProps in Go. */
export function findVocabularyProps(props: Property[] | undefined, name: string): PropMatch[] {
  const row = byName.get(name);
  if (!row || !props) return [];
  const matches: PropMatch[] = [];
  props.forEach((p, i) => {
    const m = matchVocabularyProp(row, i, p);
    if (m) matches.push(m);
  });
  return matches;
}

/**
 * Whether p is HDF's own and so must never be carried as a foreign prop: every
 * prop in the HDF namespace, and a prop with no ns whose name is a legacy row
 * (§1.4, §3.1). Mirrors ConsumedVocabularyProp in Go.
 */
export function consumedVocabularyProp(p: Property): boolean {
  if (p.ns === table.namespace) return true;
  return (p.ns ?? '') === '' && byName.get(p.name)?.legacy === true;
}
