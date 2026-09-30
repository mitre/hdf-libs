/**
 * The one mapping from HDF component identity fields to the HDF-namespaced props
 * that carry them on an OSCAL assessment subject (ADR-0014 §4.5), driven by both
 * the SAR exporter and the SAR importer. Mirrors the Go peer component_props.go.
 */

import { CloudProvider, type Component } from '@mitre/hdf-schema';
import { byCodePoint } from '../../../shared/typescript/exportmap.js';
import { emitConverterWarning } from '../../../shared/typescript/converterutil.js';
import type { Property } from './types.js';
import { emptyFieldProp, findVocabularyProp, pushVocabularyProp, vocabularyProp, vocabularyString } from './vocabulary.js';

/** One HDF component field and the prop that carries it. */
export interface ComponentProp {
  /** The vocabulary prop name (ADR-0014 §1.5). */
  prop: string;
  /** The HDF field name a marker prop reports (§1.7.5). */
  field: string;
  /** A field HDF always defines carries no empty-field marker: an empty value omits the prop (§1.7.3). */
  required?: boolean;
  /** The domain of a field HDF does not type as a free string, for the warning a rejected value earns. */
  accepts?: string;
  get: (c: Component) => string | undefined;
  /** Returns false when the value is outside the HDF field's domain, which a foreign or hand-edited subject can put there. */
  set: (c: Component, v: string) => boolean;
}

/** The hdf-results bounds on Component.port. */
const MIN_PORT = 1;
const MAX_PORT = 65535;

/**
 * The whole grammar a port prop may use. Go and JavaScript disagree over what a
 * lenient numeric parse accepts ("80abc", "1e3"), so the grammar is spelled out
 * rather than left to either language's parser.
 */
const DECIMAL_DIGITS = /^[0-9]+$/;

function componentPort(v: string): number | undefined {
  if (!DECIMAL_DIGITS.test(v)) return undefined;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < MIN_PORT || n > MAX_PORT) return undefined;
  return n;
}

/**
 * The Cloud_Provider enum in sorted order, read from the generated schema types'
 * runtime enum rather than a hand-kept copy; the Go peer reports the same order so
 * the two warnings read alike.
 */
export function cloudProviderValues(): string[] {
  return Object.values(CloudProvider).map(String).sort();
}

function validCloudProvider(v: string): v is Component['provider'] & string {
  return Object.values(CloudProvider).some((p) => String(p) === v);
}

/** One HDF component string map and the grouped key/value props that carry it. */
export interface ComponentGroupProp {
  /** The HDF map field name (labels, externalIds). */
  field: string;
  /** The prop group prefix; the key and value props extend it. */
  prefix: string;
  keyProp: string;
  valueProp: string;
  get: (c: Component) => Record<string, string> | undefined;
  set: (c: Component, m: Record<string, string>) => void;
}

/** A Component field HDF types as a plain optional string; `type` is a closed enum, not one. */
type ComponentStringField = Exclude<
  { [K in keyof Component]-?: Component[K] extends string | undefined ? K : never }[keyof Component],
  'type'
>;

/** A Component field HDF types as a string map. */
type ComponentMapField = {
  [K in keyof Component]-?: Component[K] extends Record<string, string> | undefined ? K : never;
}[keyof Component];

function stringField(prop: string, field: ComponentStringField): ComponentProp {
  return {
    prop,
    field,
    get: (c) => c[field],
    set: (c, v) => {
      c[field] = v;
      return true;
    },
  };
}

function stringMapField(field: ComponentMapField, prefix: string): ComponentGroupProp {
  return {
    field,
    prefix,
    keyProp: `${prefix}-key`,
    valueProp: `${prefix}-value`,
    get: (c) => c[field],
    set: (c, m) => {
      c[field] = m;
    },
  };
}

/**
 * The table order is the order the exporter emits props in, and the test pins it to
 * the components[] rows of the vocabulary table.
 */
const COMPONENT_PROPS: ComponentProp[] = [
  {
    prop: 'component-name',
    field: 'name',
    required: true,
    get: (c) => c.name,
    set: (c, v) => {
      c.name = v;
      return true;
    },
  },
  stringField('component-description', 'description'),
  stringField('component-hostname', 'hostname'),
  stringField('component-fqdn', 'fqdn'),
  stringField('component-domain', 'domain'),
  stringField('component-ip-address', 'ipAddress'),
  stringField('component-mac-address', 'macAddress'),
  stringField('component-os-name', 'osName'),
  stringField('component-os-version', 'osVersion'),
  stringField('component-image-id', 'imageId'),
  stringField('component-registry', 'registry'),
  stringField('component-repository', 'repository'),
  stringField('component-tag', 'tag'),
  stringField('component-container-id', 'containerId'),
  stringField('component-image', 'image'),
  stringField('component-runtime', 'runtime'),
  stringField('component-platform-type', 'platformType'),
  stringField('component-cluster-name', 'clusterName'),
  stringField('component-namespace', 'namespace'),
  stringField('component-version', 'version'),
  {
    prop: 'component-provider',
    field: 'provider',
    accepts: `one of ${cloudProviderValues().join(', ')}`,
    // HDF allows an explicit null provider, which carries as absence.
    get: (c) => c.provider ?? undefined,
    set: (c, v) => {
      if (!validCloudProvider(v)) return false;
      c.provider = v;
      return true;
    },
  },
  stringField('component-account-id', 'accountId'),
  stringField('component-region', 'region'),
  stringField('component-resource-type', 'resourceType'),
  stringField('component-resource-id', 'resourceId'),
  stringField('component-arn', 'arn'),
  stringField('component-url', 'url'),
  stringField('component-branch', 'branch'),
  stringField('component-commit', 'commit'),
  stringField('component-environment', 'environment'),
  stringField('component-package-manager', 'packageManager'),
  stringField('component-package-name', 'packageName'),
  stringField('component-cidr', 'cidr'),
  stringField('component-gateway', 'gateway'),
  stringField('component-engine', 'engine'),
  stringField('component-host', 'host'),
  {
    prop: 'component-port',
    field: 'port',
    accepts: `a decimal integer in ${MIN_PORT}..${MAX_PORT}`,
    get: (c) => (c.port === undefined ? undefined : String(c.port)),
    set: (c, v) => {
      const n = componentPort(v);
      if (n === undefined) return false;
      c.port = n;
      return true;
    },
  },
  stringField('component-model-id', 'modelId'),
  stringField('component-dataset-id', 'datasetId'),
];

const COMPONENT_GROUP_PROPS: ComponentGroupProp[] = [
  stringMapField('labels', 'component-label'),
  stringMapField('externalIds', 'component-external-id'),
];

/** Returns a copy of the component identity prop table. */
export function componentPropTable(): ComponentProp[] {
  return COMPONENT_PROPS.map((e) => ({ ...e }));
}

/** Returns a copy of the component map prop table. */
export function componentGroupPropTable(): ComponentGroupProp[] {
  return COMPONENT_GROUP_PROPS.map((g) => ({ ...g }));
}

/**
 * Carries a component's identity fields as HDF-namespaced props, in table order. A
 * present-but-empty optional string is carried by an empty-field marker (§1.7.3);
 * an absent field emits nothing. Mirrors the Go peer.
 */
export function componentSubjectProps(c: Component): Property[] {
  const props: Property[] = [];
  for (const e of COMPONENT_PROPS) {
    const v = e.get(c);
    if (v === undefined) continue;
    if (v === '') {
      if (!e.required) props.push(emptyFieldProp(e.field));
      continue;
    }
    pushVocabularyProp(props, e.prop, v);
  }
  for (const g of COMPONENT_GROUP_PROPS) appendComponentMap(props, g, g.get(c));
  return props;
}

/**
 * Fills a component's identity fields from the HDF-namespaced props on its
 * subject, leaving a field the props do not carry as the caller set it. A value
 * outside its HDF field's domain — which a foreign or hand-edited SAR can carry —
 * is dropped with a warning rather than written into a document the HDF validator
 * would reject. Mirrors the Go peer.
 */
export function readComponentSubjectProps(c: Component, props: Property[] | undefined): void {
  for (const e of COMPONENT_PROPS) {
    const v = readComponentProp(props, e);
    if (v === undefined) continue;
    if (!e.set(c, v)) {
      emitConverterWarning(`Dropping ${e.prop} ${JSON.stringify(v)} on component ${JSON.stringify(c.name)}: not ${e.accepts}`);
    }
  }
  for (const g of COMPONENT_GROUP_PROPS) {
    const m = readComponentMap(props, g);
    if (m) g.set(c, m);
  }
}

/**
 * Reads the HDF value the props carry for one entry. A required field has no
 * empty-field marker to consult, so its prop is read wherever it sits rather than
 * through the optional-string helper.
 */
function readComponentProp(props: Property[] | undefined, e: ComponentProp): string | undefined {
  if (e.required) return findVocabularyProp(props, e.prop)?.value;
  return vocabularyString(props, e.prop, e.field, '');
}

/**
 * Carries a component string map as grouped key/value props in sorted key order,
 * one group per entry, so the importer can rebuild the map. An empty key or value
 * is carried by an empty-field marker in the same group (§1.7.3). Keys sort by
 * Unicode code point, which is what Go's map-key sort produces; the default sort
 * compares UTF-16 code units and would number the groups differently.
 */
function appendComponentMap(props: Property[], g: ComponentGroupProp, m: Record<string, string> | undefined): void {
  if (!m) return;
  Object.keys(m)
    .sort(byCodePoint)
    .forEach((k, i) => {
      const group = `${g.prefix}-${i + 1}`;
      props.push(groupedComponentProp(g.keyProp, 'key', group, k));
      props.push(groupedComponentProp(g.valueProp, 'value', group, m[k]!));
    });
}

/** Builds one grouped map prop, degrading to an empty-field marker when empty. */
function groupedComponentProp(name: string, field: string, group: string, value: string): Property {
  if (value === '') return { ...emptyFieldProp(field), group };
  return { ...vocabularyProp(name, value)!, group };
}

/**
 * Rebuilds a component string map from grouped key/value props. Groups are
 * numbered from 1 in the order the exporter emitted them (sorted key order), so
 * reading stops at the first group with neither a key nor a value.
 */
function readComponentMap(props: Property[] | undefined, g: ComponentGroupProp): Record<string, string> | undefined {
  const m: Record<string, string> = {};
  for (let n = 1; ; n++) {
    const group = `${g.prefix}-${n}`;
    const key = vocabularyString(props, g.keyProp, 'key', group);
    const value = vocabularyString(props, g.valueProp, 'value', group);
    if (key === undefined && value === undefined) break;
    m[key ?? ''] = value ?? '';
  }
  return Object.keys(m).length > 0 ? m : undefined;
}
