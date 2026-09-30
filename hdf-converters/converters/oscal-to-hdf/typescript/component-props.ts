/**
 * The one mapping from HDF component identity fields to the HDF-namespaced props
 * that carry them on an OSCAL assessment subject (ADR-0014 §4.5), driven by both
 * the SAR exporter and the SAR importer. Mirrors the Go peer component_props.go.
 */

import type { Component } from '@mitre/hdf-schema';
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
  get: (c: Component) => string | undefined;
  set: (c: Component, v: string) => void;
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
    // HDF allows an explicit null provider, which carries as absence.
    get: (c) => c.provider ?? undefined,
    set: (c, v) => {
      c.provider = v as Component['provider'];
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
    get: (c) => (c.port === undefined ? undefined : String(c.port)),
    set: (c, v) => {
      const n = Number.parseInt(v, 10);
      if (!Number.isNaN(n)) c.port = n;
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
 * subject, leaving a field the props do not carry as the caller set it. Mirrors
 * the Go peer.
 */
export function readComponentSubjectProps(c: Component, props: Property[] | undefined): void {
  for (const e of COMPONENT_PROPS) {
    const v = readComponentProp(props, e);
    if (v !== undefined) e.set(c, v);
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
 * is carried by an empty-field marker in the same group (§1.7.3).
 */
function appendComponentMap(props: Property[], g: ComponentGroupProp, m: Record<string, string> | undefined): void {
  if (!m) return;
  Object.keys(m)
    .sort()
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
