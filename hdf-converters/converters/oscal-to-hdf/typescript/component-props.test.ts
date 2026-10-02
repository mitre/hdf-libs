import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TargetType, type Component } from '@mitre/hdf-schema';
import { describe, it, expect } from 'vitest';
import {
  cloudProviderValues,
  componentGroupPropTable,
  componentPropTable,
  componentSubjectProps,
  readComponentSubjectProps,
  type ComponentGroupProp,
  type ComponentProp,
} from './component-props.js';
import { hasFieldMarker, vocabularyRows } from './vocabulary.js';
import type { Property } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SHARED = join(__dirname, '..', '..', '..', 'shared');

/**
 * The set→get value a field cannot take from the generic pattern because its HDF
 * field is not a string, or is a closed enum the accessor validates against.
 */
const ROUND_TRIP_VALUES: Record<string, string> = { 'component-port': '8443', 'component-provider': 'aws' };

function propEntry(prop: string): ComponentProp {
  const e = componentPropTable().find((x) => x.prop === prop);
  expect(e, `no component prop table entry named ${prop}`).toBeDefined();
  return e!;
}

function propValue(prop: string): string {
  return ROUND_TRIP_VALUES[prop] ?? `value-${prop}`;
}

/** The HDF field every components[] vocabulary row carries, in table order (ADR-0014 §1.5). */
function componentVocabularyFields(): { order: string[]; fields: Map<string, string> } {
  const order: string[] = [];
  const fields = new Map<string, string>();
  for (const r of vocabularyRows()) {
    if (r.hdfField === null || r.hdfField === undefined || !r.hdfField.startsWith('components[].')) continue;
    order.push(r.name);
    fields.set(r.name, r.hdfField);
  }
  expect(order.length).toBeGreaterThan(0);
  return { order, fields };
}

function newComponent(): Component {
  return { type: TargetType.Host, name: '' };
}

interface GroupKeyCase {
  label: string;
  entries: Record<string, string>;
  order: string[];
  why: string;
}

const GROUP_KEY_CASES = (
  JSON.parse(readFileSync(join(SHARED, 'oscal-component-group-key-cases.json'), 'utf-8')) as { cases: GroupKeyCase[] }
).cases;

/** The sorted non-null enum values of the definition named def, wherever the bundled schema nests it. */
function schemaEnumValues(v: unknown, def: string): string[] | undefined {
  if (Array.isArray(v)) {
    for (const item of v) {
      const found = schemaEnumValues(item, def);
      if (found) return found;
    }
    return undefined;
  }
  if (typeof v !== 'object' || v === null) return undefined;
  const m = v as Record<string, unknown>;
  const sub = m[def];
  if (typeof sub === 'object' && sub !== null && Array.isArray((sub as Record<string, unknown>).enum)) {
    return ((sub as Record<string, unknown>).enum as unknown[]).filter((e): e is string => typeof e === 'string').sort();
  }
  for (const value of Object.values(m)) {
    const found = schemaEnumValues(value, def);
    if (found) return found;
  }
  return undefined;
}

/** The key each of g's prop groups carries, group 1 first. */
function groupedMapKeys(props: Property[], g: ComponentGroupProp): string[] {
  const keys: string[] = [];
  for (let n = 1; ; n++) {
    const group = `${g.prefix}-${n}`;
    const p = props.find((x) => x.group === group && x.name === g.keyProp);
    if (!p) return keys;
    keys.push(p.value);
  }
}

describe('component prop table', () => {
  it('covers every components[] vocabulary row, exactly once, in the vocabulary order', () => {
    const { order, fields } = componentVocabularyFields();
    const got: string[] = [];
    for (const e of componentPropTable()) {
      got.push(e.prop);
      expect(fields.get(e.prop), `table entry "${e.prop}" must name the HDF field its vocabulary row carries`).toBe(
        `components[].${e.field}`,
      );
    }
    for (const g of componentGroupPropTable()) {
      got.push(g.keyProp, g.valueProp);
      expect(fields.get(g.keyProp), `group entry "${g.keyProp}" must name the HDF field its vocabulary row carries`).toBe(
        `components[].${g.field} (key)`,
      );
      expect(fields.get(g.valueProp), `group entry "${g.valueProp}" must name the HDF field its vocabulary row carries`).toBe(
        `components[].${g.field} (value)`,
      );
    }
    expect(got).toStrictEqual(order);
  });

  it('round-trips a value through every entry', () => {
    const c = newComponent();
    const table = componentPropTable();
    expect(table.length).toBeGreaterThan(0);
    for (const e of table) {
      expect(e.set(c, propValue(e.prop)), `${e.prop}: the setter rejected the value the table round-trips`).toBe(true);
    }
    for (const e of table) {
      expect(e.get(c), `${e.prop}: set→get is not the identity`).toBe(propValue(e.prop));
    }
    for (const g of componentGroupPropTable()) {
      const gc = newComponent();
      const m = { k1: 'v1', k2: 'v2' };
      g.set(gc, m);
      expect(g.get(gc), `${g.prefix}: set→get is not the identity`).toStrictEqual(m);
    }
  });

  // AC: component-port carries an HDF integer, so the accessor takes exactly the
  // decimal-integer grammar within the schema's 1..65535 and rejects everything
  // else — a foreign SAR must not hand HDF a port its own schema refuses.
  it('accepts only decimal integers in 1..65535 for the port', () => {
    const entry = propEntry('component-port');
    for (const v of ['1', '80', '443', '8443', '65535', '0080']) {
      const c = newComponent();
      expect(entry.set(c, v), `${v} is a port the HDF schema admits`).toBe(true);
      expect(c.port).toBeDefined();
    }
    for (const v of ['', '0', '65536', '80abc', '1e3', ' 80', '80 ', '-1', '+80', '8.0', '0x50', '99999999999999999999']) {
      const c = newComponent();
      expect(entry.set(c, v), `${v} is not a port the HDF schema admits`).toBe(false);
      expect(c.port, 'a rejected value leaves the field absent').toBeUndefined();
    }
  });

  // AC: component-provider carries a closed HDF enum, so the accessor takes
  // exactly its values, read from the generated schema types.
  it('accepts only the Cloud_Provider enum for the provider', () => {
    const entry = propEntry('component-provider');
    expect(cloudProviderValues().length).toBeGreaterThan(0);
    for (const v of cloudProviderValues()) {
      const c = newComponent();
      expect(entry.set(c, v), `${v} is a Cloud_Provider value`).toBe(true);
      expect(c.provider).toBe(v);
    }
    for (const v of ['', 'digitalocean', 'AWS', 'aws ', 'amazon']) {
      const c = newComponent();
      expect(entry.set(c, v), `${v} is not a Cloud_Provider value`).toBe(false);
      expect(c.provider, 'a rejected value leaves the field absent').toBeUndefined();
    }
  });

  // AC: the accepted provider list is the schema's, not a hand-kept copy — the
  // generated runtime enum must still be the bundled schema's own enum.
  it('reads the provider enum from the bundled schema', () => {
    const schema = JSON.parse(
      readFileSync(join(SHARED, '..', '..', 'hdf-schema', 'dist', 'schemas', 'hdf-results.schema.json'), 'utf-8'),
    );
    const want = schemaEnumValues(schema, 'Cloud_Provider');
    expect(want, 'the bundled schema must define Cloud_Provider').not.toBeUndefined();
    expect(cloudProviderValues()).toStrictEqual(want);
  });

  it('returns copies of the tables', () => {
    const table = componentPropTable();
    table[0]!.prop = 'mutated';
    expect(componentPropTable()[0]!.prop).not.toBe('mutated');
    const groups = componentGroupPropTable();
    groups[0]!.prefix = 'mutated';
    expect(componentGroupPropTable()[0]!.prefix).not.toBe('mutated');
  });
});

describe('component subject props', () => {
  it('round-trips every field through the props', () => {
    const c = newComponent();
    for (const e of componentPropTable()) e.set(c, propValue(e.prop));
    for (const g of componentGroupPropTable()) g.set(c, { k2: 'v2', k1: 'v1' });

    const back = newComponent();
    readComponentSubjectProps(back, componentSubjectProps(c));
    expect(back).toStrictEqual(c);
  });

  it('carries a present-but-empty optional field as a marker', () => {
    const c: Component = { type: TargetType.Host, name: 'web01', hostname: '' };
    const props = componentSubjectProps(c);
    expect(hasFieldMarker(props, 'empty-field', 'hostname', '')).toBe(true);

    const back = newComponent();
    readComponentSubjectProps(back, props);
    expect(back.hostname).toBe('');
    expect(back.fqdn).toBeUndefined();
  });

  it('omits an empty required field rather than marking it', () => {
    const props = componentSubjectProps(newComponent());
    expect(props).toStrictEqual([]);
    const back: Component = { type: TargetType.Host, name: 'untouched' };
    readComponentSubjectProps(back, props);
    expect(back.name).toBe('untouched');
  });

  it('groups map entries in code-point order for every shared case', () => {
    expect(GROUP_KEY_CASES.length).toBeGreaterThan(0);
    for (const c of GROUP_KEY_CASES) {
      for (const g of componentGroupPropTable()) {
        const comp: Component = { type: TargetType.Host, name: 'web01' };
        g.set(comp, { ...c.entries });
        expect(groupedMapKeys(componentSubjectProps(comp), g), `${c.label}/${g.prefix}: ${c.why}`).toStrictEqual(c.order);
      }
    }
  });

  it('groups map entries in sorted key order', () => {
    const c: Component = { type: TargetType.Host, name: 'web01', labels: { zone: 'b', environment: '' } };
    const props = componentSubjectProps(c);
    expect(props.filter((p) => p.group !== undefined).map((p) => `${p.group}/${p.name}=${p.value}`)).toStrictEqual([
      'component-label-1/component-label-key=environment',
      'component-label-1/empty-field=value',
      'component-label-2/component-label-key=zone',
      'component-label-2/component-label-value=b',
    ]);

    const back = newComponent();
    readComponentSubjectProps(back, props);
    expect(back.labels).toStrictEqual(c.labels);
  });
});

describe('component prop table: rejecting setters', () => {
  it('name what they accept, so a warning never ends in a dangling "not"', () => {
    for (const e of componentPropTable()) {
      for (const probe of ['', '-1', 'not-a-value']) {
        const c: Component = { type: TargetType.Host, name: 'web01' };
        if (!e.set(c, probe)) expect(e.accepts, `${e.prop} rejects ${JSON.stringify(probe)} but names nothing it accepts`).toBeTruthy();
      }
    }
  });
});
