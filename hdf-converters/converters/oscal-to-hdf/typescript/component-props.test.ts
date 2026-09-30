import { TargetType, type Component } from '@mitre/hdf-schema';
import { describe, it, expect } from 'vitest';
import {
  componentGroupPropTable,
  componentPropTable,
  componentSubjectProps,
  readComponentSubjectProps,
} from './component-props.js';
import { hasFieldMarker, vocabularyRows } from './vocabulary.js';

/** The set→get value a field cannot take from the generic pattern because its HDF field is not a string. */
const ROUND_TRIP_VALUES: Record<string, string> = { 'component-port': '8443' };

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
    for (const e of table) e.set(c, propValue(e.prop));
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
