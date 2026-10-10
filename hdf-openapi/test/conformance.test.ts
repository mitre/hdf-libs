import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import AjvDraft07 from 'ajv';
import addFormats from 'ajv-formats';
import type { ErrorObject } from 'ajv';
import {
  EMBED_DIR,
  ROOT_COMPONENT_NAMES,
  buildComponentsDocument,
  extractStandaloneSchema,
  loadBundles,
} from '../src/index.js';
import type { JsonSchema } from '../src/index.js';
import { baseline, results as corpusResults } from '@mitre/hdf-fixtures';

const bundles = loadBundles(EMBED_DIR);
const doc = buildComponentsDocument(bundles);
const schemas = doc.components.schemas;

/**
 * A 2020-12 engine, deliberately. The repo's own validators are draft-07 and ignore
 * `unevaluatedProperties`, so "validates with hdf-validators" is weaker than "conforms
 * to the schema text" — the gap ADR-0009 §5 records. Using them here would pass
 * documents the schema rejects.
 */
function engine(): Ajv2020 {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  return ajv;
}

/** Validates data against a self-contained schema, returning the errors or null. */
function verdict(schema: JsonSchema, data: unknown): ErrorObject[] | null {
  const ajv = engine();
  const validate = ajv.compile(schema);
  return validate(data) ? null : (validate.errors ?? []);
}

/** Every JSON Pointer in `data` addressing a string leaf. */
function stringLeafPointers(data: unknown, prefix = ''): string[] {
  if (Array.isArray(data)) {
    return data.flatMap((item, index) => stringLeafPointers(item, `${prefix}/${index}`));
  }
  if (data === null || typeof data !== 'object') return [];
  return Object.entries(data).flatMap(([key, value]) => {
    const pointer = `${prefix}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`;
    return typeof value === 'string' ? [pointer] : stringLeafPointers(value, pointer);
  });
}

/** Writes `value` at a JSON Pointer inside an already-cloned document. */
function setAtPointer(data: unknown, pointer: string, value: unknown): void {
  const parts = pointer
    .split('/')
    .slice(1)
    .map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'));
  let cursor = data as Record<string, unknown>;
  for (const part of parts.slice(0, -1)) {
    cursor = cursor[part] as Record<string, unknown>;
  }
  cursor[parts.at(-1) as string] = value;
}

/**
 * Finds a place in `example` where `bundle` constrains the value to a closed vocabulary,
 * by probing: replace each string leaf with a sentinel and see whether the engine objects
 * on `enum` at that exact location. Returns the pointer, or null if the example reaches no
 * enum at all.
 *
 * Discovered rather than hard-coded so the test follows the schema if an enum moves — a
 * pinned pointer would start testing nothing the moment the field was renamed.
 */
function findEnumSite(bundle: JsonSchema, example: Record<string, unknown>): string | null {
  const validate = engine().compile(bundle);
  for (const pointer of stringLeafPointers(example)) {
    const probe = structuredClone(example);
    setAtPointer(probe, pointer, '__not-a-valid-enum-value__');
    if (validate(probe)) continue;
    const hit = (validate.errors ?? []).some(
      (error) => error.keyword === 'enum' && error.instancePath === pointer,
    );
    if (hit) return pointer;
  }
  return null;
}

const ROOTS = Object.values(ROOT_COMPONENT_NAMES);

describe('extraction produces a self-contained 2020-12 schema', () => {
  it.each(ROOTS)('%s extracts and compiles on its own', (name) => {
    const standalone = extractStandaloneSchema(doc, name);
    expect(standalone.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    // Self-contained: no pointer may escape the extracted document.
    const text = JSON.stringify(standalone);
    expect(text).not.toContain('#/components/schemas/');
    expect(() => engine().compile(standalone)).not.toThrow();
  });

  // Every component, not only the 8 roots and the 42 definitions that carry examples.
  // extractStandaloneSchema throws on a dangling reference, so a broken $defs closure
  // anywhere in the document surfaces here; restricting this to the example-bearing
  // subset left 73 of 123 components never extracted and never compiled.
  it.each(Object.keys(schemas))('%s extracts to a schema that compiles standalone', (name) => {
    const standalone = extractStandaloneSchema(doc, name);
    expect(standalone.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(JSON.stringify(standalone)).not.toContain('#/components/schemas/');
    expect(() => engine().compile(standalone)).not.toThrow();
  });

  it('pulls in only the transitively-reachable definitions, not the whole document', () => {
    const standalone = extractStandaloneSchema(doc, 'Checksum');
    const defs = (standalone.$defs ?? {}) as Record<string, unknown>;
    // The EXACT closure, not an upper bound: `Checksum` references `Hash_Algorithm` and
    // nothing else. A bound of "fewer than all 123" would still pass if the walk dragged
    // in a hundred unreachable definitions.
    expect(Object.keys(defs).sort()).toEqual(['Checksum', 'Hash_Algorithm']);
  });

  it('refuses a component that does not exist, rather than emitting an empty schema', () => {
    expect(() => extractStandaloneSchema(doc, 'NoSuchComponent')).toThrow(/NoSuchComponent/);
  });
});

describe('extracted roots agree with their source bundles', () => {
  // The transform must not change what a document means. For each root, the extracted
  // component and the original bundle must reach the SAME verdict on the same data —
  // that equality is the real conformance claim, not merely "the extract compiles".
  it.each(
    Object.entries(ROOT_COMPONENT_NAMES).filter(([file]) =>
      Array.isArray((bundles.get(file) as JsonSchema).examples),
    ),
  )('%s root example gets the same verdict from both', (file, name) => {
    const bundle = bundles.get(file) as JsonSchema;
    const examples = bundle.examples as unknown[];
    expect(examples.length).toBeGreaterThan(0);
    for (const example of examples) {
      const fromBundle = verdict(bundle, example);
      const fromExtract = verdict(extractStandaloneSchema(doc, name), example);
      expect(fromExtract === null, `${name}: extract says ${fromExtract === null ? 'valid' : 'invalid'}, bundle says ${fromBundle === null ? 'valid' : 'invalid'}`).toBe(
        fromBundle === null,
      );
    }
  });
});

/** Roots that carry at least one example, with their bundle filename. */
const ROOTS_WITH_EXAMPLES = Object.entries(ROOT_COMPONENT_NAMES).filter(([file]) =>
  Array.isArray((bundles.get(file) as JsonSchema).examples),
);

/**
 * Roots carrying NO root-level example, and therefore absent from every example-driven
 * check below. Tracked rather than filtered silently: a root that loses its example would
 * otherwise drop out of the negatives with nothing to say so. ADR-0008 Phase 4 adds the
 * missing `hdf-comparison` root example, at which point this list empties.
 */
const ROOTS_WITHOUT_EXAMPLES = ['HdfComparison'];

/**
 * Roots whose own example carries no value under any closed vocabulary, so no enum can be
 * violated in it without inventing data. `hdf-baseline`'s example omits `severity`,
 * `controlType` and every other enum-bearing field. Tracked for the same reason as
 * [[ROOTS_WITHOUT_EXAMPLES]] — the alternative is a test that quietly checks six roots
 * while claiming seven.
 */
const ROOTS_WITHOUT_REACHABLE_ENUM = ['HdfBaseline'];

describe('the example-driven negatives cover every root they claim to', () => {
  it('names exactly the roots that carry no example', () => {
    const without = Object.values(ROOT_COMPONENT_NAMES).filter(
      (name) => !ROOTS_WITH_EXAMPLES.some(([, withExample]) => withExample === name),
    );
    expect(without).toEqual(ROOTS_WITHOUT_EXAMPLES);
  });
});

describe('negatives: the five mutation classes', () => {
  // Missing-required, extra-key and bad-enum are tested PER ROOT. The other two — if/then
  // and a boolean-false branch — only exist at specific sites, and "violating" a constraint
  // a schema does not contain proves nothing, so those are tested where the mechanism lives.
  describe.each(ROOTS_WITH_EXAMPLES)('%s', (file, name) => {
    const bundle = bundles.get(file) as JsonSchema;
    const example = (bundle.examples as unknown[])[0] as Record<string, unknown>;
    const standalone = () => extractStandaloneSchema(doc, name);

    it('accepts its own example first, so the negatives below mean something', () => {
      expect(verdict(standalone(), example)).toBeNull();
    });

    it('rejects a missing required property', () => {
      const required = (bundle.required ?? []) as string[];
      expect(required.length, `${name} declares no required properties`).toBeGreaterThan(0);
      const mutated = structuredClone(example);
      delete mutated[required[0] as string];
      const errors = verdict(standalone(), mutated);
      expect(errors).not.toBeNull();
      expect(errors?.map((e) => e.keyword)).toContain('required');
    });

    it('rejects an extra key under unevaluatedProperties: false', () => {
      expect(standalone().unevaluatedProperties, `${name} is not closed`).toBe(false);
      const errors = verdict(standalone(), { ...structuredClone(example), notAKnownKey: 'x' });
      expect(errors).not.toBeNull();
      // The keyword matters: if this failed on `required` or `type` instead, the closed
      // -object mechanism would not actually be under test.
      expect(errors?.map((e) => e.keyword)).toContain('unevaluatedProperties');
    });

    it('rejects a bad enum value', () => {
      if (ROOTS_WITHOUT_REACHABLE_ENUM.includes(name)) {
        // Not a skip: assert the recorded reason still HOLDS, so this root rejoins the
        // class the moment its example gains an enum-bearing field.
        expect(findEnumSite(bundle, example), `${name} now has a reachable enum site`).toBeNull();
        return;
      }
      const site = findEnumSite(bundle, example);
      expect(site, `${name}: no enum site reachable from its own example`).not.toBeNull();
      const mutated = structuredClone(example);
      setAtPointer(mutated, site as string, '__not-a-valid-enum-value__');

      // The claim is PARITY: the site was discovered against the source bundle, and the
      // extracted component must reach the same verdict on it. Asserting only that ajv
      // said "enum" would be circular, since ajv is what found the site.
      const fromBundle = verdict(bundle, mutated);
      const errors = verdict(standalone(), mutated);
      expect(errors).not.toBeNull();
      expect(fromBundle).not.toBeNull();
      expect(errors?.map((e) => e.keyword)).toContain('enum');
    });
  });

  it('rejects an if/then violation', () => {
    // Kev: `inKev: true` makes dateAdded and dueDate required. Omitting them is a
    // violation of the THEN branch only — the same document with inKev false is valid,
    // which is what makes this a conditional-schema test rather than a required test.
    const kev = extractStandaloneSchema(doc, 'Kev');
    expect(verdict(kev, { inKev: false })).toBeNull();
    const errors = verdict(kev, { inKev: true });
    expect(errors).not.toBeNull();
    expect(errors?.map((e) => e.keyword)).toEqual(expect.arrayContaining(['required']));
    expect(errors?.some((e) => e.schemaPath.includes('/then/'))).toBe(true);
  });

  it('rejects a boolean-false branch violation', () => {
    // Bom: the ai-model extension may appear only on an ai-model BOM, expressed as
    // `else: { properties: { model: false } }`. A non-ai-model BOM carrying `model`
    // trips a subschema that can never be satisfied.
    const bom = extractStandaloneSchema(doc, 'Bom');
    // A base that actually VALIDATES. The previous base was already invalid for unrelated
    // reasons (Bom requires one of ref/document/packages/model/dataset), which made
    // "the mutated document is rejected" true whether or not `model` was the cause.
    const base = { bomType: 'sbom', format: 'cyclonedx', ref: 'sbom.cdx.json' };
    expect(verdict(bom, base), 'the base document must be valid for the negative to mean anything').toBeNull();
    const errors = verdict(bom, { ...base, model: { name: 'x' } });
    expect(errors, 'the model-bearing document must be rejected').not.toBeNull();
    expect(errors?.some((e) => e.schemaPath.includes('/else/'))).toBe(true);
  });
});

/**
 * Corpus documents that do NOT conform to the schema text under a 2020-12 engine, with
 * the property that trips it. They are listed rather than skipped so the list is a
 * tracked claim: if one is fixed, the assertion below fails and the entry must be
 * removed, and if another document regresses it shows up as a new failure.
 *
 * Neither is a defect in this package. Both are invisible to the repository's own
 * draft-07 validators, which ignore `unevaluatedProperties` — the gap ADR-0009 §5
 * records. `targets` is the visible end of something ADR-0008's Context already notes:
 * the `target`/`platform` primitives are unreferenced in source and never bundled, so a
 * document using them has no schema to be evaluated against.
 */
const CORPUS_NOT_CONFORMANT: Record<string, string> = {
  inspecMultilayered: 'targets',
  win2022Stig: 'checksum',
};

describe('real hdf-fixtures documents through the extracted roots', () => {
  const cases: [string, string, { read: () => string }][] = [
    ['HdfResults', 'mergeGrype', corpusResults.mergeGrype],
    ['HdfResults', 'mergeZap', corpusResults.mergeZap],
    ['HdfResults', 'minimal', corpusResults.minimal],
    ['HdfResults', 'inspecMultilayered', corpusResults.inspecMultilayered],
    ['HdfResults', 'duplicateBaselines', corpusResults.duplicateBaselines],
    ['HdfBaseline', 'win2022Stig', baseline.win2022Stig],
  ];

  // THE conformance claim: whatever the verdict, the extract and the source bundle must
  // reach the SAME one. This is what proves the transform preserved meaning, and it is
  // independent of whether any given corpus document happens to be valid.
  it.each(cases)('%s / %s — extract and bundle agree', (name, _label, ref) => {
    const data = JSON.parse(ref.read()) as unknown;
    const file = Object.entries(ROOT_COMPONENT_NAMES).find(([, n]) => n === name)?.[0] as string;
    const fromBundle = verdict(bundles.get(file) as JsonSchema, data);
    const fromExtract = verdict(extractStandaloneSchema(doc, name), data);
    expect(fromExtract === null).toBe(fromBundle === null);
  });

  it.each(cases.filter(([, label]) => !(label in CORPUS_NOT_CONFORMANT)))(
    '%s / %s — accepted',
    (name, _label, ref) => {
      const errors = verdict(extractStandaloneSchema(doc, name), JSON.parse(ref.read()));
      expect(errors, JSON.stringify(errors?.slice(0, 2))).toBeNull();
    },
  );

  it.each(cases.filter(([, label]) => label in CORPUS_NOT_CONFORMANT))(
    '%s / %s — still non-conformant for the recorded reason',
    (name, label, ref) => {
      const errors = verdict(extractStandaloneSchema(doc, name), JSON.parse(ref.read()));
      expect(
        errors,
        `${label} now validates — remove it from CORPUS_NOT_CONFORMANT`,
      ).not.toBeNull();
      const unevaluated = errors
        ?.filter((e) => e.keyword === 'unevaluatedProperties')
        .map((e) => (e.params as { unevaluatedProperty?: string }).unevaluatedProperty);
      expect(unevaluated).toContain(CORPUS_NOT_CONFORMANT[label]);
    },
  );
});

describe('every definition example validates against its extracted definition', () => {
  const withExamples = Object.entries(schemas).filter(
    ([name, body]) => !ROOTS.includes(name) && Array.isArray((body as JsonSchema).examples),
  );

  it('there are definition examples to check, so this cannot pass vacuously', () => {
    // The exact count, not a floor. A floor of 20 against an actual 42 would let half the
    // definitions lose their examples without the guard noticing — which is precisely the
    // vacuity it exists to prevent. Raise this deliberately when definitions gain examples.
    expect(withExamples.length).toBe(42);
    expect(withExamples.reduce((total, [, schema]) => total + (schema.examples as unknown[]).length, 0)).toBe(120);
  });

  it.each(withExamples.map(([name]) => name))('%s', (name) => {
    const standalone = extractStandaloneSchema(doc, name);
    const examples = (schemas[name] as JsonSchema).examples as unknown[];
    for (const [i, example] of examples.entries()) {
      const errors = verdict(standalone, example);
      expect(errors, `${name} example ${i}: ${JSON.stringify(errors?.slice(0, 2))}`).toBeNull();
    }
  });
});

describe('the draft-07 gap this card exists to avoid', () => {
  const results = bundles.get('hdf-results.schema.json') as JsonSchema;
  const example = (results.examples as unknown[])[0] as Record<string, unknown>;
  const mutated = { ...structuredClone(example), notAKnownKey: 'x' };

  // The card requires that conformance NOT use the repo's own validators. That is a
  // claim about their behaviour, so prove it rather than assert it: the same schema and
  // the same document, through the two engines, must disagree. If a future ajv makes
  // draft-07 honour unevaluatedProperties, this test fails and the prohibition can be
  // revisited on evidence instead of folklore.
  it('a 2020-12 engine rejects an extra key, and specifically on unevaluatedProperties', () => {
    const standalone = extractStandaloneSchema(doc, 'HdfResults');
    expect(standalone.unevaluatedProperties).toBe(false);
    const ajv = engine();
    const validate = ajv.compile(standalone);
    expect(validate(mutated)).toBe(false);
    expect((validate.errors ?? []).map((e) => e.keyword)).toContain('unevaluatedProperties');
  });

  it('a draft-07 engine ACCEPTS the same document — the gap, demonstrated', () => {
    const standalone = structuredClone(extractStandaloneSchema(doc, 'HdfResults'));
    delete standalone.$schema; // draft-07 ajv refuses an explicit 2020-12 dialect
    const ajv = new AjvDraft07({ strict: false, allErrors: true });
    addFormats(ajv);
    expect(
      ajv.compile(standalone)(mutated),
      'draft-07 started rejecting this — re-examine whether the 2020-12 requirement still holds',
    ).toBe(true);
  });
});
