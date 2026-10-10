import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EMBED_DIR,
  MAIN_SCHEMAS,
  ROOT_COMPONENT_NAMES,
  buildComponentsDocument,
  loadBundles,
} from '../src/index.js';
import type { JsonSchema } from '../src/index.js';

const bundles = loadBundles(EMBED_DIR);
const doc = buildComponentsDocument(bundles);
const schemas = doc.components.schemas;

/** Deep-walks a schema, yielding [keyPath, key, value] for every member. */
function* members(node: unknown, path = ''): Generator<[string, string, unknown]> {
  if (Array.isArray(node)) {
    for (const [i, v] of node.entries()) yield* members(v, `${path}/${i}`);
  } else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      yield [path, k, v];
      yield* members(v, `${path}/${k}`);
    }
  }
}

function countKeyword(keyword: string): number {
  let n = 0;
  for (const [, k] of members(schemas)) if (k === keyword) n++;
  return n;
}

describe('the embed is the source of truth', () => {
  it('reads exactly the bundler MAIN_SCHEMAS set', () => {
    expect([...bundles.keys()].sort()).toEqual([...MAIN_SCHEMAS].sort());
  });

  // The bundler owns which document types exist. If it gains or loses one, this
  // package must be updated deliberately rather than silently emitting a
  // contract that is missing a document type.
  it('MAIN_SCHEMAS agrees with the bundler source', () => {
    const src = readFileSync(
      join(import.meta.dirname, '..', '..', 'hdf-schema', 'src', 'bundle-schemas.ts'),
      'utf8',
    );
    const match = /const MAIN_SCHEMAS = \[([^\]]*)\]/.exec(src);
    expect(match, 'could not find MAIN_SCHEMAS in hdf-schema/src/bundle-schemas.ts').toBeTruthy();
    const fromBundler = [...match![1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
    expect(fromBundler.sort()).toEqual([...MAIN_SCHEMAS].sort());
  });

  it('fails loudly when the embed directory is absent', () => {
    expect(() => loadBundles(join(import.meta.dirname, 'fixtures', 'no-such-dir'))).toThrow(
      /does not exist/i,
    );
  });

  it('fails loudly when the embed is missing a bundle', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hdf-openapi-embed-'));
    try {
      writeFileSync(join(dir, 'hdf-results.schema.json'), '{}');
      expect(() => loadBundles(dir)).toThrow(/MAIN_SCHEMAS/);
      expect(() => loadBundles(dir)).toThrow(/missing: .*hdf-baseline/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails loudly on a bundle the bundler does not produce', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hdf-openapi-embed-'));
    try {
      for (const f of MAIN_SCHEMAS) writeFileSync(join(dir, f), '{}');
      writeFileSync(join(dir, 'hdf-invented.schema.json'), '{}');
      expect(() => loadBundles(dir)).toThrow(/unexpected: .*hdf-invented/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('roots', () => {
  it('emits all eight roots under their component names', () => {
    const rootNames = Object.values(ROOT_COMPONENT_NAMES);
    expect(rootNames).toHaveLength(8);
    for (const name of rootNames) expect(schemas, `missing root ${name}`).toHaveProperty(name);
  });

  it('keeps each root a real object schema, not a $ref husk', () => {
    for (const name of Object.values(ROOT_COMPONENT_NAMES)) {
      const root = schemas[name] as JsonSchema;
      expect(root.type, `${name} lost its type`).toBe('object');
      expect(root.properties, `${name} lost its properties`).toBeTypeOf('object');
    }
  });

  // The embedded copies inside comparison and change-event are byte-identical to
  // the standalone bundle, so they must collapse onto one component rather than
  // producing HdfResults2 or failing the collision guard.
  it('collapses the embedded hdf-results resource onto HdfResults', () => {
    const standalone = bundles.get('hdf-results.schema.json') as JsonSchema;
    const emitted = schemas.HdfResults as JsonSchema;
    expect(Object.keys(emitted).sort()).toEqual(
      Object.keys(standalone)
        .filter((k) => k !== '$id' && k !== '$schema' && k !== '$defs')
        .sort(),
    );
  });
});

describe('definitions are hoisted and self-contained', () => {
  it('hoists every named definition and adds nothing else', () => {
    // 115 named definitions across the bundles + 8 roots. Measured against the
    // tracked embed; a change here is a schema-set change and must be reviewed.
    expect(Object.keys(schemas)).toHaveLength(115 + 8);
  });

  it('emits component keys OpenAPI accepts', () => {
    for (const name of Object.keys(schemas)) expect(name).toMatch(/^[a-zA-Z0-9.\-_]+$/);
  });

  it('strips every embedded $id and $schema', () => {
    expect(countKeyword('$id')).toBe(0);
    expect(countKeyword('$schema')).toBe(0);
  });

  it('unwraps the URL-keyed resource wrappers', () => {
    for (const name of Object.keys(schemas)) expect(name).not.toContain('://');
    // No nested $defs survive either: everything is hoisted to components.
    expect(countKeyword('$defs')).toBe(0);
  });

  it('rewrites every $ref to a local component pointer that resolves', () => {
    let refs = 0;
    for (const [, k, v] of members(schemas)) {
      if (k !== '$ref') continue;
      refs++;
      expect(typeof v).toBe('string');
      const ref = v as string;
      expect(ref, 'absolute $ref survived the rewrite').not.toContain('://');
      expect(ref).toMatch(/^#\/components\/schemas\/[a-zA-Z0-9.\-_]+$/);
      const target = ref.slice('#/components/schemas/'.length);
      expect(schemas, `dangling $ref ${ref}`).toHaveProperty(target);
    }
    // Every ref of every unique resource lands, and none is invented. The raw
    // embed has 759 refs, but 530 of those are inside the hdf-results resource's
    // two embedded copies, which deduplicate away.
    expect(refs).toBe(expectedCounts.refs);
    expect(refs).toBeGreaterThan(0);
  });
});

/**
 * Keyword counts expected AFTER hoisting, computed by walking each unique
 * resource in the bundles exactly once.
 *
 * This is deliberately an independent count over the same input rather than a
 * number copied from the transform's output: the transform deduplicates (the
 * hdf-results resource is embedded in comparison and change-event, so a raw
 * bundle walk counts it three times), and a test that recorded whatever the
 * transform emitted would track the transform instead of checking it.
 */
function expectedFromUniqueResources(): {
  keywords: Record<string, number>;
  refs: number;
  bodies: unknown[];
} {
  const seen = new Map<string, unknown[]>();
  const rootScopes = new Set([...bundles.values()].map((b) => b.$id as string));
  for (const bundle of bundles.values()) {
    const defs = (bundle.$defs ?? {}) as Record<string, JsonSchema>;
    const rootScope = bundle.$id as string;
    const bodyOf = (schema: JsonSchema): JsonSchema =>
      Object.fromEntries(
        Object.entries(schema).filter(([k]) => k !== '$id' && k !== '$schema' && k !== '$defs'),
      );
    const collect = (
      scope: string,
      wrapper: JsonSchema,
      nested: Record<string, JsonSchema>,
      isRoot: boolean,
    ) => {
      if (seen.has(scope)) return;
      seen.set(scope, [...(isRoot ? [bodyOf(wrapper)] : []), ...Object.values(nested)]);
    };
    const named: Record<string, JsonSchema> = {};
    for (const [k, v] of Object.entries(defs)) if (!k.includes('://')) named[k] = v;
    collect(rootScope, bundle, named, true);
    for (const [key, value] of Object.entries(defs)) {
      if (!key.includes('://')) continue;
      const wrapper = value as JsonSchema;
      const inner = (wrapper.$defs ?? {}) as Record<string, JsonSchema>;
      const scope = (wrapper.$id as string) ?? key;
      collect(scope, wrapper, inner, rootScopes.has(scope));
    }
  }
  const keywords: Record<string, number> = {};
  let refs = 0;
  const bodies: unknown[] = [];
  for (const group of seen.values()) {
    for (const body of group) {
      bodies.push(body);
      for (const [, k] of members(body)) {
        if (k === '$ref') refs++;
        keywords[k] = (keywords[k] ?? 0) + 1;
      }
    }
  }
  return { keywords, refs, bodies };
}

const expectedCounts = expectedFromUniqueResources();

/**
 * Keywords whose VALUE is the feature, so a key-count histogram is blind to them.
 * `unevaluatedProperties: false -> true` and a rewritten `const` both preserve every
 * count while destroying the contract.
 */
const VALUE_BEARING = ['unevaluatedProperties', 'additionalProperties', 'const', 'type'] as const;

const isScalar = (v: unknown): boolean => v === null || ['boolean', 'number', 'string'].includes(typeof v);

/**
 * Counts (keyword, serialized value) pairs for the value-bearing keywords — the
 * value-aware companion to the key histogram.
 *
 * Scalars and arrays of scalars only. These keywords may also hold a SUBSCHEMA, whose
 * serialization legitimately differs between input and output because a `$ref` inside
 * it is rewritten; that subschema's contents are covered by the key histogram and by
 * the ref-resolution test instead.
 */
function valueHistogram(roots: Iterable<unknown>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const body of roots) {
    for (const [, k, v] of members(body)) {
      if (!(VALUE_BEARING as readonly string[]).includes(k)) continue;
      const comparable = isScalar(v) || (Array.isArray(v) && v.every(isScalar));
      if (!comparable) continue;
      const key = `${k}=${JSON.stringify(v)}`;
      out[key] = (out[key] ?? 0) + 1;
    }
  }
  return out;
}

/** Every multi-valued `type` array in the input's unique resources. */
function expectedTypeArrays(): string[][] {
  const out: string[][] = [];
  const seen = new Set<string>();
  const rootScopes = new Set([...bundles.values()].map((b) => b.$id as string));
  for (const bundle of bundles.values()) {
    const defs = (bundle.$defs ?? {}) as Record<string, JsonSchema>;
    const bodyOf = (schema: JsonSchema): JsonSchema =>
      Object.fromEntries(
        Object.entries(schema).filter(([k]) => k !== '$id' && k !== '$schema' && k !== '$defs'),
      );
    const take = (
      scope: string,
      wrapper: JsonSchema,
      nested: Record<string, JsonSchema>,
      isRoot: boolean,
    ) => {
      if (seen.has(scope)) return;
      seen.add(scope);
      for (const body of [...(isRoot ? [bodyOf(wrapper)] : []), ...Object.values(nested)]) {
        for (const [, k, v] of members(body)) {
          if (k === 'type' && Array.isArray(v)) out.push(v as string[]);
        }
      }
    };
    const named: Record<string, JsonSchema> = {};
    for (const [k, v] of Object.entries(defs)) if (!k.includes('://')) named[k] = v;
    take(bundle.$id as string, bundle, named, true);
    for (const [key, value] of Object.entries(defs)) {
      if (!key.includes('://')) continue;
      const wrapper = value as JsonSchema;
      const scope = (wrapper.$id as string) ?? key;
      take(scope, wrapper, (wrapper.$defs ?? {}) as Record<string, JsonSchema>, rootScopes.has(scope));
    }
  }
  return out;
}

describe('2020-12 features pass through untouched', () => {
  /** Every keyword in the emitted components, counted the same way as the input. */
  function actualKeywordCounts(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const body of Object.values(schemas)) {
      for (const [, k] of members(body)) out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  }

  // The WHOLE histogram, not a hand-picked subset. A subset only guards the
  // keywords someone thought to name — a six-keyword version of this test passed
  // while every `description` sibling of a $ref (125 sites) was being deleted.
  it('preserves every keyword of every unique resource, at its exact count', () => {
    expect(actualKeywordCounts()).toEqual(expectedCounts.keywords);
  });

  // The key histogram above proves nothing was dropped; this proves nothing was
  // altered. Without it, forcing all 76 `unevaluatedProperties` to true passed 40/40.
  it('preserves the VALUE of every keyword whose value is the feature', () => {
    expect(valueHistogram(Object.values(schemas))).toEqual(valueHistogram(expectedCounts.bodies));
  });

  it.each(['unevaluatedProperties', 'if', 'dependentRequired', 'contains', 'const', 'enum'])(
    '%s survives every site',
    (keyword) => {
      expect(countKeyword(keyword)).toBe(expectedCounts.keywords[keyword] ?? 0);
    },
  );

  // A key-count histogram cannot see inside a value, so nullable types need their
  // own assertion: collapsing every `type` array to its first member keeps the
  // `type` count identical while destroying `type: [string, null]`.
  it('keeps multi-valued type arrays intact, nulls included', () => {
    const arrays: string[][] = [];
    for (const [, k, v] of members(schemas)) {
      if (k === 'type' && Array.isArray(v)) arrays.push(v as string[]);
    }
    const expectedArrays = expectedTypeArrays();
    expect(arrays.map((a) => a.join('|')).sort()).toEqual(
      expectedArrays.map((a) => a.join('|')).sort(),
    );
    // The ADR's Context names `type: [string, null]` specifically.
    expect(arrays.some((a) => a.length > 1 && a.includes('null'))).toBe(true);
  });

  // Pinned absolutely as well: the derived count above proves nothing was lost
  // relative to the input, and these prove the input itself has not drifted
  // without review. Measured against the tracked embed at schema v3.7.0.
  it('matches the tracked keyword baseline', () => {
    expect({
      unevaluatedProperties: countKeyword('unevaluatedProperties'),
      if: countKeyword('if'),
      dependentRequired: countKeyword('dependentRequired'),
    }).toEqual({ unevaluatedProperties: 76, if: 8, dependentRequired: 1 });
  });

  it('keeps the three Bom boolean-false subschemas', () => {
    let falseBranches = 0;
    for (const [path, , v] of members(schemas)) {
      if (v === false && path.includes('/else/properties')) falseBranches++;
    }
    expect(falseBranches).toBe(3);
  });

  it('retains examples and $comment', () => {
    expect(countKeyword('examples')).toBe(expectedCounts.keywords.examples);
    expect(countKeyword('$comment')).toBe(expectedCounts.keywords.$comment);
    expect(countKeyword('examples')).toBeGreaterThan(0);
    expect(countKeyword('$comment')).toBeGreaterThan(0);
  });

  it('introduces none of the keywords the schemas do not use', () => {
    for (const absent of ['$dynamicRef', '$anchor', 'patternProperties', 'prefixItems']) {
      expect(countKeyword(absent), `${absent} appeared`).toBe(0);
    }
  });
});

describe('$ref shapes the schemas do not currently use but 2020-12 permits', () => {
  /** Plants a property on the hdf-comparison root and rebuilds. */
  function withPlantedRef(ref: string) {
    const planted = new Map(bundles);
    const doc = structuredClone(planted.get('hdf-comparison.schema.json')) as JsonSchema;
    (doc.properties as Record<string, JsonSchema>).planted = { $ref: ref };
    planted.set('hdf-comparison.schema.json', doc);
    return () => buildComponentsDocument(planted);
  }

  const RESULTS_ID = 'https://mitre.github.io/hdf-libs/schemas/hdf-results/v3.7.0';

  // Nothing in the embed refs a resource as a whole today, so this path would
  // otherwise be untested code that breaks the first time a schema uses it.
  it('maps a fragment-less ref to a known resource onto its root component', () => {
    const built = withPlantedRef(RESULTS_ID)();
    const props = built.components.schemas.HdfComparison as JsonSchema;
    expect((props.properties as Record<string, JsonSchema>).planted).toEqual({
      $ref: '#/components/schemas/HdfResults',
    });
  });

  it('rejects a fragment-less ref to a resource it does not know', () => {
    expect(withPlantedRef('https://example.invalid/whatever/v1')).toThrow(
      /unknown resource with no fragment/i,
    );
  });

  it('rejects a fragment that is not a /$defs/<name> pointer', () => {
    expect(withPlantedRef(`${RESULTS_ID}#/properties/baselines`)).toThrow(
      /not a \/\$defs\/<name> pointer/i,
    );
  });

  // Scope is the whole reason the rewrite resolves rather than string-replaces:
  // Checksum is defined by the common primitive, not by the comparison root.
  it('rejects a local ref to a name another resource owns', () => {
    expect(withPlantedRef('#/$defs/Checksum')).toThrow(/does not define Checksum/i);
  });

  it('names the owning resource when a scope is wrong', () => {
    expect(withPlantedRef('#/$defs/Checksum')).toThrow(/is defined by .*primitives\/common/i);
  });
});

describe('structural guards on the bundle shape', () => {
  it('rejects a resource wrapper nested inside another wrapper', () => {
    const planted = new Map(bundles);
    const doc = structuredClone(planted.get('hdf-results.schema.json')) as JsonSchema;
    const defs = doc.$defs as Record<string, JsonSchema>;
    const commonKey = Object.keys(defs).find((k) => k.includes('primitives/common'))!;
    const common = defs[commonKey];
    (common.$defs as Record<string, JsonSchema>)['https://example.invalid/nested/v1'] = {
      $id: 'https://example.invalid/nested/v1',
    };
    planted.set('hdf-results.schema.json', doc);
    expect(() => buildComponentsDocument(planted)).toThrow(/nested resource wrapper/i);
  });

  // The transform strips $defs at every depth. At a resource root that is correct
  // (the entries are hoisted); below one it would delete schema nobody hoisted, so
  // it must fail instead of quietly succeeding.
  it('rejects a $defs nested below a resource root', () => {
    const planted = new Map(bundles);
    const doc = structuredClone(planted.get('hdf-results.schema.json')) as JsonSchema;
    const defs = doc.$defs as Record<string, JsonSchema>;
    const target = defs.Evaluated_Requirement as JsonSchema;
    target.$defs = { Smuggled: { type: 'string' } };
    planted.set('hdf-results.schema.json', doc);
    expect(() => buildComponentsDocument(planted)).toThrow(/nested \$defs inside a definition/i);
  });

  // Without $id a bundle has no resource scope, so every ref in it would resolve
  // against `undefined` and fail later as a confusing unresolvable-ref.
  it('rejects a bundle carrying no $id', () => {
    const planted = new Map(bundles);
    const doc = structuredClone(planted.get('hdf-plan.schema.json')) as JsonSchema;
    delete doc.$id;
    planted.set('hdf-plan.schema.json', doc);
    expect(() => buildComponentsDocument(planted)).toThrow(/hdf-plan.schema.json has no \$id/i);
  });

  it('rejects a bundle with no registered root component name', () => {
    const planted = new Map(bundles);
    planted.set('hdf-unregistered.schema.json', { $id: 'https://example.invalid/x/v1' });
    expect(() => buildComponentsDocument(planted)).toThrow(/no root component name/i);
  });
});

describe('the discard of wrapper bodies stays safe', () => {
  // Both the transform and the expectation drop a non-root wrapper's own body. That is
  // only sound while those bodies hold nothing but prose — a wrapper body carrying real
  // schema would be silently lost with every assertion still agreeing. Fail instead.
  it('carries nothing but prose in the 18 discarded wrapper bodies', () => {
    const rootIds = new Set([...bundles.values()].map((b) => b.$id as string));
    const discarded: { scope: string; keys: string[] }[] = [];
    for (const bundle of bundles.values()) {
      for (const [key, value] of Object.entries((bundle.$defs ?? {}) as Record<string, JsonSchema>)) {
        if (!key.includes('://')) continue;
        const scope = (value.$id as string) ?? key;
        if (rootIds.has(scope)) continue;
        const keys = Object.keys(value).filter(
          (k) => k !== '$id' && k !== '$schema' && k !== '$defs',
        );
        if (!discarded.some((d) => d.scope === scope)) discarded.push({ scope, keys });
      }
    }
    expect(discarded).toHaveLength(18);
    for (const { scope, keys } of discarded) {
      expect(keys.sort(), `wrapper ${scope} carries more than prose`).toEqual([
        'description',
        'title',
      ]);
    }
  });
});

describe('the document is a valid OpenAPI 3.1 shell', () => {
  it('declares 3.1 and the 2020-12 dialect', () => {
    expect(doc.openapi).toMatch(/^3\.1\./);
    expect(doc.jsonSchemaDialect).toBe('https://json-schema.org/draft/2020-12/schema');
  });

  it('carries the schema version from the embed $id, not the package version', () => {
    const results = bundles.get('hdf-results.schema.json') as JsonSchema;
    const version = /\/v(\d+\.\d+\.\d+)$/.exec(results.$id as string)![1];
    expect(doc.info.version).toBe(version);
  });

  // `license` is required by Redocly's lint. `contact` is not enforced by anything now
  // that Spectral is deferred — it stays because a published contract should say who owns
  // it, and this assertion is what holds it in place.
  it('states its licence as an SPDX identifier and names a contact', () => {
    expect(doc.info.license).toEqual({ name: 'Apache-2.0', identifier: 'Apache-2.0' });
    expect(doc.info.contact?.url).toBe('https://saf.mitre.org');
  });
});

describe('guards fail when violated', () => {
  it('rejects a same-name definition with a different body', () => {
    const planted = new Map(bundles);
    const baseline = structuredClone(planted.get('hdf-baseline.schema.json')) as JsonSchema;
    const defs = baseline.$defs as Record<string, JsonSchema>;
    // Redefine a name that hdf-results also defines, with a different body.
    defs.Evaluated_Requirement = { type: 'string', description: 'planted collision' };
    planted.set('hdf-baseline.schema.json', baseline);
    expect(() => buildComponentsDocument(planted)).toThrow(/collision|Evaluated_Requirement/i);
  });

  it('rejects a definition count that no longer matches the tracked expectation', () => {
    const planted = new Map(bundles);
    const results = structuredClone(planted.get('hdf-results.schema.json')) as JsonSchema;
    (results.$defs as Record<string, JsonSchema>).Planted_Extra_Definition = { type: 'string' };
    planted.set('hdf-results.schema.json', results);
    expect(() => buildComponentsDocument(planted, { expectedDefinitions: 115 })).toThrow(
      /count|116|115/i,
    );
  });

  it('rejects a $ref whose target does not exist in the scope it names', () => {
    const planted = new Map(bundles);
    const results = structuredClone(planted.get('hdf-results.schema.json')) as JsonSchema;
    const props = results.properties as Record<string, JsonSchema>;
    props.planted = { $ref: '#/$defs/Does_Not_Exist' };
    planted.set('hdf-results.schema.json', results);
    expect(() => buildComponentsDocument(planted)).toThrow(/Does_Not_Exist|unresolv/i);
  });

  it('rejects an unrecognized absolute $ref scope', () => {
    const planted = new Map(bundles);
    const results = structuredClone(planted.get('hdf-results.schema.json')) as JsonSchema;
    const props = results.properties as Record<string, JsonSchema>;
    props.planted = { $ref: 'https://example.invalid/nope/v1#/$defs/Thing' };
    planted.set('hdf-results.schema.json', results);
    expect(() => buildComponentsDocument(planted)).toThrow(/example\.invalid|unknown resource/i);
  });
});
