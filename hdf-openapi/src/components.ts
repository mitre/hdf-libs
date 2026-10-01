export interface JsonSchema {
  [key: string]: unknown;
}

export interface ComponentsDocument {
  openapi: string;
  info: { title: string; version: string; description: string };
  jsonSchemaDialect: string;
  components: { schemas: Record<string, JsonSchema> };
}

/** The bundler's own list (hdf-schema/src/bundle-schemas.ts), in its order. */
export const MAIN_SCHEMAS = [
  'hdf-results.schema.json',
  'hdf-baseline.schema.json',
  'hdf-comparison.schema.json',
  'hdf-system.schema.json',
  'hdf-plan.schema.json',
  'hdf-amendments.schema.json',
  'hdf-evidence-package.schema.json',
  'hdf-requirement-change-event.schema.json',
] as const;

export const ROOT_COMPONENT_NAMES: Record<string, string> = {
  'hdf-results.schema.json': 'HdfResults',
  'hdf-baseline.schema.json': 'HdfBaseline',
  'hdf-comparison.schema.json': 'HdfComparison',
  'hdf-system.schema.json': 'HdfSystem',
  'hdf-plan.schema.json': 'HdfPlan',
  'hdf-amendments.schema.json': 'HdfAmendments',
  'hdf-evidence-package.schema.json': 'HdfEvidencePackage',
  'hdf-requirement-change-event.schema.json': 'HdfRequirementChangeEvent',
};

/** Named definitions across the bundles, excluding the eight roots. */
export const EXPECTED_DEFINITIONS = 115;

const DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const COMPONENT_PREFIX = '#/components/schemas/';
const RESOURCE_KEYS = new Set(['$id', '$schema', '$defs']);

/** One JSON Schema resource: an $id and the named definitions it owns. */
interface Resource {
  scope: string;
  defs: Record<string, JsonSchema>;
  /** Root-level keywords, when this resource is also a document root. */
  rootBody?: JsonSchema;
  rootName?: string;
}

function isUrlKey(key: string): boolean {
  return key.includes('://');
}

function namedDefs(defs: Record<string, unknown>): Record<string, JsonSchema> {
  const out: Record<string, JsonSchema> = {};
  for (const [k, v] of Object.entries(defs)) {
    if (!isUrlKey(k)) out[k] = v as JsonSchema;
  }
  return out;
}

function withoutResourceKeys(schema: JsonSchema): JsonSchema {
  const out: JsonSchema = {};
  for (const [k, v] of Object.entries(schema)) {
    if (!RESOURCE_KEYS.has(k)) out[k] = v;
  }
  return out;
}

/**
 * Enumerates the resources in one bundle: the root, plus each URL-keyed wrapper.
 * A wrapper whose $id is a document root's (the hdf-results resource embedded in
 * comparison and change-event) carries that root's body too, so it deduplicates
 * onto the root component instead of being lost or colliding.
 */
function resourcesOf(file: string, bundle: JsonSchema, rootIds: Map<string, string>): Resource[] {
  const defs = (bundle.$defs ?? {}) as Record<string, unknown>;
  const rootScope = bundle.$id as string;
  const resources: Resource[] = [
    {
      scope: rootScope,
      defs: namedDefs(defs),
      rootBody: withoutResourceKeys(bundle),
      rootName: ROOT_COMPONENT_NAMES[file],
    },
  ];
  for (const [key, value] of Object.entries(defs)) {
    if (!isUrlKey(key)) continue;
    const wrapper = value as JsonSchema;
    const scope = (wrapper.$id as string | undefined) ?? key;
    const nested = (wrapper.$defs ?? {}) as Record<string, unknown>;
    for (const nestedKey of Object.keys(nested)) {
      if (isUrlKey(nestedKey)) {
        throw new Error(`nested resource wrapper inside ${scope}: ${nestedKey}`);
      }
    }
    const embeddedRootName = rootIds.get(scope);
    resources.push({
      scope,
      defs: namedDefs(nested),
      ...(embeddedRootName
        ? { rootBody: withoutResourceKeys(wrapper), rootName: embeddedRootName }
        : {}),
    });
  }
  return resources;
}

/**
 * Rewrites one $ref to a component pointer. The scope matters: a local
 * `#/$defs/X` resolves against the resource that encloses it, not against the
 * bundle, so a global string replace would silently retarget refs inside an
 * embedded primitive. Every target is checked to exist in the scope it names, so
 * the rewrite is a resolution rather than a substitution.
 */
function rewriteRef(ref: string, scope: string, owners: Map<string, Set<string>>, rootIds: Map<string, string>): string {
  const hash = ref.indexOf('#');
  const base = hash === -1 ? ref : ref.slice(0, hash);
  const fragment = hash === -1 ? undefined : ref.slice(hash + 1);
  const targetScope = base === '' ? scope : base;

  if (fragment === undefined || fragment === '') {
    const rootName = rootIds.get(targetScope);
    if (!rootName) {
      throw new Error(`$ref to an unknown resource with no fragment: ${ref}`);
    }
    return `${COMPONENT_PREFIX}${rootName}`;
  }

  const match = /^\/\$defs\/([^/]+)$/.exec(fragment);
  const captured = match?.[1];
  if (captured === undefined) {
    throw new Error(`$ref fragment is not a /$defs/<name> pointer: ${ref}`);
  }
  const name = decodeURIComponent(captured);
  const scopes = owners.get(name);
  if (!scopes) {
    throw new Error(`unresolvable $ref ${ref}: no resource defines ${name}`);
  }
  if (!scopes.has(targetScope)) {
    const known = [...scopes].join(', ');
    throw new Error(
      `unresolvable $ref ${ref}: resource ${targetScope} does not define ${name}; ` +
        `${name} is defined by ${known}`,
    );
  }
  return `${COMPONENT_PREFIX}${name}`;
}

function rewriteRefsDeep(
  node: unknown,
  scope: string,
  owners: Map<string, Set<string>>,
  rootIds: Map<string, string>,
  depth = 0,
): unknown {
  if (Array.isArray(node)) {
    return node.map((item) => rewriteRefsDeep(item, scope, owners, rootIds, depth + 1));
  }
  if (node === null || typeof node !== 'object') return node;

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    // $defs below a resource root would be a definition nobody hoisted. Stripping
    // it silently deletes schema; refuse instead. Today there are none.
    if (key === '$defs' && depth > 0) {
      throw new Error(
        `nested $defs inside a definition of ${scope}; hoisting does not reach it and stripping would silently drop schema`,
      );
    }
    if (RESOURCE_KEYS.has(key)) continue;
    if (key === '$ref' && typeof value === 'string') {
      out[key] = rewriteRef(value, scope, owners, rootIds);
      continue;
    }
    // examples are data, not schemas: a string inside one that happens to be
    // named $ref must not be rewritten.
    out[key] = key === 'examples' ? value : rewriteRefsDeep(value, scope, owners, rootIds, depth + 1);
  }
  return out;
}

const canonical = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)));
    }
    return v;
  });

export interface BuildOptions {
  /** Tracked expectation for the named-definition count; a mismatch fails. */
  expectedDefinitions?: number;
}

export function buildComponentsDocument(
  bundles: Map<string, JsonSchema>,
  options: BuildOptions = {},
): ComponentsDocument {
  const rootIds = new Map<string, string>();
  for (const [file, bundle] of bundles) {
    const name = ROOT_COMPONENT_NAMES[file];
    if (!name) throw new Error(`no root component name registered for ${file}`);
    const id = bundle.$id;
    if (typeof id !== 'string' || id === '') {
      throw new Error(`${file} has no $id; every bundle is a JSON Schema resource and must carry one`);
    }
    rootIds.set(id, name);
  }

  // Pass one: which resource owns which definition name. Refs are resolved
  // against this, so it must be complete before any rewriting happens.
  const allResources: Resource[] = [];
  const owners = new Map<string, Set<string>>();
  for (const [file, bundle] of bundles) {
    for (const resource of resourcesOf(file, bundle, rootIds)) {
      allResources.push(resource);
      for (const name of Object.keys(resource.defs)) {
        let set = owners.get(name);
        if (!set) owners.set(name, (set = new Set()));
        set.add(resource.scope);
      }
    }
  }

  // Pass two: hoist, strip, rewrite, and deduplicate by deep equality.
  const schemas: Record<string, JsonSchema> = {};
  const origin = new Map<string, string>();
  const definitionNames = new Set<string>();

  const place = (name: string, body: JsonSchema, scope: string, isRoot: boolean): void => {
    // Only a resource root may carry $defs — the hoist consumes it. A definition
    // therefore starts at depth 1 so its own $defs trips the guard below.
    const rewritten = rewriteRefsDeep(body, scope, owners, rootIds, isRoot ? 0 : 1) as JsonSchema;
    const existing = schemas[name];
    if (existing !== undefined) {
      if (canonical(existing) !== canonical(rewritten)) {
        throw new Error(
          `component name collision: ${name} is defined differently by ${origin.get(name)} and ${scope}`,
        );
      }
      return;
    }
    schemas[name] = rewritten;
    origin.set(name, scope);
    if (!isRoot) definitionNames.add(name);
  };

  for (const resource of allResources) {
    for (const [name, body] of Object.entries(resource.defs)) {
      place(name, body, resource.scope, false);
    }
  }
  // Roots last: a root body's refs resolve in its own scope, and placing them
  // after the definitions means the embedded hdf-results copy deduplicates onto
  // the standalone one rather than racing it.
  for (const resource of allResources) {
    if (resource.rootBody && resource.rootName) {
      place(resource.rootName, resource.rootBody, resource.scope, true);
    }
  }

  const expected = options.expectedDefinitions ?? EXPECTED_DEFINITIONS;
  if (definitionNames.size !== expected) {
    throw new Error(
      `definition count mismatch: hoisted ${definitionNames.size}, expected ${expected}. ` +
        `If the schema set genuinely changed, update EXPECTED_DEFINITIONS and the tracked test baseline in the same change.`,
    );
  }

  // From the $id, never package.json: the two version axes are independent (ADR §4).
  // They diverged at the v3.7.1 release — package 3.7.1, schema $id still v3.7.0,
  // because a patch release leaves the $id alone — so the test for this is load-bearing.
  const resultsId = bundles.get('hdf-results.schema.json')?.$id as string | undefined;
  const version = resultsId ? (/\/v(\d+\.\d+\.\d+)$/.exec(resultsId)?.[1] ?? '0.0.0') : '0.0.0';

  return {
    openapi: '3.1.1',
    info: {
      title: 'HDF Components',
      version,
      description:
        'OpenAPI 3.1 components generated from the HDF JSON Schema 2020-12 bundles. ' +
        'Generated — do not edit by hand.',
    },
    jsonSchemaDialect: DIALECT,
    components: { schemas },
  };
}
