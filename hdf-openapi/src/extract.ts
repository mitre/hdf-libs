import type { ComponentsDocument, JsonSchema } from './components.js';

const DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const COMPONENT_PREFIX = '#/components/schemas/';
const LOCAL_PREFIX = '#/$defs/';

/** Every component name a schema references directly. */
function directRefs(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const item of node) directRefs(item, into);
    return;
  }
  if (node === null || typeof node !== 'object') return;
  for (const [key, value] of Object.entries(node)) {
    if (key === '$ref' && typeof value === 'string' && value.startsWith(COMPONENT_PREFIX)) {
      into.add(value.slice(COMPONENT_PREFIX.length));
      continue;
    }
    // examples are data, not schemas: a string inside one that happens to look like a
    // ref must not drag a component into the closure.
    if (key !== 'examples') directRefs(value, into);
  }
}

/** Rewrites component pointers to local `$defs` pointers. */
function localise(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(localise);
  if (node === null || typeof node !== 'object') return node;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === '$ref' && typeof value === 'string' && value.startsWith(COMPONENT_PREFIX)) {
      out[key] = `${LOCAL_PREFIX}${value.slice(COMPONENT_PREFIX.length)}`;
      continue;
    }
    out[key] = key === 'examples' ? value : localise(value);
  }
  return out;
}

/**
 * Lifts one component out of the components document as a schema that validates on its
 * own — the inverse of the components transform, and the only way to check that the
 * transform preserved meaning rather than merely producing well-formed output.
 *
 * The closure is walked transitively rather than copying every component, so what comes
 * back is the subgraph the named component actually depends on. A component that dragged
 * in the whole document would make the test pass for the wrong reason.
 *
 * Validate the result with a 2020-12 engine. This repository's own validators are
 * draft-07 and ignore `unevaluatedProperties` (ADR-0009 §5), so they would accept
 * documents the schema text rejects.
 */
export function extractStandaloneSchema(doc: ComponentsDocument, name: string): JsonSchema {
  const all = doc.components.schemas;
  const root = all[name];
  if (root === undefined) {
    throw new Error(`no component named ${name} in the document`);
  }

  // Breadth-first closure over component references. `seen` doubles as the cycle guard:
  // the HDF schemas are mutually recursive (a component can reach itself), so a naive
  // recursive copy would not terminate.
  const seen = new Set<string>();
  const queue = [name];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    if (seen.has(current)) continue;
    seen.add(current);
    const schema = all[current];
    if (schema === undefined) {
      throw new Error(`dangling reference to ${current} while extracting ${name}`);
    }
    const next = new Set<string>();
    directRefs(schema, next);
    for (const dep of next) if (!seen.has(dep)) queue.push(dep);
  }

  // The root itself is inlined rather than referenced, so the result is usable directly;
  // it stays in $defs too, because a mutually recursive schema may point back at it.
  const defs: Record<string, JsonSchema> = {};
  for (const dep of [...seen].sort()) {
    defs[dep] = localise(all[dep]) as JsonSchema;
  }

  return {
    $schema: DIALECT,
    ...(localise(root) as JsonSchema),
    $defs: defs,
  };
}
