import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from 'vitest';
import { validateExample } from '../src/validate-example.js';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const DIST = join(HERE, '..', 'dist');

interface OpenApiDocument {
  components: {
    schemas: Record<string, unknown>;
    responses?: Record<string, unknown>;
    headers?: Record<string, unknown>;
    parameters?: Record<string, unknown>;
    requestBodies?: Record<string, unknown>;
  };
  paths?: Record<string, unknown>;
}

const load = (name: string): OpenApiDocument =>
  JSON.parse(readFileSync(join(DIST, name), 'utf-8')) as OpenApiDocument;

// One document since the reference API moved to the sibling repository. Kept as a list so
// a second document does not need this file restructured.
const DOCUMENTS: [string, OpenApiDocument][] = [
  ['hdf-components.oas.json', load('hdf-components.oas.json')],
];

/** An example, the schema it must satisfy, and where it was found. */
interface Site {
  where: string;
  schema: Record<string, unknown>;
  examples: unknown[];
}

/** Keywords whose value is a schema, a map of schemas, or a list of schemas. */
const SCHEMA_VALUED = new Set([
  'items',
  'additionalProperties',
  'unevaluatedProperties',
  'unevaluatedItems',
  'additionalItems',
  'contains',
  'propertyNames',
  'contentSchema',
  'not',
  'if',
  'then',
  'else',
]);
const SCHEMA_MAPS = new Set([
  'properties',
  'patternProperties',
  'dependentSchemas',
  'dependencies',
  '$defs',
  'definitions',
]);
const SCHEMA_LISTS = new Set(['oneOf', 'anyOf', 'allOf', 'prefixItems']);

/**
 * Every subschema under `schema` that carries its own `examples`, including the root.
 *
 * A nested one is easy to miss and was: `Cvss/properties/source` and
 * `HdfResults/properties/preAmendmentChecksum` each carry an `examples` array of their own,
 * and validating the enclosing component exercises those subschemas without ever checking
 * their examples against them. Four examples per document sat outside this gate.
 */
function schemaSites(schema: unknown, where: string): Site[] {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return [];
  const node = schema as Record<string, unknown>;
  const found: Site[] = [];
  if (Array.isArray(node.examples)) {
    found.push({ where, schema: node, examples: node.examples });
  }
  for (const [key, value] of Object.entries(node)) {
    if (SCHEMA_VALUED.has(key)) {
      // `items` may be a LIST of schemas in the draft-07 tuple form. Neither document uses
      // it, but schemaSites returns [] for an array, so without this the subschemas and
      // their examples would be invisible rather than merely absent.
      if (Array.isArray(value)) {
        value.forEach((sub, i) => found.push(...schemaSites(sub, `${where}/${key}/${i}`)));
      } else {
        found.push(...schemaSites(value, `${where}/${key}`));
      }
    } else if (SCHEMA_MAPS.has(key) && value !== null && typeof value === 'object') {
      for (const [member, sub] of Object.entries(value)) {
        found.push(...schemaSites(sub, `${where}/${key}/${member}`));
      }
    } else if (SCHEMA_LISTS.has(key) && Array.isArray(value)) {
      value.forEach((sub, i) => found.push(...schemaSites(sub, `${where}/${key}/${i}`)));
    }
  }
  return found;
}

/**
 * Every example in a document, paired with the schema that governs it.
 *
 * Two shapes carry one: a schema with its own `examples` array — at any depth, which is
 * what schemaSites walks — and any object with a `schema` member and an `example`/
 * `examples` sibling, which is a media type, a header or a parameter. Walking for
 * `example` keys alone would find the values and not know what to check them against,
 * which is how an unchecked example survives.
 */
function sites(doc: OpenApiDocument): Site[] {
  const found: Site[] = [];
  for (const [name, schema] of Object.entries(doc.components.schemas)) {
    found.push(...schemaSites(schema, `components/schemas/${name}`));
  }
  const walk = (node: unknown, where: string): void => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${where}/${i}`));
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const object = node as Record<string, unknown>;
    if (object.schema !== null && typeof object.schema === 'object') {
      const single = 'example' in object ? [object.example] : [];
      const named =
        object.examples !== null && typeof object.examples === 'object'
          ? Object.values(object.examples as Record<string, { value?: unknown }>).map(
              (e) => e.value,
            )
          : [];
      const examples = [...single, ...named];
      if (examples.length > 0) {
        found.push({ where, schema: object.schema as Record<string, unknown>, examples });
      }
      // The schema under it may carry examples of its own, at any depth.
      found.push(...schemaSites(object.schema, `${where}/schema`));
    }
    for (const [key, value] of Object.entries(object)) {
      if (key === 'schema') continue;
      walk(value, `${where}/${key}`);
    }
  };
  walk(doc.paths ?? {}, 'paths');
  walk(doc.components.responses ?? {}, 'components/responses');
  // The regions the comment below predicted. ETag, Retry-After and the RateLimit pair
  // became shared components, and their examples lived outside the gate for one build.
  walk(doc.components.headers ?? {}, 'components/headers');
  walk(doc.components.parameters ?? {}, 'components/parameters');
  walk(doc.components.requestBodies ?? {}, 'components/requestBodies');
  return found;
}

describe('every example in the published document validates against its own schema', () => {
  /**
   * Every position in the document that carries an `example` or `examples` key, found by a
   * walk that knows nothing about schema keywords.
   *
   * This is the yardstick `sites()` is measured against, and it is deliberately not a
   * recorded number. An exact count catches a walk that reaches too FEW of the positions
   * it visits, but not one that never visits a region at all — examples appearing later
   * under components.parameters, components.headers, components.requestBodies or
   * webhooks would leave the count unchanged and the assertion still green. It also
   * invites being bumped to match whatever the walk currently finds.
   *
   * It does not descend into an example's VALUE, where an `examples` key would be data.
   */
  const examplePositions = (node: unknown, where = ''): string[] => {
    if (Array.isArray(node)) return node.flatMap((v, i) => examplePositions(v, `${where}/${i}`));
    if (node === null || typeof node !== 'object') return [];
    const found: string[] = [];
    for (const [key, value] of Object.entries(node)) {
      if (key === 'example' || key === 'examples') {
        found.push(`${where}/${key}`);
        continue;
      }
      found.push(...examplePositions(value, `${where}/${key}`));
    }
    return found;
  };

  it.each(DOCUMENTS.map(([name]) => name))('%s: the walk reaches every example', (name) => {
    const doc = DOCUMENTS.find(([n]) => n === name)![1];
    const positions = examplePositions(doc);
    expect(positions.length, `${name} carries no examples at all`).toBeGreaterThan(5);
    expect(sites(doc).length, `${name}: the walk reaches fewer positions than exist`).toBe(
      positions.length,
    );
  });

  it('reaches the nested subschema examples a top-level-only walk misses', () => {
    // Both are HDF component schemas, so they are in this document whether or not an API
    // document exists — the nested-walk defect this guards is the same either way.
    const doc = DOCUMENTS.find(([n]) => n === 'hdf-components.oas.json')![1];
    const where = sites(doc).map((s) => s.where);
    expect(where).toContain('components/schemas/Cvss/properties/source');
    expect(where).toContain('components/schemas/HdfResults/properties/preAmendmentChecksum');
  });

  it.each(DOCUMENTS.map(([name]) => name))('%s: every example validates', (name) => {
    const doc = DOCUMENTS.find(([n]) => n === name)![1];
    const failures: string[] = [];
    for (const site of sites(doc)) {
      // A site's own `examples` array is what validateExample reads, so a single
      // `example` is handed over as a one-member array rather than special-cased.
      const faults = validateExample(
        { ...site.schema, examples: site.examples },
        doc.components.schemas,
      );
      for (const fault of faults) {
        failures.push(`${site.where}[${fault.index}]: ${fault.errors}`);
      }
    }
    expect(failures).toEqual([]);
  });
});

// The helper is exported as published API and ADR-0008 §2 makes a CHECKED example the
// condition of the conventions privilege, so its ability to report a fault has to be pinned
// directly: every other use of it here feeds it examples that pass, which cannot tell a
// working validator from one that always returns no faults.
describe('validateExample reports faults', () => {
  it('reports an example that violates its own schema', () => {
    const faults = validateExample({
      type: 'object',
      properties: { n: { type: 'integer' } },
      required: ['n'],
      examples: [{ n: 'not an integer' }],
    });
    expect(faults).toHaveLength(1);
    expect(faults[0]!.index).toBe(0);
    expect(faults[0]!.errors).toContain('integer');
  });

  it('indexes each fault by its position, passing examples included', () => {
    const faults = validateExample({
      type: 'object',
      properties: { n: { type: 'integer' } },
      examples: [{ n: 1 }, { n: 'bad' }, { n: 2 }, { n: 'also bad' }],
    });
    expect(faults.map((f) => f.index)).toEqual([1, 3]);
  });

  it('resolves a $ref into the supplied references rather than failing to compile', () => {
    const schema = { $ref: '#/components/schemas/Inner', examples: [{ k: 'wrong type' }] };
    const references = { Inner: { type: 'object', properties: { k: { type: 'number' } } } };
    expect(validateExample(schema, references)).toHaveLength(1);
    expect(validateExample({ ...schema, examples: [{ k: 1 }] }, references)).toEqual([]);
  });

  it('is silent about a schema carrying no examples, rather than inventing a fault', () => {
    expect(validateExample({ type: 'object' })).toEqual([]);
    expect(validateExample({ type: 'object', examples: 'not a list' })).toEqual([]);
  });
});

// Card i6889.2's own first failing test: the package emits the components document and no
// API document. The DOCUMENTS list above records the expectation in prose; this asserts it
// against what the build actually wrote.
describe('the built artifacts', () => {
  const built = readdirSync(DIST);

  it('include the components document', () => {
    expect(built).toContain('hdf-components.oas.json');
    expect(built).toContain('hdf-components.oas.yaml');
  });

  it('include no reference API document', () => {
    expect(built.length).toBeGreaterThan(2);
    expect(built.filter((f) => /hdf-api/.test(f))).toEqual([]);
  });
});
