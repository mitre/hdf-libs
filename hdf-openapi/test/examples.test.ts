import { readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { validateExample } from '../src/validate-example.js';

const HERE = new URL('.', import.meta.url).pathname;
const DIST = join(HERE, '..', 'dist');
const SRC = join(HERE, '..', 'src');

interface OpenApiDocument {
  components: { schemas: Record<string, unknown>; responses?: Record<string, unknown> };
  paths?: Record<string, unknown>;
}

const load = (name: string): OpenApiDocument =>
  JSON.parse(readFileSync(join(DIST, name), 'utf-8')) as OpenApiDocument;

const DOCUMENTS: [string, OpenApiDocument][] = [
  ['hdf-components.oas.json', load('hdf-components.oas.json')],
  ['hdf-api.oas.json', load('hdf-api.oas.json')],
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
  return found;
}

describe('every example in both published documents validates against its own schema', () => {
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
    const api = DOCUMENTS.find(([n]) => n === 'hdf-api.oas.json')![1];
    const where = sites(api).map((s) => s.where);
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

// §3: a problem example must not leak the MCP it was derived from. `nextCall` is rewritten
// by the generator, and `detail` must not carry paths or raw upstream strings — so a tool
// name or an HDF_MCP_ env var surviving into an example means the rewrite did not run.
describe('no problem example leaks the MCP surface', () => {
  const toolNames = (
    JSON.parse(readFileSync(join(SRC, 'tools-list.golden.json'), 'utf-8')) as {
      tools: { name: string }[];
    }
  ).tools.map((t) => t.name);

  const problemExamples = (): { where: string; text: string }[] => {
    const found: { where: string; text: string }[] = [];
    for (const [name, doc] of DOCUMENTS) {
      for (const site of sites(doc)) {
        if (!site.where.includes('problem+json')) continue;
        site.examples.forEach((example, i) => {
          found.push({ where: `${name} ${site.where}[${i}]`, text: JSON.stringify(example) });
        });
      }
    }
    return found;
  };

  it('there are problem examples to check', () => {
    expect(toolNames.length).toBeGreaterThan(5);
    expect(problemExamples().length).toBeGreaterThan(5);
  });

  it('carries no HDF_MCP_ substring', () => {
    for (const { where, text } of problemExamples()) {
      expect(text, where).not.toContain('HDF_MCP_');
    }
  });

  it('names no MCP tool', () => {
    for (const { where, text } of problemExamples()) {
      for (const tool of toolNames) {
        expect(text, `${where} names ${tool}`).not.toContain(tool);
      }
    }
  });
});

// AC2 rests entirely on validateExample REPORTING a fault, and the committed suite only
// ever exercised the path where it finds none — so its fault branch was uncovered and the
// whole gate above could have been passing on a helper that never returns anything.
describe('the harness this gate rests on can report a fault', () => {
  it('reports the index and the error when an example violates its schema', () => {
    const faults = validateExample({
      type: 'object',
      required: ['status'],
      properties: { status: { type: 'integer' } },
      examples: [{ status: 404 }, { status: 'four-oh-four' }, {}],
    });
    expect(faults.map((f) => f.index)).toEqual([1, 2]);
    expect(faults[0]!.errors).toContain('must be integer');
    expect(faults[1]!.errors).toContain('status');
  });

  it('resolves a $ref through the references it is handed', () => {
    const references = {
      Problem: { type: 'object', required: ['status'], properties: { status: { type: 'integer' } } },
    };
    expect(
      validateExample({ $ref: '#/components/schemas/Problem', examples: [{ status: 404 }] }, references),
    ).toEqual([]);
    expect(
      validateExample(
        { $ref: '#/components/schemas/Problem', examples: [{ status: 'no' }] },
        references,
      ),
    ).toHaveLength(1);
  });
});
