// Generate the reference API document from the MCP contract, the binding table and the
// conventions components.
//
// Nothing here authors an API. Every path, method and placement comes from
// src/bindings.yaml; every shape is a generated component, a reflected shape from the
// contract golden, or a conventions component referenced by name. The rules this applies
// — the fixed rewrite map, the problem-type table, the response conventions — are
// ADR-0008 §2/§3 and ADR-0010 §6, consumed rather than reinterpreted.

import { createHash } from 'crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { FILESYSTEM_FIELDS, loadBindings, type BindingTable, type ToolBinding } from './bindings.js';
import { loadConventions } from './conventions.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, '..', 'dist');

/**
 * ADR-0010 §6, consumed as written: the codes it gives an HTTP status, with the status and
 * the kebab-cased problem type. The `type` is the hosted prefix plus the kebab code, which
 * §6 states rather than leaves to the reader.
 */
export const PROBLEM_TYPES: Record<string, { status: number; type: string }> = {
  DOCUMENT_NOT_FOUND: { status: 404, type: 'document-not-found' },
  HANDLE_STALE: { status: 412, type: 'handle-stale' },
  TOO_LARGE: { status: 413, type: 'payload-too-large' },
  SCHEMA_INVALID: { status: 422, type: 'schema-invalid' },
  WRONG_DOC_TYPE: { status: 422, type: 'wrong-doc-type' },
  NO_CONVERTER: { status: 422, type: 'no-converter' },
  AMBIGUOUS_FORMAT: { status: 422, type: 'ambiguous-format' },
};

/**
 * The codes ADR-0010 §6 marks `never`. Recorded rather than silently dropped: each is a
 * `file`-adapter concern with no HTTP surface, and TRUNCATED is dead in the MCP too.
 */
export const UNMAPPED_CODES = [
  'CACHE_MISS',
  'OUTPUT_EXISTS',
  'PATH_DENIED',
  'WRITE_FAILED',
  'TRUNCATED',
];

const PROBLEM_BASE = 'https://mitre.github.io/hdf-libs/problems';

/**
 * RFC 9457 problem details. `additionalProperties` is true because the RFC admits
 * extension members and ADR-0008 §3 uses one: the 403 carries `scope` naming what was
 * missing. That makes Problem the one non-document schema the strictness rule exempts,
 * recorded here rather than silently waived.
 */
const PROBLEM_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['type', 'title', 'status'],
  properties: {
    type: { type: 'string', format: 'uri' },
    title: { type: 'string' },
    status: { type: 'integer' },
    detail: { type: 'string' },
    instance: { type: 'string', format: 'uri' },
  },
  description:
    'RFC 9457 problem details. Extension members are permitted; the 403 carries `scope`.',
};

/** Schemas exempt from the additionalProperties:false rule, each with its reason. */
export const STRICTNESS_EXEMPT: Record<string, string> = {
  Problem: 'RFC 9457 admits extension members, and §3 uses one (`scope` on the 403)',
};

function problemRef(title: string, status: number, type: string): Record<string, unknown> {
  return {
    description: title,
    content: {
      'application/problem+json': {
        schema: { $ref: '#/components/schemas/Problem' },
        example: { type: `${PROBLEM_BASE}/${type}`, title, status },
      },
    },
  };
}

/**
 * The responses every operation shares. ADR-0008 §3 fixes their shapes: 403 is the one
 * insufficient-scope type for every scope failure, 401 is about:blank with a challenge,
 * and 503 carries Retry-After.
 */
function sharedResponses(): Record<string, unknown> {
  return {
    Unauthorized: {
      description: 'No or invalid credentials',
      headers: {
        'WWW-Authenticate': {
          schema: { type: 'string' },
          example: 'Bearer resource_metadata="https://hdf.example.org/.well-known/oauth-protected-resource", scope="hdf:read"',
        },
      },
      content: {
        'application/problem+json': {
          schema: { $ref: '#/components/schemas/Problem' },
          example: { type: 'about:blank', title: 'Unauthorized', status: 401 },
        },
      },
    },
    InsufficientScope: {
      ...problemRef('Insufficient scope', 403, 'insufficient-scope'),
      headers: {
        'WWW-Authenticate': {
          schema: { type: 'string' },
          example: 'Bearer error="insufficient_scope", scope="hdf:write", resource_metadata="https://hdf.example.org/.well-known/oauth-protected-resource"',
        },
      },
    },
    TooManyRequests: problemRef('Quota exceeded', 429, 'quota-exceeded'),
    InternalError: problemRef('Internal error', 500, 'internal-error'),
    StoreUnavailable: {
      ...problemRef('Store unavailable', 503, 'store-unavailable'),
      headers: { 'Retry-After': { schema: { type: 'integer' } } },
    },
    UnsupportedMediaType: problemRef('Unsupported media type', 415, 'unsupported-media-type'),
  };
}

/** ADR-0008 §4's format allowlist. A format outside it hard-fails rather than shipping. */
export const ALLOWED_FORMATS = new Set(['uuid', 'date-time', 'date', 'email', 'uri']);

/**
 * ADR-0008 §2's fixed rewrite map, output half. These are MCP transport state — a
 * filesystem path, a write gate, a page index, a handle — and none may reach HTTP. Stripped
 * from every response shape rather than waived per operation.
 */
export const STRIPPED_OUTPUT_FIELDS = new Set([
  'page',
  'nextPage',
  'handle',
  'fromHandle',
  'toHandle',
  'writesDisabled',
  'outputPath',
  'truncated',
  'returned',
]);

/**
 * Nested leaves that are open on purpose, each with the reason. Everything else that is
 * not a document schema must set additionalProperties: false.
 */
export const OPEN_LEAF_EXEMPT: Record<string, string> = {
  'query.full/tags': 'the HDF schema declares tags additionalProperties:true for tool-specific metadata',
  'diff.temporal.full/fieldChanges': 'a field change can be on any requirement field, so its values are untyped',
  'diff.system-drift.full/fieldChanges': 'same: a field change can be on any component field',
};

/** Strip the rewritten names from a response shape, recursively. */
function stripTransportState(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(stripTransportState);
  if (node === null || typeof node !== 'object') return node;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === 'properties' && value !== null && typeof value === 'object') {
      const kept: Record<string, unknown> = {};
      for (const [prop, schema] of Object.entries(value)) {
        if (!STRIPPED_OUTPUT_FIELDS.has(prop)) kept[prop] = stripTransportState(schema);
      }
      out[key] = kept;
      continue;
    }
    if (key === 'required' && Array.isArray(value)) {
      out[key] = value.filter((r) => typeof r !== 'string' || !STRIPPED_OUTPUT_FIELDS.has(r));
      continue;
    }
    out[key] = stripTransportState(value);
  }
  return out;
}

/** Every `format` used anywhere, with where it was found. */
function formatsIn(node: unknown, where: string): { format: string; where: string }[] {
  if (Array.isArray(node)) return node.flatMap((v, i) => formatsIn(v, `${where}/${i}`));
  if (node === null || typeof node !== 'object') return [];
  const found: { format: string; where: string }[] = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === 'format' && typeof value === 'string') found.push({ format: value, where });
    found.push(...formatsIn(value, `${where}/${key}`));
  }
  return found;
}

interface Operation {
  operationId: string;
  summary?: string;
  parameters?: unknown[];
  requestBody?: unknown;
  responses: Record<string, unknown>;
  security?: Record<string, string[]>[];
}

/** Scopes for a class. Read-only tools never acquire a write scope. */
function scopesFor(cls: string): string[] {
  if (cls === 'admin') return ['hdf:read', 'hdf:write', 'hdf:admin'];
  if (cls === 'write') return ['hdf:read', 'hdf:write'];
  return ['hdf:read'];
}

function problemResponse(code: string): Record<string, unknown> {
  const { type } = PROBLEM_TYPES[code]!;
  return {
    description: code,
    content: {
      'application/problem+json': {
        schema: { $ref: '#/components/schemas/Problem' },
        example: { type: `${PROBLEM_BASE}/${type}`, title: code, status: PROBLEM_TYPES[code]!.status },
      },
    },
  };
}

/**
 * Responses every operation carries. ADR-0008 §3 requires a declared 500 and the RateLimit
 * headers everywhere, and 413/415 wherever a request body exists — so they are added here
 * rather than per operation, which is what stops one being forgotten.
 */
function conventionalResponses(hasBody: boolean): Record<string, unknown> {
  const responses: Record<string, unknown> = {
    '401': { $ref: '#/components/responses/Unauthorized' },
    '403': { $ref: '#/components/responses/InsufficientScope' },
    '429': { $ref: '#/components/responses/TooManyRequests' },
    '500': { $ref: '#/components/responses/InternalError' },
    '503': { $ref: '#/components/responses/StoreUnavailable' },
  };
  if (hasBody) {
    responses['413'] = problemResponse('TOO_LARGE');
    responses['415'] = { $ref: '#/components/responses/UnsupportedMediaType' };
  }
  return responses;
}

/** The fixed rewrite map's input half: page becomes a cursor, limit stays a count. */
function parameterFor(field: string, placement: string): Record<string, unknown> {
  // The fixed rewrite map: `page` becomes an opaque cursor, and a document reference
  // placed in the path becomes `{id}` — HTTP addresses documents by id, so the parameter
  // must be named for the path template rather than for the MCP field it came from.
  const name = placement === 'path' ? 'id' : field === 'page' ? 'next' : field;
  const description =
    field === 'page'
      ? 'Opaque cursor from a previous response. Replaces the MCP page index.'
      : undefined;
  return {
    name,
    in: placement === 'path' ? 'path' : 'query',
    required: placement === 'path',
    ...(description ? { description } : {}),
    schema: { type: 'string' },
  };
}

/** First sentence of the MCP's own description: generated, not authored. */
function summarize(description: string | undefined, fallback: string): string {
  if (!description) return fallback;
  const first = description.split(/(?<=\.)\s|\n/)[0]!.trim();
  return first.length > 0 ? first : fallback;
}

function okResponse(binding: ToolBinding): Record<string, unknown> {
  const named = [binding.fullResponse ?? []].flat();
  if (named.length === 0) return { description: 'Success' };
  // One name is the shape; several are the set the table records — mode x verbosity for
  // diff, docType for open.
  //
  // anyOf, not oneOf. The alternatives are selected by a REQUEST parameter (`verbosity`,
  // `mode`), and a concise row is a strict subset of its full counterpart, so nothing in
  // the payload distinguishes them: oneOf would assert a mutual exclusivity that does not
  // hold, which Redocly flags correctly. anyOf makes the weaker claim that is true — a row
  // is one of these shapes — rather than a stronger one the generator cannot honour across
  // reflected shapes it did not design.
  const schema =
    named.length === 1
      ? { $ref: `#/components/schemas/${named[0]}` }
      : { anyOf: named.map((n) => ({ $ref: `#/components/schemas/${n}` })) };
  const items = binding.items;
  return {
    description: 'Success',
    content: {
      'application/json': {
        // The envelope: the named row shape under `items`, with the cursor the rewrite map
        // substitutes for the MCP's page index.
        schema: items
          ? {
              type: 'object',
              additionalProperties: false,
              required: [items],
              properties: {
                [items]: { type: 'array', items: schema },
                next: { type: 'string', description: 'Cursor for the following page.' },
                total: { type: 'integer' },
              },
            }
          : schema,
      },
    },
  };
}

function operationFor(
  name: string,
  binding: ToolBinding,
  cls: string,
  summary: string,
): Operation {
  const fields = Object.entries(binding.fields ?? {});
  // Every {x} in the path template gets a parameter, whether or not a field was placed
  // there — delete is synthetic, has no fields, and still addresses {id}.
  const templated = [...(binding.path ?? '').matchAll(/\{(\w+)\}/g)].map((m) => m[1]!);
  const parameters = [
    ...templated.map((name) => ({
      name,
      in: 'path',
      required: true,
      schema: { type: 'string' },
    })),
    ...fields
      .filter(([, f]) => f.placement === 'query')
      .map(([field, f]) => parameterFor(field, f.placement!)),
  ];
  const bodyFields = fields.filter(([, f]) => f.placement === 'body');
  const hasBody = bodyFields.length > 0 || binding.bodyRef !== undefined;

  const responses: Record<string, unknown> = {
    '200': okResponse(binding),
    ...conventionalResponses(hasBody),
  };
  // Every operation that addresses a document can fail to find it.
  if (binding.path?.includes('{id}')) responses['404'] = problemResponse('DOCUMENT_NOT_FOUND');

  return {
    operationId: name,
    summary,
    parameters: parameters.length > 0 ? parameters : undefined,
    requestBody: hasBody ? { required: true, content: { 'application/json': { schema: { type: 'object' } } } } : undefined,
    responses,
    security: cls === 'documentOnly' ? [] : [{ bearerAuth: scopesFor(cls) }],
  };
}

export interface ApiDocument {
  openapi: string;
  info: Record<string, string>;
  paths: Record<string, Record<string, Operation>>;
  components: Record<string, unknown>;
}

export interface GenerateOptions {
  /** Replace the tracked table, so a test can plant a fault the real one cannot carry. */
  tableOverride?: BindingTable;
  /** Extra component schemas, so a test can plant one the strictness rules must reject. */
  extraSchemas?: Record<string, unknown>;
}

export function generateApiDocument(options: GenerateOptions = {}): ApiDocument {
  const table: BindingTable =
    options.tableOverride ?? loadBindings(readFileSync(join(HERE, 'bindings.yaml'), 'utf-8'));
  const contractRaw = readFileSync(join(HERE, 'mcp-contract.golden.json'), 'utf-8');
  const toolsList = JSON.parse(readFileSync(join(HERE, 'tools-list.golden.json'), 'utf-8')) as {
    tools: { name: string; description?: string; annotations?: { readOnlyHint?: boolean } }[];
  };
  const componentsDoc = JSON.parse(
    readFileSync(join(DIST, 'hdf-components.oas.json'), 'utf-8'),
  ) as { info: { version: string }; components: { schemas: Record<string, unknown> } };
  const conventions = loadConventions();

  const paths: Record<string, Record<string, Operation>> = {};
  const describe = new Map(
    (toolsList.tools as { name: string; description?: string }[]).map((t) => [t.name, t.description]),
  );
  const add = (binding: ToolBinding, name: string, cls: string): void => {
    if (!binding.method || !binding.path) return;
    paths[binding.path] ??= {};
    paths[binding.path]![binding.method] = operationFor(
      name,
      binding,
      cls,
      summarize(describe.get(name), `${binding.method.toUpperCase()} ${binding.path}`),
    );
  };

  // class derives from readOnlyHint for every real tool — never hand-set.
  const readOnly = new Map(toolsList.tools.map((t) => [t.name, t.annotations?.readOnlyHint === true]));
  for (const [name, binding] of Object.entries(table.tools ?? {})) {
    add(binding, name, readOnly.get(name) === true ? 'read' : 'write');
  }
  // Synthetic operations carry a hand-set class, the documented exception.
  for (const [name, binding] of Object.entries(table.synthetic ?? {})) {
    add(binding, name, binding.class ?? 'read');
  }
  // Resources are read-only by construction: they serve catalogs, enums and schemas.
  for (const [name, binding] of Object.entries(table.resources ?? {})) {
    add(binding, name, 'read');
  }

  const documentSchemas = new Set(Object.keys(componentsDoc.components.schemas));
  const schemas: Record<string, unknown> = { ...componentsDoc.components.schemas };
  for (const c of conventions) schemas[c.name] = c.schema;
  schemas.Problem = PROBLEM_SCHEMA;
  // The reflected response shapes the table names, with the rewrite map applied so no MCP
  // transport state survives into an HTTP response.
  const contract = JSON.parse(contractRaw) as { fullShapes: Record<string, unknown> };
  for (const [name, shape] of Object.entries(contract.fullShapes)) {
    schemas[name] = stripTransportState(shape);
  }
  for (const [name, schema] of Object.entries(options.extraSchemas ?? {})) {
    schemas[name] = schema;
  }

  // ---- hard-fails. Each is a refusal to emit, not a warning to ignore. ----

  // An MCP filesystem input that reached a placement rather than a drop.
  for (const [tool, binding] of Object.entries(table.tools ?? {})) {
    for (const [field, spec] of Object.entries(binding.fields ?? {})) {
      if (FILESYSTEM_FIELDS.has(field) && spec.placement !== undefined) {
        throw new Error(
          `${tool}.${field} is filesystem-shaped and placed in ${spec.placement}; it must be dropped`,
        );
      }
    }
  }

  // A format outside the tracked allowlist, scoped to what the API layer INTRODUCES.
  //
  // The document schemas are generated from the HDF bundles and are authoritative about
  // their own formats: they use nine outside the allowlist, including uri-reference,
  // hostname, ipv4, ipv6 and the BOM identifiers cyclonedx, cyclonedx-ml, croissant, ecs,
  // ocsf and x-splunk-export. Applying the rule to them would refuse to emit the
  // components Phase 1 already publishes.
  //
  // §4 states the allowlist as part of the parity projection P, and the hard-fail exists
  // so P's format-stripping cannot hide a divergence in something this generator added —
  // a format the bundles carry is stripped from both sides equally and is no parity risk.
  // Its sibling rule below is explicitly scoped to non-document schemas; this reads the
  // same way, which is also the only reading that can emit a document at all.
  for (const [name, schema] of Object.entries(schemas)) {
    if (documentSchemas.has(name)) continue;
    for (const { format, where } of formatsIn(schema, '')) {
      if (ALLOWED_FORMATS.has(format)) continue;
      if (format === 'binary' && name === 'Binary') continue;
      throw new Error(`${name}${where}: format ${format} is outside the allowlist`);
    }
  }

  // A non-document schema that does not close itself. Document schemas are generated from
  // the bundles and carry their own strictness; everything else must say so.
  for (const [name, schema] of Object.entries(schemas)) {
    if (documentSchemas.has(name)) continue;
    if (name === 'Problem' && STRICTNESS_EXEMPT[name]) continue;
    const s = schema as Record<string, unknown>;
    const closed = s.additionalProperties === false;
    const isUnion = Array.isArray(s.oneOf) || Array.isArray(s.anyOf) || Array.isArray(s.allOf);
    if (!closed && !isUnion) {
      throw new Error(`${name}: a non-document schema must set additionalProperties: false`);
    }
  }

  return {
    openapi: '3.1.1',
    info: {
      title: 'HDF Reference API',
      version: '1.0.0',
      license: { name: 'Apache-2.0', identifier: 'Apache-2.0' },
      'x-hdf-schema-version': componentsDoc.info.version,
      'x-hdf-mcp-golden-sha': createHash('sha256').update(contractRaw).digest('hex'),
    } as unknown as Record<string, string>,
    paths,
    components: {
      schemas,
      responses: sharedResponses(),
      // ADR-0008 §3: one http/bearer scheme, with the closed scope vocabulary advertised
      // as x-hdf-scopes. No oauth2 scheme, because its URLs vary per deployment; clients
      // discover the authorization server through RFC 9728 instead.
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description:
            'Bearer token. The deployment advertises its authorization server through ' +
            'RFC 9728 protected-resource metadata at /.well-known/oauth-protected-resource.',
          'x-hdf-scopes': ['hdf:read', 'hdf:write', 'hdf:admin'],
        },
      },
    },
  };
}

export function main(): void {
  const doc = generateApiDocument();
  mkdirSync(DIST, { recursive: true });
  writeFileSync(join(DIST, 'hdf-api.oas.json'), `${JSON.stringify(doc, null, 2)}\n`);
  process.stdout.write(
    `hdf-api.oas.json: ${Object.keys(doc.paths).length} paths at schema v${doc.info['x-hdf-schema-version']}\n`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
