// Generate the reference API document from the MCP contract, the binding table and the
// conventions components.
//
// Nothing here authors an API. Every path, method and placement comes from
// src/bindings.yaml; every shape is a generated component, a reflected shape from the
// contract golden, or a conventions component referenced by name. The rules this applies
// — the fixed rewrite map, the problem-type table, the response conventions — are
// ADR-0008 §2/§3 and ADR-0010 §6, consumed rather than reinterpreted.

import { createHash } from 'crypto';
import { readFileSync, mkdirSync } from 'fs';
import { writeArtifact } from './write-artifact.js';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { FILESYSTEM_FIELDS, loadBindings, type BindingTable, type ToolBinding } from './bindings.js';
import { DIALECT } from './components.js';
import { loadConventions } from './conventions.js';
import { loadProblemDocs } from './problems.js';

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

/**
 * The 422 problem. ADR-0008 §3 requires `SCHEMA_INVALID` to carry `errors[]` of
 * `{path, line, message}`, which is an RFC 9457 extension member — so this is Problem plus
 * that array, not a different shape.
 */
const VALIDATION_PROBLEM_SCHEMA = {
  allOf: [{ $ref: '#/components/schemas/Problem' }],
  type: 'object',
  additionalProperties: true,
  properties: {
    errors: {
      type: 'array',
      description: 'Where the document failed, one entry per violation.',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['path', 'message'],
        properties: {
          path: { type: 'string', description: 'JSON Pointer to the offending member.' },
          line: { type: 'integer', description: 'Line in the submitted bytes, when known.' },
          message: { type: 'string' },
        },
      },
    },
  },
};

/** Paged operations that publish no example, each with the reason no capture is stable. */
export const ENVELOPE_EXAMPLE_EXEMPT: Record<string, string> = {
  hdf_convert:
    'the reply carries sha256 of the converted document and the converter stamps time.Now(), so no capture is byte-stable',
  hdf_aggregate:
    'the binding names no fullResponse, so the operation emits no envelope for an example to live in',
};

/** Schemas exempt from the additionalProperties:false rule, each with its reason. */
export const STRICTNESS_EXEMPT: Record<string, string> = {
  Problem: 'RFC 9457 admits extension members, and §3 uses one (`scope` on the 403)',
  ValidationProblem: 'Problem plus §3\'s errors[]; it inherits RFC 9457\'s openness',
};

function problemRef(fallback: string, status: number, type: string): Record<string, unknown> {
  const title = titleFor(type, fallback);
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
    // Two types share this status, and RFC 9457 discriminates on `type`, so both are
    // declared. no-active-organization is named by §3 and appeared in no operation, which
    // left a generated client to fold a tenancy failure into insufficient-scope — whose
    // published remedy is "obtain a token with the scope named in the response".
    Forbidden: {
      ...problemResponseForRefs(403, [
        { type: 'insufficient-scope', title: 'insufficient-scope' },
        { type: 'no-active-organization', title: 'no-active-organization' },
      ]),
      headers: {
        'WWW-Authenticate': {
          schema: { type: 'string' },
          example: 'Bearer error="insufficient_scope", scope="hdf:write", resource_metadata="https://hdf.example.org/.well-known/oauth-protected-resource"',
        },
        ...rateLimitHeaders(),
      },
    },
    TooManyRequests: {
      ...problemRef('Quota exceeded', 429, 'quota-exceeded'),
      headers: retryAfterHeaders(),
    },
    InternalError: { ...problemRef('Internal error', 500, 'internal-error'), headers: rateLimitHeaders() },
    StoreUnavailable: {
      ...problemRef('Store unavailable', 503, 'store-unavailable'),
      headers: retryAfterHeaders(),
    },
    UnsupportedMediaType: {
      ...problemRef('Unsupported media type', 415, 'unsupported-media-type'),
      headers: rateLimitHeaders(),
    },
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
  'notice',
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
  'query.full/properties/tags':
    'the HDF schema declares tags additionalProperties:true for tool-specific metadata',
  'diff.temporal.full/properties/fieldChanges':
    'oldValue/newValue reflect to a bare true, because a field change can be on any requirement field',
  'diff.system-drift.full/properties/fieldChanges':
    'same, for any component field',
  'POST /documents/authored requestBody/properties/content/items':
    'an authored item is a slice of any of the eight document schemas, chosen by docType; the MCP declares it open and the server validates it',
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

/**
 * ADR-0008 §2's fixed rewrite map, input half. A document reference arrives from the MCP as
 * `{handle, path}` and on HTTP is `{id}`: `handle` is renamed, `path` is dropped.
 *
 * The output half above cannot stand in for this. It strips `handle`, because no response
 * carries one — so applying it to a request body deletes the HTTP half and keeps the
 * filesystem half, which is the rule inverted.
 *
 * A nullable input also collapses to its concrete type: the MCP marks an optional field
 * `["null", T]`, and on HTTP absence is expressed by omitting the field.
 */
export function rewriteInputShape(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(rewriteInputShape);
  if (node === null || typeof node !== 'object') return node;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === 'properties' && value !== null && typeof value === 'object') {
      const kept: Record<string, unknown> = {};
      for (const [prop, schema] of Object.entries(value)) {
        if (FILESYSTEM_FIELDS.has(prop)) continue;
        // A pure rename. `handle` is an opaque server string and so is `id`; giving it a
        // format here would invent a constraint the path parameter does not carry either.
        kept[prop === 'handle' ? 'id' : prop] = rewriteInputShape(schema);
      }
      out[key] = kept;
      continue;
    }
    if (key === 'required' && Array.isArray(value)) {
      out[key] = value
        .filter((r) => typeof r !== 'string' || !FILESYSTEM_FIELDS.has(r))
        .map((r) => (r === 'handle' ? 'id' : r));
      continue;
    }
    if (key === 'type' && Array.isArray(value)) {
      const concrete = value.filter((t) => t !== 'null');
      out[key] = concrete.length === 1 ? concrete[0] : concrete;
      continue;
    }
    if (key === 'description' && typeof value === 'string') {
      out[key] = value
        .replace(/\{path\}|\{handle\}/g, '{id}')
        .replace(/\{id\}(?: or \{id\})+/g, '{id}');
      continue;
    }
    out[key] = rewriteInputShape(value);
  }
  return out;
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
 * Nested subschemas that are open — `additionalProperties: true`, or a bare `true` where a
 * schema should be — with the path they sit at.
 *
 * The top-level strictness rule does not see these: a shape can close itself and still
 * carry an open object three levels down, which is where a reflected `map[string]any` or
 * an `any` leaf ends up. Without this walk OPEN_LEAF_EXEMPT was a documented rule that
 * nothing enforced.
 *
 * It descends through schema positions only. Walking every key instead would read
 * `required: true` on an OpenAPI parameter, or a property whose name happens to be
 * `default`, as a schema — which is why this can be pointed at request bodies as well as
 * at components.
 */
function openLeaves(node: unknown, where: string): string[] {
  if (node === true) return [where];
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return [];
  const schema = node as Record<string, unknown>;
  const found: string[] = [];
  if (schema.additionalProperties === true) found.push(where);
  for (const [key, value] of Object.entries(schema)) {
    if (key === 'additionalProperties' && value === true) continue;
    if (SCHEMA_VALUED.has(key)) {
      const at = `${where}/${key}`;
      if (Array.isArray(value)) value.forEach((s, i) => found.push(...openLeaves(s, `${at}/${i}`)));
      else found.push(...openLeaves(value, at));
    } else if (SCHEMA_MAPS.has(key) && value !== null && typeof value === 'object') {
      for (const [member, sub] of Object.entries(value)) {
        found.push(...openLeaves(sub, `${where}/${key}/${member}`));
      }
    } else if (SCHEMA_LISTS.has(key) && Array.isArray(value)) {
      value.forEach((sub, i) => found.push(...openLeaves(sub, `${where}/${key}/${i}`)));
    }
  }
  return found;
}

/** Every member of a `properties` map under `node`, with where it sits. */
function propertyNamesIn(node: unknown, where: string): { name: string; where: string }[] {
  if (Array.isArray(node)) return node.flatMap((v, i) => propertyNamesIn(v, `${where}/${i}`));
  if (node === null || typeof node !== 'object') return [];
  const found: { name: string; where: string }[] = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === 'properties' && value !== null && typeof value === 'object') {
      for (const name of Object.keys(value)) found.push({ name, where: `${where}/properties/${name}` });
    }
    found.push(...propertyNamesIn(value, `${where}/${key}`));
  }
  return found;
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
  tags?: string[];
  summary?: string;
  parameters?: unknown[];
  requestBody?: unknown;
  responses: Record<string, unknown>;
  security?: Record<string, string[]>[];
}

/** Scopes for a class. Read-only tools never acquire a write scope. */
/**
 * The classes §3 defines. Closed rather than defaulting: `read` was the fallback for
 * anything unrecognised, so a mistyped class emitted a read-only scope on a write — and
 * suppressed If-Match with it, since `writes` derives from this same answer.
 */
const CLASSES = new Set(['read', 'write', 'admin', 'documentOnly']);

export function scopesFor(cls: string): string[] {
  if (!CLASSES.has(cls)) {
    throw new Error(`class ${cls} is not one of ${[...CLASSES].sort().join(', ')}`);
  }
  // §3 makes them cumulative: a write requires hdf:write AS WELL AS hdf:read.
  if (cls === 'admin') return ['hdf:read', 'hdf:write', 'hdf:admin'];
  if (cls === 'write') return ['hdf:read', 'hdf:write'];
  if (cls === 'documentOnly') return [];
  return ['hdf:read'];
}

/**
 * The problem response for one status, naming every taxonomy code that maps to it.
 *
 * Several codes share a status — §3 sends SCHEMA_INVALID, WRONG_DOC_TYPE, NO_CONVERTER and
 * AMBIGUOUS_FORMAT all to 422 — and RFC 9457 discriminates on `type`, not on the status.
 * So the response carries one named example per code a client can actually meet, which is
 * also what stops a 422 reading as if only one thing could have gone wrong.
 */
interface ProblemRef {
  /** The kebab-case type name, which is what RFC 9457 discriminates on. */
  type: string;
  title: string;
}

function problemResponseForRefs(status: number, refs: ProblemRef[]): Record<string, unknown> {
  const schema =
    status === 422
      ? { $ref: '#/components/schemas/ValidationProblem' }
      : { $ref: '#/components/schemas/Problem' };
  const examples: Record<string, unknown> = {};
  for (const ref of refs) {
    const value: Record<string, unknown> = {
      type: `${PROBLEM_BASE}/${ref.type}`,
      title: titleFor(ref.type, ref.title),
      status,
    };
    // §3 gives SCHEMA_INVALID an `errors[]`, so the example a client copies shows one.
    // Without it the member exists in the schema and in no example.
    if (ref.type === 'schema-invalid') {
      value.errors = [
        { path: '/baselines/0/requirements/3/impact', line: 142, message: 'must be <= 1' },
      ];
    }
    examples[ref.type] = { summary: ref.title, value };
  }
  return {
    description: refs.map((r) => r.title).join(' | '),
    headers: rateLimitHeaders(),
    content: { 'application/problem+json': { schema, examples } },
  };
}

function problemResponseFor(status: number, codes: string[]): Record<string, unknown> {
  return problemResponseForRefs(
    status,
    codes.map((code) => ({ type: PROBLEM_TYPES[code]!.type, title: code })),
  );
}

/**
 * RFC 9457 §3.1.2 wants `title` to be a short human-readable summary that does not change
 * from occurrence to occurrence. The derived path used the mcperr code, which is neither
 * readable nor localizable and which `type` already carries, so the document shipped
 * DOCUMENT_NOT_FOUND beside hand-authored prose for the conventional responses.
 */
let problemTitles: Record<string, string> | undefined;

function titleFor(type: string, fallback: string): string {
  // Read on first use, not at module load: the table is a build input that does not ship
  // in dist, and importing this module must not depend on it being there.
  problemTitles ??= Object.fromEntries(
    Object.entries(loadProblemDocs()).map(([name, entry]) => [name, entry.title]),
  );
  return problemTitles[type] ?? fallback;
}

/** Type name -> the mcperr code that owns it, for resolving a declared problem type. */
const CODE_BY_TYPE = new Map(Object.entries(PROBLEM_TYPES).map(([code, m]) => [m.type, code]));

/**
 * Resolves one name from a `problems` declaration. A name the taxonomy owns must agree with
 * it on the status; anything else is a service-owned condition the MCP cannot raise, whose
 * title is the screaming-snake form of its type.
 */
function declaredProblemRef(status: number, type: string): ProblemRef {
  const code = CODE_BY_TYPE.get(type);
  if (code === undefined) {
    return { type, title: type.toUpperCase().replace(/-/g, '_') };
  }
  const mapped = PROBLEM_TYPES[code]!.status;
  if (mapped !== status) {
    throw new Error(
      `declared problem type ${type} is ${status} in the binding table and ${mapped} in ADR-0010 §6`,
    );
  }
  return { type, title: code };
}

function problemResponse(code: string): Record<string, unknown> {
  const { type } = PROBLEM_TYPES[code]!;
  return {
    description: code,
    headers: rateLimitHeaders(),
    content: {
      'application/problem+json': {
        schema: { $ref: '#/components/schemas/Problem' },
        example: {
          type: `${PROBLEM_BASE}/${type}`,
          title: titleFor(type, code),
          status: PROBLEM_TYPES[code]!.status,
        },
      },
    },
  };
}

/**
 * Responses every operation carries. ADR-0008 §3 requires a declared 500 and the RateLimit
 * headers everywhere, and 413/415 wherever a request body exists — so they are added here
 * rather than per operation, which is what stops one being forgotten.
 */
/**
 * The IETF RateLimit header fields (draft-ietf-httpapi-ratelimit-headers), adopted by
 * ADR-0008 §3's standards pass. Declared on the success response of every operation, not
 * only on the 429: a client should learn its budget from a call that worked, rather than
 * having to provoke a rejection to find out.
 */
/**
 * ADR-0008 §3's conventions as actual shared components. They were inlined on every
 * response, which is why one wrong example appeared nineteen times.
 */
function sharedHeaders(): Record<string, unknown> {
  return {
    ETag: {
      description:
        'Strong entity-tag for the document, the `sha256` of its stored bytes. Condition a ' +
        'write on it with `If-Match` (RFC 9110 §8.8.3, §13.1.1).',
      required: true,
      schema: { type: 'string' },
      example: '"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"',
    },
    RateLimit: {
      description: 'Remaining quota for the active window, as a structured field.',
      schema: { type: 'string' },
      // draft-ietf-httpapi-ratelimit-headers-11 §4: a dictionary keyed by policy name with
      // `r` remaining and `t` seconds to reset. The `limit=/remaining=/reset=` form this
      // carried was draft-07 and was removed in -08.
      example: '"default";r=87;t=12',
    },
    'RateLimit-Policy': {
      description: 'The quota policy this endpoint applies.',
      schema: { type: 'string' },
      example: '"default";q=100;w=60',
    },
    'Retry-After': {
      description: 'Delay before retrying, in seconds or as an HTTP-date (RFC 9110 §10.2.3).',
      schema: { oneOf: [{ type: 'integer', minimum: 0 }, { type: 'string' }] },
      example: 42,
    },
  };
}

/** The one request parameter every conditional write shares. */
function sharedParameters(): Record<string, unknown> {
  return {
    IfMatch: {
      name: 'If-Match',
      in: 'header',
      required: true,
      description:
        'The document ETag the write is conditioned on, taken from the `ETag` of a prior ' +
        'response. A mismatch is 412 (RFC 9110 §13.1.1).',
      schema: { type: 'string' },
    },
  };
}

const headerRef = (name: string): Record<string, unknown> => ({
  $ref: `#/components/headers/${name}`,
});

function rateLimitHeaders(): Record<string, unknown> {
  return { RateLimit: headerRef('RateLimit'), 'RateLimit-Policy': headerRef('RateLimit-Policy') };
}

function retryAfterHeaders(): Record<string, unknown> {
  return { ...rateLimitHeaders(), 'Retry-After': headerRef('Retry-After') };
}

function conventionalResponses(hasBody: boolean): Record<string, unknown> {
  const responses: Record<string, unknown> = {
    '401': { $ref: '#/components/responses/Unauthorized' },
    '403': { $ref: '#/components/responses/Forbidden' },
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

/**
 * The page-size ceiling. ADR-0008 §3 requires `limit` to carry an OpenAPI `maximum` and
 * says an over-limit value is coerced down with the effective limit echoed (AIP-158), but
 * it names no number — so this is a tracked choice, not a quotation.
 *
 * 1000 is a conventional ceiling, chosen here and nowhere else. The MCP sets none — its
 * own `limit` is unbounded, with 0 meaning all — so nothing upstream is being quoted.
 * Raise it here and the generated document changes in one place.
 */
/**
 * The reference API's own semver. ADR-0008 §6 gives this document a version independent of
 * the schema release train, and §4 says what moves it. It is a reviewed value, not a
 * derived one — a digest can tell you the contract changed, never whether the change was
 * breaking — so the test baseline refuses a changed digest under an unchanged version.
 */
export const API_VERSION = '2.0.0';

/** The contract's identity: everything but `info`, which carries this value. */
export function contractDigest(document: ApiDocument): string {
  const rest = Object.fromEntries(
    Object.entries(document).filter(([key]) => key !== 'info'),
  );
  return createHash('sha256').update(stableStringify(rest)).digest('hex');
}

/** Key-sorted JSON, so a reordering in the generator is not a contract change. */
function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, inner: unknown) => {
    if (inner !== null && typeof inner === 'object' && !Array.isArray(inner)) {
      return Object.fromEntries(
        Object.entries(inner as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
      );
    }
    return inner;
  });
}

export const MAX_PAGE_SIZE = 1000;

/**
 * Operations whose success body this document cannot describe, each with the reason.
 *
 * Recorded here rather than left to a comment in the binding table, because every other
 * deliberate omission in this generator carries a typed entry, a reason and a reachability
 * test — and this one is the largest. An operation that emits no response schema and is
 * absent from this map fails the build.
 */
export const RESPONSE_SHAPE_EXEMPT: Record<string, string> = {
  hdf_compliance:
    'the MCP registers engine.statusCounts and engine.thresholdConfig, which are parts of the reply rather than the reply',
  hdf_aggregate:
    'the MCP registers no whole-response shape for the cross-document aggregate',
  hdf_inspect: 'the MCP registers no whole-response shape for the structure walk',
  hdf_validate: 'the MCP registers no whole-response shape for a validation report',
  hdf_author: 'the MCP registers no whole-response shape for an authored document',
  hdf_apply_amendment: 'the MCP registers no whole-response shape for an amended document',
  'hdf-converter-catalog': 'a resource binding names a method and a path only, so the grammar cannot carry a shape',
  'hdf-enum': 'a resource binding names a method and a path only, so the grammar cannot carry a shape',
  'hdf-schema-whole': 'a resource binding names a method and a path only, so the grammar cannot carry a shape',
  'hdf-schema-slice': 'a resource binding names a method and a path only, so the grammar cannot carry a shape',
};

/**
 * One query or path parameter, with the fixed rewrite map applied.
 *
 * `page` becomes the opaque cursor `next`; a document reference placed in the path becomes
 * `{id}`, because HTTP addresses documents by id and the parameter is named for the path
 * template rather than the MCP field behind it; and `limit` becomes a bounded integer.
 *
 * `enumFrom: schema enum` copies the vocabulary from the MCP's own input schema, which is
 * where prerequisite (a) put it — so the advertised values are the accepted values, with
 * no second list to drift. `enumFrom: registry` carries no inline enum because there is
 * none to copy: prerequisite (a) left `hdf_convert.from` a bare string, so the
 * converter-catalog resource is the only vocabulary this document can point at.
 */
/**
 * A query parameter carries scalars, so a document reference the rewrite map has reduced to
 * a lone `id` becomes that id. `?sources=<id>&sources=<id>` is the serialisable form; an
 * array of one-member objects is not.
 */
function inQueryPosition(shape: Record<string, unknown>): Record<string, unknown> {
  const properties = shape.properties as Record<string, unknown> | undefined;
  if (properties !== undefined && Object.keys(properties).length === 1 && properties.id !== undefined) {
    const id = properties.id as Record<string, unknown>;
    return { ...id, ...(shape.description !== undefined ? { description: shape.description } : {}) };
  }
  const items = shape.items as Record<string, unknown> | undefined;
  if (items !== undefined && !Array.isArray(items)) {
    return { ...shape, items: inQueryPosition(items) };
  }
  return shape;
}

/**
 * Identifiers a generated client cannot use as a method name. A document whose operationId
 * is a keyword forces every generator to mangle it, and they mangle differently — which is
 * the instability a stable operationId exists to prevent.
 */
const RESERVED_IDENTIFIERS = new Set([
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default', 'delete',
  'do', 'else', 'enum', 'export', 'extends', 'false', 'finally', 'for', 'function', 'if',
  'import', 'in', 'instanceof', 'new', 'null', 'return', 'super', 'switch', 'this', 'throw',
  'true', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield', 'let', 'static',
  'implements', 'interface', 'package', 'private', 'protected', 'public', 'await',
]);

/**
 * The operationId, camelCased from the binding's own name so the mapping stays mechanical.
 * The three sources spelled it three ways — snake_case tool names, camelCase synthetics and
 * kebab-case resources — and one was `delete`.
 */
function operationIdFor(name: string): string {
  const parts = name.split(/[-_]/).filter((part) => part !== '');
  const id = parts
    .map((part, i) => (i === 0 ? part : `${part[0]!.toUpperCase()}${part.slice(1)}`))
    .join('');
  if (!/^[a-z][A-Za-z0-9]*$/.test(id)) {
    throw new Error(`${name}: operationId ${id} is not a usable identifier`);
  }
  if (RESERVED_IDENTIFIERS.has(id)) {
    throw new Error(`${name}: operationId ${id} is a reserved word; name the binding something else`);
  }
  return id;
}

function parameterFor(
  field: string,
  placement: string,
  spec: { enumFrom?: string } = {},
  declared: Record<string, unknown> = {},
): Record<string, unknown> {
  const name = placement === 'path' ? 'id' : field === 'page' ? 'next' : field;

  // The declared shape, carried through the rewrite map's input half, rather than a bare
  // string: `sources` is an array of document references upstream and was emitted as
  // `string` on the parameter naming WHICH DOCUMENTS ARE READ, and the descriptions that
  // held the only grammar these filters have — `>=7`, `valid | none-valid` — were dropped.
  // rewriteInputShape is declared over `unknown` because it walks arbitrary schema nodes;
  // a parameter's declared schema is always an object, and an empty one falls through to
  // the string default below.
  const rewritten = rewriteInputShape(declared);
  let schema: Record<string, unknown> = inQueryPosition(
    rewritten !== null && typeof rewritten === 'object' && !Array.isArray(rewritten)
      ? { ...(rewritten as Record<string, unknown>) }
      : {},
  );
  let description = typeof schema.description === 'string' ? schema.description : undefined;
  delete schema.description;
  if (Object.keys(schema).length === 0) schema = { type: 'string' };
  if (field === 'page') {
    schema = { type: 'string' };
    description = 'Opaque cursor from a previous response. Omit it to read the first page.';
  } else if (field === 'limit') {
    schema = { type: 'integer', minimum: 1, maximum: MAX_PAGE_SIZE };
    description = `Page size. An over-limit value is coerced down to ${MAX_PAGE_SIZE} and the effective limit echoed in the response.`;
  } else if (spec.enumFrom === 'schema enum') {
    // The enum may sit on the property or, for a repeated filter, on its items.
    const items = declared.items as Record<string, unknown> | undefined;
    const values = (declared.enum ?? items?.enum) as unknown[] | undefined;
    if (Array.isArray(values) && values.length > 0) {
      schema = Array.isArray(declared.type) || declared.type === 'array'
        ? { type: 'array', items: { type: 'string', enum: values } }
        : { type: 'string', enum: values };
    }
  }

  return {
    name,
    in: placement === 'path' ? 'path' : 'query',
    required: placement === 'path',
    ...(description ? { description } : {}),
    // Stated rather than defaulted, so a generated client serialises a repeated filter the
    // way the service reads it.
    ...(schema.type === 'array' ? { style: 'form', explode: true } : {}),
    schema,
  };
}

/** First sentence of the MCP's own description: generated, not authored. */
/**
 * Rewrites a tool name mentioned in prose into the operation that binds it.
 *
 * The MCP's descriptions cross-reference each other — "for other document types call
 * hdf_inspect" — which is useful to an agent and meaningless to an HTTP client, who has no
 * hdf_inspect. §2's rewrite map keeps that vocabulary off this surface; it applies to prose
 * for the same reason it applies to member names. A mention of a tool nothing binds is a
 * refusal rather than a silent leak.
 */
function rewriteToolMentions(text: string, operations: Map<string, string>): string {
  return text.replace(/\bhdf_[a-z_]+\b/g, (tool) => {
    const operation = operations.get(tool);
    if (operation === undefined) {
      throw new Error(`a description names ${tool}, which no operation binds`);
    }
    return operation;
  });
}

/** What each tag groups, for a rendered document and for a generated client's class name. */
const TAG_DESCRIPTIONS: Record<string, string> = {
  documents: 'Stored HDF documents: ingest, read, amend and delete.',
  requirements: 'Requirement-level reads across one document or many.',
  comparisons: 'Differential analysis between two documents.',
  conversions: 'Conversion of third-party tool output into HDF.',
  validations: 'Schema validation of a submitted document.',
  catalog: 'What this deployment supports.',
  enums: 'The closed vocabularies the schemas declare.',
  schemas: 'The HDF JSON Schema documents themselves.',
  auth: 'Token issuance, served by the authorization server rather than a service route.',
};

/**
 * The resource an operation belongs to, from the first non-templated path segment. Tags
 * group operations in a rendered document and are what most generators name a client class
 * after, so every operation carries exactly one and nothing hand-maintains the list.
 */
function tagFor(path: string): string {
  const segments = path.split('/').filter((part) => part !== '' && !part.startsWith('{'));
  // The auth routes live under /api/auth/... and belong together, not under "api".
  if (segments[0] === 'api' && segments[1] === 'auth') return 'auth';
  return segments[0] ?? 'default';
}

const prose = (text: string | undefined, operations: Map<string, string>): string | undefined =>
  text === undefined ? undefined : rewriteToolMentions(text, operations);

function summarize(description: string | undefined, fallback: string): string {
  if (!description) return fallback;
  const first = description.split(/(?<=\.)\s|\n/)[0]!.trim();
  return first.length > 0 ? first : fallback;
}

/**
 * Where each envelope member's example value comes from in the raw MCP reply.
 *
 * `next` is absent: the cursor's opaque format is ADR-0011's to define.
 */
const EXAMPLE_SOURCE: Record<string, string> = {
  total: 'total',
  limit: 'returned',
  summary: 'summary',
};

/** The envelope example, built from the members the envelope declares. */
function envelopeExample(
  properties: Record<string, unknown>,
  items: string,
  capture: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (capture[items] === undefined) return undefined;
  const example: Record<string, unknown> = { [items]: capture[items] };
  for (const member of Object.keys(properties)) {
    const from = EXAMPLE_SOURCE[member];
    if (from === undefined) continue;
    if (capture[from] !== undefined) example[member] = capture[from];
  }
  return example;
}

function okResponse(binding: ToolBinding, capture?: Record<string, unknown>): Record<string, unknown> {
  const named = [binding.fullResponse ?? []].flat();
  if (named.length === 0) {
    // An absent `content` ASSERTS an empty body (OpenAPI 3.1.1 §4.8.17) — the format has
    // no third "shape not described yet" state. A media type with no schema makes the
    // weaker claim that is true, and a consumer generates `unknown` rather than `void`.
    return {
      description: 'Success. The body is JSON whose shape this document does not yet describe.',
      content: { 'application/json': {} },
    };
  }
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
  if (items === undefined) {
    return { description: 'Success', content: { 'application/json': { schema } } };
  }

  // The envelope: the named row shape under `items`, with the cursor the rewrite map
  // substitutes for the MCP's page index.
  //
  // `next` and `limit` appear only where the tool actually exposes the input behind them.
  // Emitting them unconditionally advertised paging that does not exist: hdf_convert has
  // neither a page index nor a limit and was given both, so the document promised a cursor
  // no operation accepts; hdf_diff pages but takes no limit, so it advertised a page size
  // that cannot be asked for. Only hdf_query exposes a limit upstream.
  const fields = binding.fields ?? {};
  const pages = fields.page !== undefined;
  const bounded = fields.limit !== undefined;
  const envelope = {
    type: 'object',
    additionalProperties: false,
    required: [items],
    properties: {
      [items]: { type: 'array', items: schema },
      ...(pages ? { next: { type: 'string', description: 'Cursor for the following page.' } } : {}),
      total: { type: 'integer' },
      // AIP-158: the server echoes the limit it actually applied, which may be
      // lower than the one asked for.
      ...(bounded ? { limit: { type: 'integer', minimum: 1, maximum: MAX_PAGE_SIZE } } : {}),
      // A comparison-level rollup, where the tool returns one. It is envelope
      // data rather than a row, and the envelope closes itself, so without a
      // declared member the response could not carry it at all. Three of its ten
      // members — `unchanged`, `total` and `matchedCount` — cannot be recovered
      // from the rows either, because all three count unchanged entries and those
      // never enter the array. Distinct from the envelope's `total`: that counts
      // the pageable rows, while the summary's own counts every entry the diff
      // compared — requirement diffs in temporal mode, component diffs in
      // system-drift, since /comparisons serves both.
      ...(binding.summaryRef !== undefined
        ? { summary: { $ref: `#/components/schemas/${binding.summaryRef}` } }
        : {}),
    },
  };

  const example = capture === undefined
    ? undefined
    : envelopeExample(envelope.properties as Record<string, unknown>, items, capture);
  return {
    description: 'Success',
    content: { 'application/json': { schema: envelope, ...(example ? { example } : {}) } },
  };
}

/**
 * The request body.
 *
 * A `bodyRef` names a component and the body IS that component: ADR-0008 §2 says a
 * synthetic operation's body is "bodyRef-only or a fixed conventions component, never an
 * inline schema". A tool's body instead carries the fields the table placed there, typed
 * from the MCP's own input schema — derived from the table and the contract, not authored.
 *
 * The media type comes from the component when it declares one. RFC 6749 §4.4 requires the
 * token grant to be form-encoded, so that operation cannot be JSON; a conventions
 * component states it with `x-hdf-media-type` rather than the generator guessing from a
 * name.
 */
function requestBodyFor(
  binding: ToolBinding,
  bodyFields: [string, { placement?: string }][],
  schemas: Record<string, unknown>,
  inputProperties: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (binding.bodyRef !== undefined) {
    const component = schemas[binding.bodyRef] as Record<string, unknown> | undefined;
    const mediaType =
      (component?.['x-hdf-media-type'] as string | undefined) ?? 'application/json';
    return {
      required: true,
      content: { [mediaType]: { schema: { $ref: `#/components/schemas/${binding.bodyRef}` } } },
    };
  }
  if (bodyFields.length === 0) return undefined;
  const properties: Record<string, unknown> = {};
  for (const [field] of bodyFields) {
    const declared = inputProperties[field];
    properties[field] = rewriteInputShape(declared ?? { type: 'string' });
  }
  return {
    required: true,
    content: {
      'application/json': {
        schema: { type: 'object', additionalProperties: false, properties },
      },
    },
  };
}

function operationFor(
  name: string,
  binding: ToolBinding,
  cls: string,
  summary: string,
  description: string | undefined,
  schemas: Record<string, unknown>,
  inputProperties: Record<string, unknown>,
  raisableCodes: string[],
  capture?: Record<string, unknown>,
): Operation {
  // §3 gives a write-class operation hdf:write as well as hdf:read, so the scope set is
  // also what says whether this is a write — read from the one place that decides it.
  const writes = scopesFor(cls).some((scope) => scope === 'hdf:write' || scope === 'hdf:admin');
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
      .map(([field, f]) =>
        parameterFor(field, f.placement!, f, (inputProperties[field] ?? {}) as Record<string, unknown>),
      ),
  ];
  const bodyFields = fields.filter(([, f]) => f.placement === 'body');
  const hasBody = bodyFields.length > 0 || binding.bodyRef !== undefined;

  // A declared success status replaces the default 200, and 204 carries no body at all:
  // a 200 on a delete would promise a response document that does not exist.
  const success = binding.success ?? 200;
  const successResponse =
    success === 204
      ? { description: 'No content', headers: rateLimitHeaders() }
      : { ...okResponse(binding, capture), headers: rateLimitHeaders() };
  const responses: Record<string, unknown> = {
    [String(success)]: successResponse,
    ...conventionalResponses(hasBody),
  };

  // The problem responses come from what this tool can actually raise, recorded per tool in
  // the contract golden. §3 gives the code -> status mapping and never says which operation
  // declares which, so the alternative was a structural guess: keying 404 on `{id}` in the
  // path missed the five operations that name a document somewhere else — in the body for
  // /validations, /conversions and /documents/authored, and in a query parameter for
  // /requirements and /comparisons — and keying 422 on "has a document body" would have put
  // one on /validations, where an invalid document is a successful validation rather than
  // an error.
  const byStatus = new Map<number, ProblemRef[]>();
  for (const code of raisableCodes) {
    const mapped = PROBLEM_TYPES[code];
    if (mapped === undefined) continue;
    // 413 is a REQUEST-size status (RFC 9110 §15.5.14) and conventionalResponses already
    // puts it on every operation carrying a body. TOO_LARGE covers both an oversized inline
    // body and a stored document too large to load, so deriving it per tool put a 413 on
    // six GETs that carry no request body at all, where the status cannot apply.
    if (mapped.status === 413) continue;
    // §2 scopes If-Match, and therefore 412, to write operations addressing a document. The
    // MCP can raise HANDLE_STALE on a read, but a read carries no If-Match, so a 412 there
    // would describe a response that cannot occur.
    if (mapped.status === 412 && !(writes && binding.path?.includes('{id}'))) continue;
    byStatus.set(mapped.status, [
      ...(byStatus.get(mapped.status) ?? []),
      { type: mapped.type, title: code },
    ]);
  }
  // §2's grammar declares the statuses a synthetic operation has, since nothing derives
  // them. Unioned with the derivation rather than replacing it.
  for (const [status, types] of Object.entries(binding.problems ?? {})) {
    const code = Number(status);
    byStatus.set(code, [
      ...(byStatus.get(code) ?? []),
      ...types.map((type) => declaredProblemRef(code, type)),
    ]);
  }
  for (const [status, refs] of byStatus) {
    responses[String(status)] = problemResponseForRefs(
      status,
      [...refs].sort((a, b) => a.type.localeCompare(b.type)),
    );
  }
  // A floor the derivation does not replace: an operation addressing a document by id can
  // always fail to find it, and a SYNTHETIC operation has no MCP tool and therefore no
  // derived code set — so replacing this rule rather than unioning with it silently took
  // the 404 off DELETE /documents/{id}.
  if (binding.path?.includes('{id}') && responses['404'] === undefined) {
    responses['404'] = problemResponseFor(404, ['DOCUMENT_NOT_FOUND']);
  }
  if (byStatus.has(412)) {
    parameters.push({ $ref: '#/components/parameters/IfMatch' });
  }
  // §3 ties the validator to the document's sha256, so an operation that returns or changes
  // one document issues it. Declared in §2's grammar rather than derived: nothing in the MCP
  // has a validator concept, and a 204 has no representation to tag.
  if (binding.etag === true) {
    if (success === 204) throw new Error(`${name}: declares etag with a 204, which tags nothing`);
    (successResponse as { headers: Record<string, unknown> }).headers = {
      ETag: headerRef('ETag'),
      ...rateLimitHeaders(),
    };
  }

  return {
    operationId: operationIdFor(name),
    tags: [tagFor(binding.path ?? '')],
    summary,
    // Both, always. `summary` is the first sentence and `description` the whole of it; for
    // a one-sentence operation they coincide, and omitting the longer field to avoid the
    // duplication left five operations with no description at all.
    ...(description !== undefined ? { description } : {}),
    parameters: parameters.length > 0 ? parameters : undefined,
    requestBody: requestBodyFor(binding, bodyFields, schemas, inputProperties),
    responses,
    // §2 hand-sets scopes on a synthetic operation, so the hand-set value is what travels.
    // It was computed from `class` and the declaration was never read, so the file looked
    // authoritative while an operator narrowing it would have seen no change. bindingFaults
    // holds it to scopesFor(class), so it is used and checked rather than one or neither.
    security: cls === 'documentOnly' ? [] : [{ bearerAuth: binding.scopes ?? scopesFor(cls) }],
  };
}

export interface ApiDocument {
  openapi: string;
  tags?: { name: string; description: string }[];
  jsonSchemaDialect?: string;
  servers?: { url: string; variables?: Record<string, { default: string; description?: string }> }[];
  info: Record<string, string>;
  paths: Record<string, Record<string, Operation>>;
  components: Record<string, unknown>;
}

export interface GenerateOptions {
  /** Replace the tracked table, so a test can plant a fault the real one cannot carry. */
  tableOverride?: BindingTable;
  /** Extra component schemas, so a test can plant one the strictness rules must reject. */
  extraSchemas?: Record<string, unknown>;
  /** Extra path items, so a test can plant a leak the rewrite map would otherwise remove. */
  extraPaths?: Record<string, Record<string, unknown>>;
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

  const documentSchemas = new Set(Object.keys(componentsDoc.components.schemas));
  const schemas: Record<string, unknown> = { ...componentsDoc.components.schemas };
  // The source files declare their dialect so an editor validates them, but the document
  // states it once in jsonSchemaDialect — leaving $schema on five components had them
  // declaring plain 2020-12 while the other 121 used the OpenAPI base dialect.
  for (const c of conventions) {
    schemas[c.name] = Object.fromEntries(
      Object.entries(c.schema).filter(([key]) => key !== '$schema'),
    );
  }
  schemas.Problem = PROBLEM_SCHEMA;
  schemas.ValidationProblem = VALIDATION_PROBLEM_SCHEMA;
  // The reflected response shapes the table names, with the rewrite map applied so no MCP
  // transport state survives into an HTTP response.
  const contract = JSON.parse(contractRaw) as {
    fullShapes: Record<string, unknown>;
    toolErrorCodes?: Record<string, string[]>;
  };
  // Which codes each tool can raise, derived in hdf-cli by walking the one package where
  // every mcperr code is raised, and recorded in the golden. Absent means the golden
  // predates the member, which must fail rather than silently declare nothing.
  if (contract.toolErrorCodes === undefined) {
    throw new Error('the contract golden has no toolErrorCodes; run pnpm run sync:golden');
  }
  const codesFor = new Map(Object.entries(contract.toolErrorCodes));
  // Raw MCP replies, captured in hdf-cli and synced here. The projection into an example
  // happens below, so ADR-0008 §2's rewrite map stays in one language.
  const envelopes = JSON.parse(
    readFileSync(join(HERE, 'mcp-envelopes.golden.json'), 'utf-8'),
  ) as { captures: Record<string, Record<string, unknown>> };
  for (const [name, shape] of Object.entries(contract.fullShapes)) {
    schemas[name] = stripTransportState(shape);
  }
  for (const [name, schema] of Object.entries(options.extraSchemas ?? {})) {
    schemas[name] = schema;
  }

  const paths: Record<string, Record<string, Operation>> = {};
  const describe = new Map(
    (toolsList.tools as { name: string; description?: string }[]).map((t) => [t.name, t.description]),
  );
  const inputsFor = new Map(
    (toolsList.tools as { name: string; inputSchema?: { properties?: Record<string, unknown> } }[]).map(
      (t) => [t.name, t.inputSchema?.properties ?? {}],
    ),
  );
  const bindingNameOf = new Map<string, string>();
  // Built before any operation is described, so a cross-reference resolves whichever order
  // the tools are walked in.
  const operationOf = new Map<string, string>();
  for (const [name, binding] of Object.entries({ ...table.tools, ...table.synthetic })) {
    if (binding.method && binding.path) {
      operationOf.set(name, `\`${binding.method.toUpperCase()} ${binding.path}\``);
    }
  }
  const add = (binding: ToolBinding, name: string, cls: string): void => {
    if (!binding.method || !binding.path) return;
    bindingNameOf.set(operationIdFor(name), name);
    paths[binding.path] ??= {};
    paths[binding.path]![binding.method] = operationFor(
      name,
      binding,
      cls,
      summarize(
        prose(binding.description ?? describe.get(name), operationOf),
        `${binding.method.toUpperCase()} ${binding.path}`,
      ),
      prose(binding.description ?? describe.get(name), operationOf),
      schemas,
      inputsFor.get(name) ?? {},
      codesFor.get(name) ?? [],
      envelopes.captures[name],
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

  for (const [path, item] of Object.entries(options.extraPaths ?? {})) {
    paths[path] = item as Record<string, Operation>;
  }

  // ---- hard-fails. Each is a refusal to emit, not a warning to ignore. ----

  // Paging the document advertises must be paging a caller can drive. An envelope member
  // with no matching input is a capability that does not exist; an input with no member is
  // a cursor the caller can never receive back.
  for (const [path, item] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(item)) {
      const query = new Set(
        (op.parameters ?? [])
          .map((p) => p as { name?: string; in?: string })
          .filter((p) => p.in === 'query')
          .map((p) => p.name),
      );
      const success = Object.entries(op.responses as Record<string, { content?: Record<string, { schema?: { properties?: Record<string, unknown> } }> }>)
        .find(([status]) => Number(status) < 400);
      const properties = success?.[1].content?.['application/json']?.schema?.properties;
      if (properties === undefined) continue;
      for (const member of ['next', 'limit'] as const) {
        const declared = properties[member] !== undefined;
        if (declared !== query.has(member)) {
          throw new Error(
            `${method.toUpperCase()} ${path} (${op.operationId}) ${declared ? 'returns' : 'accepts'} ` +
              `${member} and does not ${declared ? 'accept' : 'return'} it`,
          );
        }
      }
      // §3 requires the page size to carry a ceiling, and the only non-vacuous place to
      // check it is where a limit actually exists.
      const limit = properties.limit as { maximum?: number } | undefined;
      if (limit !== undefined && typeof limit.maximum !== 'number') {
        throw new Error(`${op.operationId}: limit carries no maximum, which §3 requires`);
      }
    }
  }

  // An operation publishing a success body with no schema, not recorded as exempt. The
  // document would promise a shape it never names and nothing would say so.
  for (const [path, item] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(item)) {
      const success = Object.entries(op.responses as Record<string, { content?: Record<string, { schema?: unknown }> }>)
        .find(([status]) => Number(status) < 400);
      if (success === undefined) continue;
      const [status, response] = success;
      if (status === '204') continue;
      const described = response.content?.['application/json']?.schema !== undefined;
      if (described) continue;
      // Keyed by the binding name, which is what a maintainer edits, not by the derived id.
      const bound = bindingNameOf.get(op.operationId) ?? op.operationId;
      if (RESPONSE_SHAPE_EXEMPT[bound] === undefined) {
        throw new Error(
          `${method.toUpperCase()} ${path} (${bound}) publishes a success body with no schema ` +
            'and is not in RESPONSE_SHAPE_EXEMPT; name the shape or record why it has none',
        );
      }
    }
  }

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
    // An exemption covers the whole schema, root and nested: RFC 9457's openness is the
    // reason for every entry here, and that openness is not confined to the root.
    if (STRICTNESS_EXEMPT[name] !== undefined) continue;
    const s = schema as Record<string, unknown>;
    const closed = s.additionalProperties === false;
    const isUnion = Array.isArray(s.oneOf) || Array.isArray(s.anyOf) || Array.isArray(s.allOf);
    if (!closed && !isUnion) {
      throw new Error(`${name}: a non-document schema must set additionalProperties: false`);
    }
    // And nothing open may hide inside it. A leaf is open on purpose only if it is listed,
    // with its reason, in OPEN_LEAF_EXEMPT.
    for (const leaf of openLeaves(schema, '')) {
      const key = `${name}${leaf}`;
      const exempt = Object.keys(OPEN_LEAF_EXEMPT).some((e) => key.startsWith(e));
      if (!exempt) {
        throw new Error(
          `${key}: an open nested leaf must be listed in OPEN_LEAF_EXEMPT with a reason`,
        );
      }
    }
  }

  // The same rule over request bodies. A body is typed from the contract, so an open leaf
  // can arrive there without any component carrying it.
  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods)) {
      const content = (op.requestBody as { content?: Record<string, { schema?: unknown }> } | undefined)
        ?.content;
      for (const media of Object.values(content ?? {})) {
        for (const leaf of openLeaves(media.schema, '')) {
          const key = `${method.toUpperCase()} ${path} requestBody${leaf}`;
          if (!Object.keys(OPEN_LEAF_EXEMPT).some((e) => key.startsWith(e))) {
            throw new Error(
              `${key}: an open nested leaf must be listed in OPEN_LEAF_EXEMPT with a reason`,
            );
          }
        }
      }
    }
  }

  // A paged operation publishes an example or is excused by name. Without this a new
  // paged tool ships an envelope no capture backs, and nothing says so.
  for (const [name, binding] of Object.entries(table.tools ?? {})) {
    if (binding.items === undefined) continue;
    if (envelopes.captures[name] !== undefined) continue;
    const reason = ENVELOPE_EXAMPLE_EXEMPT[name];
    if (reason === undefined || reason.length < 20) {
      throw new Error(
        `${name} is paged with no captured reply; capture it or list it in ENVELOPE_EXAMPLE_EXEMPT with a reason`,
      );
    }
  }

  // Nothing the rewrite map renames or drops may survive into the emitted document.
  //
  // The per-field check above reads the binding table's own top-level names, so it cannot
  // see a field nested inside a shape the contract supplied — which is exactly where a
  // filesystem `path` hid once, inside every `source` object, while the table was clean.
  // This reads the document instead, and fails closed.
  //
  // Scoped to `paths` deliberately, and widening it would break the build: five document
  // and reflected components carry one of these names as a legitimate property — a JSON
  // pointer in Field_Change.path, a regex in Input_Constraints.pattern — and responses
  // reach them by $ref rather than inlining them, so this reach is exactly the surface
  // rewriteInputShape builds.
  for (const { name, where } of propertyNamesIn(paths, '')) {
    if (FILESYSTEM_FIELDS.has(name)) {
      throw new Error(`${where}: ${name} is filesystem-shaped and must not reach HTTP`);
    }
    if (STRIPPED_OUTPUT_FIELDS.has(name)) {
      throw new Error(`${where}: ${name} is MCP transport state and must not reach HTTP`);
    }
  }

  // The media-type annotation has done its work by now: every request body is built. It is
  // an instruction to this generator, not part of the published shape.
  for (const schema of Object.values(schemas)) {
    if (schema !== null && typeof schema === 'object') {
      delete (schema as Record<string, unknown>)['x-hdf-media-type'];
    }
  }

  const document: ApiDocument = {
    openapi: '3.1.1',
    // Stated once, as the components document does. Without it the schemas here use the
    // OpenAPI base dialect by default while five conventions components declared plain
    // 2020-12 on themselves — two vocabulary sets inside one document.
    jsonSchemaDialect: DIALECT,
    info: {
      title: 'HDF Reference API',
      version: API_VERSION,
      description:
        'Reference HTTP API for the Heimdall Data Format, generated from the HDF MCP ' +
        "server's tool contract and a closed-grammar binding table. Generated — do not edit " +
        'by hand. Errors are RFC 9457 problem documents whose `type` dereferences to its ' +
        'documentation; see problems.json in this package.',
      license: { name: 'Apache-2.0', identifier: 'Apache-2.0' },
      contact: { name: 'MITRE Security Automation Framework', url: 'https://saf.mitre.org' },
      'x-hdf-schema-version': componentsDoc.info.version,
      'x-hdf-mcp-golden-sha': createHash('sha256').update(contractRaw).digest('hex'),
      // Over the whole document with `info` excluded. The two shas above cover two of the
      // three inputs — the components document and the MCP golden — and neither covers the
      // third, the binding table and the hand-authored conventions, which is where every
      // breaking change in revisions 17 to 19 came from. This also moves when the generator
      // changes, which no input sha can see.
      'x-hdf-contract-digest': '',
    } as unknown as Record<string, string>,
    paths,
    tags: [...new Set(Object.values(paths).flatMap((item) => Object.values(item).flatMap((op) => op.tags ?? [])))]
      .sort()
      .map((name) => {
        const description = TAG_DESCRIPTIONS[name];
        if (description === undefined) throw new Error(`tag ${name} has no description`);
        return { name, description };
      }),
    components: {
      schemas,
      headers: sharedHeaders(),
      parameters: sharedParameters(),
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

  // Filled after the fact: the digest covers the document it describes, so it cannot be
  // one of its own inputs.
  (document.info as Record<string, string>)['x-hdf-contract-digest'] = contractDigest(document);
  return document;
}

export function main(): void {
  const doc = generateApiDocument();
  mkdirSync(DIST, { recursive: true });
  writeArtifact(join(DIST, 'hdf-api.oas.json'), `${JSON.stringify(doc, null, 2)}\n`);
  process.stdout.write(
    `hdf-api.oas.json: ${Object.keys(doc.paths).length} paths at schema v${doc.info['x-hdf-schema-version']}\n`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
