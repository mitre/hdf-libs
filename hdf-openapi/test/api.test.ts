import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { createRequire } from 'module';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { generateApiDocument, main as writeApiDocument, MAX_PAGE_SIZE, OPEN_LEAF_EXEMPT, ENVELOPE_EXAMPLE_EXEMPT, PROBLEM_TYPES, rewriteInputShape, STRICTNESS_EXEMPT, STRIPPED_OUTPUT_FIELDS, UNMAPPED_CODES } from '../src/generate-api.js';
import { bindingFaults, FILESYSTEM_FIELDS, loadBindings } from '../src/bindings.js';
import { loadConventions } from '../src/conventions.js';

const HERE = new URL('.', import.meta.url).pathname;
const SRC = join(HERE, '..', 'src');
const toolsList = JSON.parse(readFileSync(join(SRC, 'tools-list.golden.json'), 'utf-8'));
const contract = JSON.parse(readFileSync(join(SRC, 'mcp-contract.golden.json'), 'utf-8'));
const conventionNames = loadConventions().map((c) => c.name);
const table = loadBindings(readFileSync(join(SRC, 'bindings.yaml'), 'utf-8'));

// The lint below reads dist/hdf-api.oas.json, so write it here at module scope rather
// than trusting whatever a previous local run left behind: without this the suite fails in
// CI, where nothing has generated yet, and passes locally for the wrong reason.
writeApiDocument();
const doc = generateApiDocument();

describe('the generated reference API', () => {
  it('is OpenAPI 3.1 and carries the contract versions it was built from', () => {
    expect(doc.openapi).toMatch(/^3\.1\./);
    expect(doc.info['x-hdf-schema-version']).toMatch(/^\d+\.\d+\.\d+$/);
    expect(doc.info['x-hdf-mcp-golden-sha']).toMatch(/^[0-9a-f]{64}$/);
  });

  // Derived from the table, never restated: a hand-kept list of paths would agree with
  // itself while a bound tool went unemitted.
  it('emits one operation for every bound tool and synthetic operation', () => {
    const expected = new Set<string>();
    for (const op of [...Object.values(table.tools ?? {}), ...Object.values(table.synthetic ?? {})]) {
      if (op.method && op.path) expected.add(`${op.method.toUpperCase()} ${op.path}`);
    }
    const emitted = new Set<string>();
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const method of Object.keys(item)) emitted.add(`${method.toUpperCase()} ${path}`);
    }
    expect([...expected].filter((e) => !emitted.has(e))).toEqual([]);
    expect(expected.size).toBeGreaterThan(10);
  });

  // class derives from readOnlyHint; a read-only tool must never acquire hdf:write.
  it('gives every read-only tool hdf:read and no write scope', () => {
    for (const tool of toolsList.tools) {
      const binding = table.tools?.[tool.name];
      if (!binding?.path || !binding.method) continue;
      const readOnly = tool.annotations?.readOnlyHint === true;
      const op = doc.paths[binding.path]?.[binding.method];
      expect(op, `${tool.name} produced no operation`).toBeDefined();
      const scopes = (op!.security ?? []).flatMap((r) => Object.values(r).flat());
      expect(scopes).toContain('hdf:read');
      if (readOnly) expect(scopes).not.toContain('hdf:write');
      else expect(scopes).toContain('hdf:write');
    }
  });

  // ADR-0008 §3: every operation declares 500 and the RateLimit headers.
  it('declares 500 on every operation', () => {
    const missing: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(item)) {
        if (!op.responses?.['500']) missing.push(`${method.toUpperCase()} ${path}`);
      }
    }
    expect(missing).toEqual([]);
  });

  // ADR-0008 §3: every operation with a requestBody declares 413 and 415.
  it('declares 413 and 415 on every operation that takes a body', () => {
    const missing: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(item)) {
        if (!op.requestBody) continue;
        for (const status of ['413', '415']) {
          if (!op.responses?.[status]) missing.push(`${method.toUpperCase()} ${path} -> ${status}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  // The problem types come from ADR-0010 §6, consumed as written.
  it('maps exactly the error codes §6 gives an HTTP status', () => {
    expect(Object.keys(PROBLEM_TYPES).sort()).toEqual([
      'AMBIGUOUS_FORMAT',
      'DOCUMENT_NOT_FOUND',
      'HANDLE_STALE',
      'NO_CONVERTER',
      'SCHEMA_INVALID',
      'TOO_LARGE',
      'WRONG_DOC_TYPE',
    ]);
    // The five the table marks `never` are file-adapter concerns with no HTTP surface,
    // recorded rather than silently dropped.
    expect(UNMAPPED_CODES.sort()).toEqual([
      'CACHE_MISS',
      'OUTPUT_EXISTS',
      'PATH_DENIED',
      'TRUNCATED',
      'WRITE_FAILED',
    ]);
  });

  it('every mapped code accounts for all twelve the contract carries', () => {
    const contract = JSON.parse(readFileSync(join(SRC, 'mcp-contract.golden.json'), 'utf-8'));
    const accounted = new Set([...Object.keys(PROBLEM_TYPES), ...UNMAPPED_CODES]);
    expect(contract.errorCodes.filter((c: string) => !accounted.has(c))).toEqual([]);
    expect(contract.errorCodes.length).toBe(accounted.size);
  });
});

// Presence of a response key says nothing about whether its $ref resolves. The first
// version of these tests asserted the keys and passed against a document carrying seven
// dangling references, which is the shape of test this guard exists to replace.
describe('every reference resolves', () => {
  it('has no dangling $ref anywhere in the document', () => {
    const refs = [...JSON.stringify(doc).matchAll(/"#\/components\/(\w+)\/([\w.-]+)"/g)];
    expect(refs.length).toBeGreaterThan(50);
    const dangling = refs
      .map(([, kind, name]) => ({ kind, name }))
      .filter(({ kind, name }) => {
        const bucket = (doc.components as Record<string, Record<string, unknown>>)[kind!];
        return bucket === undefined || bucket[name!] === undefined;
      })
      .map(({ kind, name }) => `#/components/${kind}/${name}`);
    expect([...new Set(dangling)]).toEqual([]);
  });
});

describe('path parameters come from the template', () => {
  // The first version derived them from which field happened to be placed in the path,
  // so the synthetic delete operation — which has no fields and still addresses {id} —
  // emitted none, and Redocly rejected the document.
  it('declares every {x} in every path template', () => {
    const missing: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      const templated = [...path.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!);
      for (const [method, op] of Object.entries(item)) {
        const declared = ((op.parameters ?? []) as { name: string; in: string }[])
          .filter((p) => p.in === 'path')
          .map((p) => p.name);
        for (const name of templated) {
          if (!declared.includes(name)) missing.push(`${method.toUpperCase()} ${path} -> ${name}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  // A document reference placed in the path becomes {id}: the fixed handle -> id rewrite.
  it('names the document parameter id, not the MCP field it came from', () => {
    const op = doc.paths['/documents/{id}']?.get;
    const names = ((op?.parameters ?? []) as { name: string }[]).map((p) => p.name);
    expect(names).toContain('id');
    expect(names).not.toContain('source');
  });
});

describe('resources reach the document', () => {
  // They are bound in the table, so they must be emitted; the first version iterated only
  // tools and synthetic operations and dropped all four silently.
  it('emits an operation for every bound resource', () => {
    const paths = Object.entries(table.resources ?? {}).map(([, r]) => r.path);
    expect(paths.length).toBeGreaterThan(3);
    for (const path of paths) expect(doc.paths[path!]).toBeDefined();
  });
});

describe('what Redocly checks, checked here too', () => {
  it('every operation carries a summary', () => {
    const missing: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(item)) {
        if (!op.summary) missing.push(`${method.toUpperCase()} ${path}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it('defines the security scheme its operations reference', () => {
    const schemes = new Set<string>();
    for (const item of Object.values(doc.paths)) {
      for (const op of Object.values(item)) {
        for (const req of op.security ?? []) Object.keys(req).forEach((s) => schemes.add(s));
      }
    }
    expect(schemes.size).toBeGreaterThan(0);
    const defined = (doc.components as { securitySchemes?: Record<string, unknown> }).securitySchemes ?? {};
    expect([...schemes].filter((s) => defined[s] === undefined)).toEqual([]);
  });

  it('advertises the closed scope vocabulary on the scheme', () => {
    const scheme = (doc.components as { securitySchemes: Record<string, Record<string, unknown>> })
      .securitySchemes.bearerAuth!;
    expect(scheme['x-hdf-scopes']).toEqual(['hdf:read', 'hdf:write', 'hdf:admin']);
  });
});

// The card requires the lints to report zero errors on the API document, so the lint runs
// here rather than by hand. Spawned through process.execPath with the resolved bin entry,
// the same way the matrix script does it: a .bin shim is not executable on Windows.
describe('Redocly accepts the generated document', () => {
  it('reports no errors', () => {
    const binJs = createRequire(import.meta.url).resolve('@redocly/cli/bin/cli.js');
    const out = spawnSync(process.execPath, [binJs, 'lint', 'dist/hdf-api.oas.json'], {
      cwd: join(HERE, '..'),
      encoding: 'utf-8',
      env: { ...process.env, REDOCLY_TELEMETRY: 'off' },
    });
    expect(out.status, `${out.stdout}\n${out.stderr}`).toBe(0);
  });
});

// class drives scopes, so each class is checked at the document rather than at the helper:
// a mapping that is right in isolation and wired wrong emits the same bug.
describe('class determines scopes', () => {
  it('delete is admin and carries hdf:admin', () => {
    const op = doc.paths['/documents/{id}']?.delete;
    expect(op).toBeDefined();
    const scopes = (op!.security ?? []).flatMap((r) => Object.values(r).flat());
    expect(scopes).toEqual(['hdf:read', 'hdf:write', 'hdf:admin']);
  });

  it('ingest is write and carries hdf:write but not hdf:admin', () => {
    const scopes = (doc.paths['/documents']?.post?.security ?? []).flatMap((r) =>
      Object.values(r).flat(),
    );
    expect(scopes).toContain('hdf:write');
    expect(scopes).not.toContain('hdf:admin');
  });

  // documentOnly operations are served by the authorization server, so they carry no
  // security requirement at all — the empty array Spectral's rule accepts.
  it.each(['/api/auth/oauth2/token', '/api/auth/api-key/exchange'])(
    '%s is documentOnly with an empty security requirement',
    (path) => {
      const op = doc.paths[path]?.post;
      expect(op).toBeDefined();
      expect(op!.security).toEqual([]);
    },
  );

  it('a resource operation is read-only', () => {
    const scopes = (doc.paths['/catalog/converters']?.get?.security ?? []).flatMap((r) =>
      Object.values(r).flat(),
    );
    expect(scopes).toEqual(['hdf:read']);
  });
});

// ADR-0008 §2's fixed rewrite map, output half. These names are MCP transport state —
// filesystem paths, write-gating, page indices — and none may reach an HTTP response.
const FORBIDDEN_OUTPUT_FIELDS = ['page', 'nextPage', 'handle', 'writesDisabled', 'outputPath'];

describe('the rewrite map strips MCP transport state from responses', () => {
  // Non-vacuity first: this check is worthless unless operations actually carry response
  // schemas. Before fullResponse was wired every operation declared a bare 200, and the
  // field scan below passed by having nothing to scan.
  it('operations carry real response schemas to scan', () => {
    const withSchema = Object.values(doc.paths)
      .flatMap((item) => Object.values(item))
      .filter((op) => {
        const ok = op.responses?.['200'] as { content?: Record<string, { schema?: unknown }> };
        return ok?.content?.['application/json']?.schema !== undefined;
      });
    // Derived from the table rather than a literal: every binding that names a
    // fullResponse must produce a schema, and a magic number would drift the moment the
    // table changed — as it did when compliance and aggregate stopped naming one.
    const expected = [...Object.values(table.tools ?? {}), ...Object.values(table.synthetic ?? {})]
      .filter((b) => b.fullResponse !== undefined).length;
    expect(expected).toBeGreaterThan(4);
    expect(withSchema.length).toBe(expected);
  });

  it.each(FORBIDDEN_OUTPUT_FIELDS)('no response shape exposes %s', (field) => {
    const hits: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(item)) {
        const ok = op.responses?.['200'];
        if (ok === undefined) continue;
        const walk = (node: unknown, where: string): void => {
          if (Array.isArray(node)) return node.forEach((v, i) => walk(v, `${where}/${i}`));
          if (node === null || typeof node !== 'object') return;
          for (const [key, value] of Object.entries(node)) {
            if (key === 'properties' && value !== null && typeof value === 'object') {
              for (const prop of Object.keys(value)) {
                if (prop === field) hits.push(`${method.toUpperCase()} ${path}${where}/${prop}`);
              }
            }
            walk(value, `${where}/${key}`);
          }
        };
        walk(ok, '');
      }
    }
    expect(hits).toEqual([]);
  });
});

describe('the generator hard-fails rather than emitting a bad document', () => {
  it('on a filesystem field that was not dropped', () => {
    expect(() =>
      generateApiDocument({
        tableOverride: { tools: { hdf_author: { method: 'post', path: '/x', fields: { dryRun: { placement: 'query' } } } } },
      }),
    ).toThrow(/dryRun/);
  });

  it('on a format outside the tracked allowlist', () => {
    expect(() =>
      generateApiDocument({ extraSchemas: { Planted: { type: 'integer', format: 'int64' } } }),
    ).toThrow(/int64/);
  });

  it('on a non-document schema without additionalProperties: false', () => {
    expect(() =>
      generateApiDocument({ extraSchemas: { Loose: { type: 'object', properties: { a: { type: 'string' } } } } }),
    ).toThrow(/Loose/);
  });

  it('but accepts a schema that is strict and uses an allowed format', () => {
    expect(() =>
      generateApiDocument({
        extraSchemas: { Fine: { type: 'object', additionalProperties: false, properties: { id: { type: 'string', format: 'uuid' } } } },
      }),
    ).not.toThrow();
  });
});

describe('the scope-failure responses carry what RFC 6750 and §3 require', () => {
  it('the 403 is the insufficient-scope shape with the WWW-Authenticate header', () => {
    const r = (doc.components as { responses: Record<string, Record<string, unknown>> })
      .responses.InsufficientScope!;
    expect(JSON.stringify(r)).toContain('problems/insufficient-scope');
    expect(r.headers).toHaveProperty('WWW-Authenticate');
  });

  it('the 401 challenge names a scope, which the MCP revision asks for', () => {
    const r = (doc.components as { responses: Record<string, Record<string, unknown>> })
      .responses.Unauthorized!;
    const example = JSON.stringify(r);
    expect(example).toContain('about:blank');
    expect(example).toContain('scope=');
  });
});

// ADR-0008 §3's standards pass adopts the IETF RateLimit header fields. The AC pairs them
// with the declared 500, so both are checked across every operation rather than sampled.
describe('every operation advertises its rate-limit budget', () => {
  it.each(['RateLimit', 'RateLimit-Policy'])('declares %s on its success response', (header) => {
    const missing: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(item)) {
        // The success status is not always 200 — a delete declares 204 — so find it
        // rather than naming it, or this passes by looking at a response that is absent.
        const [, ok] = Object.entries(op.responses ?? {}).find(([status]) => Number(status) < 400) ?? [];
        const headers = (ok as { headers?: Record<string, unknown> } | undefined)?.headers;
        if (headers?.[header] === undefined) missing.push(`${method.toUpperCase()} ${path}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it('the 429 carries them too, alongside Retry-After', () => {
    const r = (doc.components as { responses: Record<string, { headers?: Record<string, unknown> }> })
      .responses.TooManyRequests!;
    expect(Object.keys(r.headers ?? {}).sort()).toEqual(['RateLimit', 'RateLimit-Policy', 'Retry-After']);
  });
});

describe('nested open leaves are exempted by name, not by silence', () => {
  // The rule OPEN_LEAF_EXEMPT describes was declared, documented and exported while
  // nothing read it — and its keys did not even match the real paths, so it was dead twice
  // over. It is now enforced, and these keep it honest in both directions.
  it('faults an open nested leaf that is not listed', () => {
    expect(() =>
      generateApiDocument({
        extraSchemas: {
          Nested: {
            type: 'object',
            additionalProperties: false,
            properties: { inner: { type: 'object', additionalProperties: true } },
          },
        },
      }),
    ).toThrow(/Nested\/properties\/inner.*OPEN_LEAF_EXEMPT/);
  });

  it('faults a bare true where a schema belongs', () => {
    expect(() =>
      generateApiDocument({
        extraSchemas: {
          Bare: { type: 'object', additionalProperties: false, properties: { anything: true } },
        },
      }),
    ).toThrow(/Bare\/properties\/anything/);
  });

  // An exemption that matches nothing is the dead config this rule just came out of, so
  // every key must still describe a real leaf.
  it('every exemption matches a leaf that is actually open, and carries a reason', () => {
    const doc = generateApiDocument();
    const all = (doc.components as { schemas: Record<string, unknown> }).schemas;
    // Scoped to what the generator actually consults. It skips the document schemas, which
    // carry their own strictness, and Problem. An exemption keyed to a leaf outside that
    // set is read by nothing — which is the dead config this test exists to catch, and the
    // every-schema version of it blessed a planted `HdfResults/properties/extensions`.
    const documentSchemas = new Set(
      Object.keys(
        (
          JSON.parse(readFileSync(join(SRC, '..', 'dist', 'hdf-components.oas.json'), 'utf-8')) as {
            components: { schemas: Record<string, unknown> };
          }
        ).components.schemas,
      ),
    );
    expect(documentSchemas.size).toBeGreaterThan(0);
    const schemas = Object.fromEntries(
      Object.entries(all).filter(([name]) => !documentSchemas.has(name) && name !== 'Problem'),
    );
    expect(Object.keys(schemas).length).toBeGreaterThan(0);
    const openLeaf = (node: unknown, where: string): string[] => {
      if (node === true) return [where];
      if (Array.isArray(node)) return node.flatMap((v, i) => openLeaf(v, `${where}/${i}`));
      if (node === null || typeof node !== 'object') return [];
      const schema = node as Record<string, unknown>;
      const out: string[] = [];
      if (schema.additionalProperties === true) out.push(where);
      for (const [key, value] of Object.entries(schema)) {
        if (['examples', 'enum', 'const', 'default'].includes(key)) continue;
        out.push(...openLeaf(value, `${where}/${key}`));
      }
      return out;
    };
    const actual = Object.entries(schemas).flatMap(([name, schema]) =>
      openLeaf(schema, '').map((leaf) => `${name}${leaf}`),
    );
    // Request bodies carry their own leaves, and one exemption lives there.
    for (const [path, methods] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(methods)) {
        const content = (op as { requestBody?: { content?: Record<string, { schema?: unknown }> } })
          .requestBody?.content;
        for (const media of Object.values(content ?? {})) {
          actual.push(
            ...openLeaf(media.schema, '').map(
              (leaf) => `${method.toUpperCase()} ${path} requestBody${leaf}`,
            ),
          );
        }
      }
    }
    expect(actual.length).toBeGreaterThan(0);
    for (const [key, reason] of Object.entries(OPEN_LEAF_EXEMPT)) {
      expect(reason.length, `${key} has no reason`).toBeGreaterThan(20);
      expect(
        actual.some((leaf) => leaf.startsWith(key)),
        `${key} matches no open leaf — remove it`,
      ).toBe(true);
    }
  });
});

// ADR-0008 §2: a synthetic operation's body is "bodyRef-only or a fixed conventions
// component, never an inline schema". The first version read bodyRef only to decide
// WHETHER there was a body and then emitted {type: object}, leaving three conventions
// components reachable from nothing — a $ref count of zero on each.
describe('bodyRef names the body, and the body is that component', () => {
  const bodyRefs = Object.entries({ ...table.tools, ...table.synthetic }).filter(
    ([, b]) => b.bodyRef !== undefined,
  );

  it('there are bodyRef bindings to check', () => {
    expect(bodyRefs.length).toBeGreaterThan(2);
  });

  it.each(bodyRefs)('%s refs its named component from the request body', (_name, binding) => {
    const op = doc.paths[binding.path!]?.[binding.method!];
    const content = (op?.requestBody as { content?: Record<string, { schema?: unknown }> })?.content;
    const schemas = Object.values(content ?? {}).map((c) => JSON.stringify(c.schema));
    expect(schemas.join(' ')).toContain(`#/components/schemas/${binding.bodyRef}`);
  });

  // Derived from the table: a component named as a bodyRef must be reachable, which is the
  // specific thing that was false.
  it('every conventions component named as a bodyRef is referenced somewhere', () => {
    const serialized = JSON.stringify(doc);
    for (const [, binding] of bodyRefs) {
      const refs = serialized.split(`"#/components/schemas/${binding.bodyRef}"`).length - 1;
      expect(refs, `${binding.bodyRef} is referenced ${refs} times`).toBeGreaterThan(0);
    }
  });

  // §3 makes RFC 8707's `resource` required on both token grants. It is declared in the
  // component, which is only meaningful if the operation actually references it.
  it.each(['/api/auth/oauth2/token', '/api/auth/api-key/exchange'])(
    '%s resolves to a component that requires `resource`',
    (path) => {
      const content = (doc.paths[path]?.post?.requestBody as {
        content: Record<string, { schema: { $ref?: string } }>;
      }).content;
      const ref = Object.values(content)[0]!.schema.$ref!;
      const name = ref.split('/').pop()!;
      const component = (doc.components as { schemas: Record<string, { required?: string[] }> })
        .schemas[name]!;
      expect(component.required).toContain('resource');
    },
  );

  // RFC 6749 §4.4 requires the grant to be form-encoded, and the component says so. The
  // operation must agree, or a client following the description gets a 415.
  it('the oauth2 grant is form-encoded, matching what its component declares', () => {
    const content = (doc.paths['/api/auth/oauth2/token']?.post?.requestBody as {
      content: Record<string, unknown>;
    }).content;
    expect(Object.keys(content)).toEqual(['application/x-www-form-urlencoded']);
  });
});

describe('pagination is bounded, and the applied limit is echoed', () => {
  it('every limit parameter is an integer with a maximum', () => {
    const limits = Object.values(doc.paths)
      .flatMap((item) => Object.values(item))
      .flatMap((op) => (op.parameters ?? []) as { name: string; schema: Record<string, unknown> }[])
      .filter((p) => p.name === 'limit');
    expect(limits.length).toBeGreaterThan(0);
    for (const limit of limits) {
      expect(limit.schema.type).toBe('integer');
      expect(limit.schema.maximum).toBe(MAX_PAGE_SIZE);
    }
  });

  // Scoped to bindings that actually produce an envelope: `items` names the row array, but
  // the envelope is only emitted when a row SHAPE is also named. hdf_aggregate has items
  // and no fullResponse — it is paged with no registered row type — so it has no envelope
  // to echo into. That is a real gap, recorded on the card rather than papered over with
  // an untyped items array, which would itself be an unlisted open leaf.
  it('the paged envelope echoes the limit it applied, per AIP-158', () => {
    const paged = Object.entries({ ...table.tools, ...table.synthetic }).filter(
      ([, b]) => b.items !== undefined && b.fullResponse !== undefined,
    );
    expect(paged.length).toBeGreaterThan(1);
    for (const [, binding] of paged) {
      const schema = (
        doc.paths[binding.path!]?.[binding.method!]?.responses['200'] as {
          content: Record<string, { schema: { properties?: Record<string, unknown> } }>;
        }
      ).content['application/json']!.schema;
      expect(Object.keys(schema.properties ?? {})).toContain('limit');
    }
  });
});

// Prerequisite (a) put the closed vocabularies into the MCP's input schemas as real enum
// arrays. The table says enumFrom for twelve fields; the first version read it nowhere, so
// the document advertised bare strings and the vocabularies were lost on the way to HTTP.
describe('enumFrom reaches the document', () => {
  const fromSchema = Object.entries(table.tools ?? {}).flatMap(([tool, binding]) =>
    Object.entries(binding.fields ?? {})
      .filter(([, f]) => f.enumFrom === 'schema enum' && f.placement === 'query')
      .map(([field]) => [tool, field, binding] as const),
  );

  it('there are enumFrom query fields to check', () => {
    expect(fromSchema.length).toBeGreaterThan(8);
  });

  it.each(fromSchema.map(([t, f, b]) => [`${t}.${f}`, f, b] as const))(
    '%s advertises a non-empty enum',
    (_label, field, binding) => {
      const op = doc.paths[binding.path!]?.[binding.method!];
      const parameter = ((op?.parameters ?? []) as { name: string; schema: unknown }[]).find(
        (p) => p.name === field,
      );
      expect(parameter, `${field} has no parameter`).toBeDefined();
      const serialized = JSON.stringify(parameter!.schema);
      expect(serialized).toContain('"enum"');
      expect(JSON.parse(serialized).enum?.length ?? JSON.parse(serialized).items?.enum?.length)
        .toBeGreaterThan(1);
    },
  );

  // `registry` carries no inline enum because the contract supplies none to carry: a
  // previous version of this test asserted that absence, which no upstream enum could ever
  // have falsified. The invariant worth pinning is that the vocabulary is reachable at all.
  it('the registry-sourced field has no upstream enum, and the catalog serves it instead', () => {
    const declared = toolsList.tools.find(
      (t: { name: string }) => t.name === 'hdf_convert',
    )!.inputSchema.properties.from as Record<string, unknown>;
    expect(declared.enum, 'hdf_convert.from gained an enum — inline it').toBeUndefined();
    expect(doc.paths['/catalog/converters']?.get).toBeDefined();
  });
});

// ADR-0008 §2's rewrite map has two halves, and the first version applied the wrong one to
// request bodies: `stripTransportState` removes `handle` because no response carries one,
// so on an INPUT it deleted the HTTP half of every document reference and kept the
// filesystem half. Every tool body shipped `source: {path}` — the inverse of the rule the
// ADR states, and the inverse of the reason `sources` is not name-gated.
describe('request bodies carry the input half of the rewrite map', () => {
  const bodySchemas = Object.entries(doc.paths).flatMap(([path, methods]) =>
    Object.entries(methods).flatMap(([method, op]) => {
      const content = (op as { requestBody?: { content?: Record<string, { schema?: unknown }> } })
        .requestBody?.content;
      return Object.values(content ?? {}).map((m) => ({ where: `${method} ${path}`, schema: m.schema }));
    }),
  );

  const propertyNames = (node: unknown, where: string): { name: string; where: string }[] => {
    if (Array.isArray(node)) return node.flatMap((v, i) => propertyNames(v, `${where}/${i}`));
    if (node === null || typeof node !== 'object') return [];
    const out: { name: string; where: string }[] = [];
    for (const [key, value] of Object.entries(node)) {
      if (key === 'properties' && value !== null && typeof value === 'object') {
        for (const name of Object.keys(value)) out.push({ name, where: `${where}/${name}` });
      }
      out.push(...propertyNames(value, `${where}/${key}`));
    }
    return out;
  };

  it('there are request bodies to check', () => {
    expect(bodySchemas.length).toBeGreaterThan(5);
  });

  it('no body property, at any depth, is filesystem-shaped or MCP transport state', () => {
    for (const { where, schema } of bodySchemas) {
      for (const prop of propertyNames(schema, where)) {
        expect(FILESYSTEM_FIELDS.has(prop.name), `${prop.where} is filesystem-shaped`).toBe(false);
        expect(
          STRIPPED_OUTPUT_FIELDS.has(prop.name),
          `${prop.where} is MCP transport state`,
        ).toBe(false);
      }
    }
  });

  it('every document reference in a body is addressed by id', () => {
    const refs = bodySchemas.flatMap(({ where, schema }) =>
      Object.entries(
        ((schema as { properties?: Record<string, Record<string, unknown>> }).properties ?? {}),
      )
        .filter(([field]) => ['source', 'sources', 'amendments'].includes(field))
        .map(([field, shape]) => ({ where: `${where}/${field}`, shape })),
    );
    // Counted from the table rather than guessed: every document reference the table
    // places in a body must appear in one, so the two sides are compared, not restated.
    const placed = Object.values(table.tools ?? {}).flatMap((b) =>
      Object.entries(b.fields ?? {}).filter(
        ([field, f]) => f.placement === 'body' && ['source', 'sources', 'amendments'].includes(field),
      ),
    );
    expect(placed.length).toBeGreaterThan(0);
    expect(refs.length).toBe(placed.length);
    for (const { where, shape } of refs) {
      const object = (shape.items ?? shape) as { properties?: Record<string, unknown> };
      expect(Object.keys(object.properties ?? {}), `${where}`).toEqual(['id']);
    }
  });

  it('no body description still points at a path or a handle', () => {
    for (const { where, schema } of bodySchemas) {
      expect(JSON.stringify(schema), where).not.toMatch(/\{path\}|\{handle\}/);
    }
  });

  // §2 normalizes a nullable input away: the MCP marks an optional field ["null", T], and
  // on HTTP absence is omission. The first version carried five of them through.
  it('no body shape declares a nullable type union', () => {
    for (const { where, schema } of bodySchemas) {
      const types = JSON.stringify(schema).match(/"type":\s*\[[^\]]*"null"[^\]]*\]/g);
      expect(types, where).toBeNull();
    }
  });

  // The guard is what makes the above a refusal to emit rather than a test somebody can
  // delete. The per-field check in bindings.ts reads the TABLE's top-level names, so it
  // never saw the nested leak; this reads the emitted document.
  it('faults a filesystem property planted in a body', () => {
    expect(() =>
      generateApiDocument({
        extraPaths: {
          '/planted': {
            post: {
              operationId: 'planted',
              responses: {},
              requestBody: {
                content: {
                  'application/json': { schema: { type: 'object', properties: { path: { type: 'string' } } } },
                },
              },
            },
          },
        },
      }),
    ).toThrow(/path is filesystem-shaped/);
  });

  it('faults MCP transport state planted in a body', () => {
    expect(() =>
      generateApiDocument({
        extraPaths: {
          '/planted': {
            post: {
              operationId: 'planted',
              responses: {},
              requestBody: {
                content: {
                  'application/json': {
                    schema: { type: 'object', properties: { handle: { type: 'string' } } },
                  },
                },
              },
            },
          },
        },
      }),
    ).toThrow(/handle is MCP transport state/);
  });
});

// The rewrite's rules are exercised unevenly by the real contract: every document
// reference is {handle, path}, so the branches that handle a THIRD member, a declared
// `required`, or a multi-type union are never reached by the golden. Each is still a rule
// that would silently emit an invalid document if it were wrong -- a `required: [handle]`
// surviving against `properties: {id}` is the obvious one -- so they are pinned directly.
describe('rewriteInputShape applies each rule, including the ones the golden never hits', () => {
  it('renames handle, drops filesystem members, and leaves everything else alone', () => {
    expect(
      rewriteInputShape({
        type: 'object',
        properties: {
          handle: { type: 'string' },
          path: { type: 'string' },
          label: { type: 'string' },
        },
      }),
    ).toEqual({
      type: 'object',
      properties: { id: { type: 'string' }, label: { type: 'string' } },
    });
  });

  it('rewrites a declared required list the same way as the properties it names', () => {
    expect(
      rewriteInputShape({ type: 'object', required: ['handle', 'path', 'label'] }),
    ).toEqual({ type: 'object', required: ['id', 'label'] });
  });

  it('keeps a non-string required entry rather than discarding it', () => {
    expect(rewriteInputShape({ required: [7] })).toEqual({ required: [7] });
  });

  it('collapses a nullable union to its single concrete type', () => {
    expect(rewriteInputShape({ type: ['null', 'object'] })).toEqual({ type: 'object' });
  });

  it('keeps a union that is genuinely more than one type, minus the null', () => {
    expect(rewriteInputShape({ type: ['null', 'string', 'number'] })).toEqual({
      type: ['string', 'number'],
    });
  });

  it('recurses through arrays and leaves scalars untouched', () => {
    expect(
      rewriteInputShape({ anyOf: [{ properties: { handle: { type: 'string' } } }, 'scalar'] }),
    ).toEqual({ anyOf: [{ properties: { id: { type: 'string' } } }, 'scalar'] });
  });
});

// `items` may be a LIST of schemas, and the open-leaf walk has to descend each one. The
// built document never uses that form, so without this the array arm is unexercised.
describe('the open-leaf walk descends a list-valued items', () => {
  it('faults a bare true inside an items array', () => {
    expect(() =>
      generateApiDocument({
        extraSchemas: {
          Tupled: { type: 'object', additionalProperties: false, items: [{ type: 'string' }, true] },
        },
      }),
    ).toThrow(/Tupled\/items\/1/);
  });
});

// The same refusal over request bodies. Only one real body is exempt, so without a planted
// fault this throw was reachable by mutation and by nothing a future change would run.
describe('an unlisted open leaf in a request body refuses to emit', () => {
  it('faults additionalProperties: true planted in a body', () => {
    expect(() =>
      generateApiDocument({
        extraPaths: {
          '/planted': {
            post: {
              operationId: 'planted',
              responses: {},
              requestBody: {
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: { loose: { type: 'object', additionalProperties: true } },
                    },
                  },
                },
              },
            },
          },
        },
      }),
    ).toThrow(/POST \/planted requestBody\/properties\/loose.*OPEN_LEAF_EXEMPT/);
  });
});

// ADR-0008 §3 maps the mcperr taxonomy onto HTTP statuses but says nothing about WHICH
// operation declares WHICH code, and the first version of this generator declared none of
// them: the document had no 412 and no 422 at all, so a client could not type the response
// it gets when it posts an invalid document. The contract golden now records, per tool, the
// codes that tool can actually raise — derived by walking the one package where every
// mcperr code in the repo is raised — so this is derived, not a per-operation list.
describe('each operation declares the problem responses its tool can raise', () => {
  const perTool = (contract as { toolErrorCodes: Record<string, string[]> }).toolErrorCodes;

  const operationFor = (tool: string): Record<string, unknown> => {
    const binding = table.tools![tool]!;
    return doc.paths[binding.path!]![binding.method!]! as unknown as Record<string, unknown>;
  };
  const statusesOf = (tool: string): string[] =>
    Object.keys((operationFor(tool).responses ?? {}) as Record<string, unknown>);

  it('the golden records a per-tool code set for every bound tool', () => {
    expect(perTool, 'the contract golden has no toolErrorCodes').toBeDefined();
    for (const tool of Object.keys(table.tools ?? {})) {
      expect(perTool[tool], `${tool} has no recorded code set`).toBeDefined();
      expect(perTool[tool]!.length).toBeGreaterThan(0);
    }
  });

  /**
   * Two statuses are deliberately NOT derived from the code set, each for a stated reason.
   * They are named here rather than left as a softer assertion, so the exceptions are
   * reviewable and a third one cannot be added by quietly relaxing the rule.
   *
   * 412: §2 scopes If-Match, and so 412, to write operations addressing a document. The
   * MCP raises HANDLE_STALE on reads too, but a read sends no If-Match, so a 412 there
   * would document a response that cannot occur.
   *
   * 413: a REQUEST-size status (RFC 9110 §15.5.14), already placed on every body-carrying
   * operation. TOO_LARGE covers both an oversized inline body (convert.go's
   * ValidateInputSize on inline content) and a stored document too large to load, so
   * deriving it per tool put a 413 on six GETs that carry no request body at all.
   */
  const SCOPED_ELSEWHERE = new Map<number, string>([
    [412, 'ADR-0008 §2 scopes If-Match to writes addressing a document'],
    [413, 'RFC 9110 §15.5.14 is about request size, and hasBody already places it'],
  ]);

  it.each(Object.keys(table.tools ?? {}))(
    '%s declares a response for every mapped code it can raise',
    (tool) => {
      const statuses = new Set(statusesOf(tool));
      let checked = 0;
      for (const code of perTool[tool] ?? []) {
        const mapped = PROBLEM_TYPES[code];
        if (mapped === undefined) continue;
        if (SCOPED_ELSEWHERE.has(mapped.status)) continue;
        checked += 1;
        expect(
          statuses.has(String(mapped.status)),
          `${tool} can raise ${code} (${mapped.status}) and its operation declares no ${mapped.status}`,
        ).toBe(true);
      }
      expect(checked, `${tool} had no mapped code to check, so this passed vacuously`)
        .toBeGreaterThan(0);
    },
  );

  it('every scoped-elsewhere status is reachable somewhere, so neither exception is a blanket drop', () => {
    const everyStatus = new Set(
      Object.values(doc.paths).flatMap((item) =>
        Object.values(item).flatMap((op) => Object.keys(op.responses ?? {})),
      ),
    );
    for (const [status, reason] of SCOPED_ELSEWHERE) {
      expect(reason.length).toBeGreaterThan(20);
      expect(
        everyStatus.has(String(status)),
        `${status} is excluded from derivation and appears nowhere, so it was dropped entirely`,
      ).toBe(true);
    }
  });

  it('declares no status for a code the taxonomy marks as never reaching HTTP', () => {
    // Every unmapped code's status would have to come from somewhere else, so the test is
    // that no operation gained a status ONLY an unmapped code could justify.
    for (const tool of Object.keys(table.tools ?? {})) {
      const mappedStatuses = new Set(
        (perTool[tool] ?? [])
          .map((code) => PROBLEM_TYPES[code]?.status)
          .filter((s): s is number => s !== undefined)
          .map(String),
      );
      const conventional = new Set(['200', '401', '403', '413', '415', '429', '500', '503']);
      for (const status of statusesOf(tool)) {
        if (conventional.has(status)) continue;
        expect(
          mappedStatuses.has(status),
          `${tool} declares ${status}, which no code it can raise maps to`,
        ).toBe(true);
      }
    }
  });

  // The discriminations that matter, each measured from the Go source rather than guessed.
  it('scopes the conversion-only codes to the conversion operation', () => {
    expect(statusesOf('hdf_convert')).toContain('422');
    const types = JSON.stringify(operationFor('hdf_convert').responses);
    expect(types).toContain('no-converter');
    expect(types).toContain('ambiguous-format');
    for (const tool of ['hdf_query', 'hdf_diff', 'hdf_compliance']) {
      const other = JSON.stringify(operationFor(tool).responses);
      expect(other, `${tool} must not advertise a conversion failure`).not.toContain('no-converter');
    }
  });

  // hdf_validate raises no SCHEMA_INVALID: an invalid document is a SUCCESSFUL validation
  // with a negative result, not an error. A structural rule keyed on "the body carries a
  // document" would have put a 422 here, and it would have been wrong.
  it('does not give /validations a 422, because validation failure is a 200', () => {
    expect(perTool.hdf_validate).not.toContain('SCHEMA_INVALID');
    expect(statusesOf('hdf_validate')).not.toContain('422');
  });

  // DOCUMENT_NOT_FOUND is reachable wherever a document reference is resolved, which
  // includes operations with no {id} in the path — the reference travels in the body. The
  // previous structural rule keyed on the path template and missed those.
  it('declares 404 on an operation that names a document in its body', () => {
    expect(perTool.hdf_validate).toContain('DOCUMENT_NOT_FOUND');
    expect(statusesOf('hdf_validate')).toContain('404');
  });

  // §3: SCHEMA_INVALID carries `errors[]` of {path,line,message}.
  it('the 422 problem carries the errors[] member §3 requires', () => {
    const response = (operationFor('hdf_convert').responses as Record<string, unknown>)['422'];
    const ref = JSON.stringify(response);
    expect(ref).toContain('ValidationProblem');
    const schema = (doc.components as { schemas: Record<string, Record<string, unknown>> })
      .schemas.ValidationProblem;
    expect(schema, 'no ValidationProblem component').toBeDefined();
    const errors = (schema!.properties as Record<string, Record<string, unknown>>).errors;
    expect(errors, 'ValidationProblem has no errors member').toBeDefined();
    const item = errors!.items as { properties?: Record<string, unknown> };
    expect(Object.keys(item.properties ?? {}).sort()).toEqual(['line', 'message', 'path']);
  });

  // §2: "If-Match gates write operations ... so 412 is meaningful and maps HANDLE_STALE".
  // Scoped to writes deliberately: the MCP can raise HANDLE_STALE on a read, but a read
  // carries no If-Match, so a 412 there would describe something that cannot happen.
  it('gives 412 and an If-Match header to a write that addresses a document', () => {
    const op = operationFor('hdf_apply_amendment');
    expect(perTool.hdf_apply_amendment).toContain('HANDLE_STALE');
    expect(Object.keys(op.responses as Record<string, unknown>)).toContain('412');
    const headers = ((op.parameters ?? []) as { name: string; in: string }[]).filter(
      (p) => p.in === 'header',
    );
    expect(headers.map((h) => h.name)).toContain('If-Match');
  });

  it('gives no 412 to a read, which carries no If-Match', () => {
    expect(perTool.hdf_query).toContain('HANDLE_STALE');
    expect(statusesOf('hdf_query')).not.toContain('412');
  });
});

// STRICTNESS_EXEMPT is a map, and the strictness loop once named one of its keys directly
// — so a second entry was configuration nothing consulted. Both directions are pinned
// here: every key must be honoured, and every key must still describe a real schema.
describe('the strictness exemptions are all honoured and all real', () => {
  it('has more than one exemption, so honouring only the first would be visible', () => {
    expect(Object.keys(STRICTNESS_EXEMPT).length).toBeGreaterThan(1);
  });

  it('every exempt name is a component that exists and carries a reason', () => {
    const schemas = (doc.components as { schemas: Record<string, unknown> }).schemas;
    for (const [name, reason] of Object.entries(STRICTNESS_EXEMPT)) {
      expect(schemas[name], `${name} is exempt and is not a component`).toBeDefined();
      expect(reason.length, `${name} has no reason`).toBeGreaterThan(20);
    }
  });

  // Asserting `additionalProperties !== false` would only be a PROXY for refusal: a schema
  // using allOf with no additionalProperties key would satisfy it while its exemption did
  // nothing. So each key is removed and the generator asked.
  it('each exemption is load-bearing: removing it makes the generator refuse', () => {
    for (const name of Object.keys(STRICTNESS_EXEMPT)) {
      const saved = STRICTNESS_EXEMPT[name]!;
      delete STRICTNESS_EXEMPT[name];
      let threw = false;
      try {
        generateApiDocument();
      } catch {
        threw = true;
      } finally {
        STRICTNESS_EXEMPT[name] = saved;
      }
      expect(threw, `${name}'s exemption is dead config — the generator emits without it`).toBe(
        true,
      );
    }
  });
});

// A synthetic operation has no MCP tool, so it has no derived code set — and every
// assertion in the block above iterates table.tools, which is exactly why replacing the
// structural 404 rule with the derivation silently took the 404 off DELETE /documents/{id}.
// The synthetic surface needs its own coverage or it is reviewed by nobody.
describe('the synthetic operations declare an error surface too', () => {
  const synthetic = Object.entries(table.synthetic ?? {}).filter(
    ([, b]) => b.method !== undefined && b.path !== undefined,
  );

  it('there are synthetic operations to check', () => {
    expect(synthetic.length).toBeGreaterThan(3);
  });

  it.each(synthetic.map(([name, b]) => [name, b] as const))(
    '%s addressing a document by id declares a 404',
    (_name, binding) => {
      if (!binding.path!.includes('{id}')) return;
      const op = doc.paths[binding.path!]![binding.method!]!;
      expect(
        Object.keys(op.responses),
        `${binding.method} ${binding.path} addresses {id} and declares no 404`,
      ).toContain('404');
    },
  );

  it('every synthetic operation declares the conventional statuses', () => {
    for (const [, binding] of synthetic) {
      const statuses = Object.keys(doc.paths[binding.path!]![binding.method!]!.responses);
      for (const required of ['401', '403', '429', '500', '503']) {
        expect(statuses, `${binding.method} ${binding.path} lacks ${required}`).toContain(required);
      }
    }
  });
});

// §2 states DELETE /documents/{id}'s surface — 204, a delete-restricted 409 and a legal-hold
// 409 — and none of it is derivable: a synthetic operation raises no mcperr code, and the
// two 409 conditions are ADR-0009/ADR-0013 service concerns the MCP has no equivalent for.
// So §2's grammar declares them and the generator reads the declaration.
describe("a synthetic operation's declared statuses reach the document", () => {
  const declaring = Object.entries(table.synthetic ?? {}).filter(
    ([, b]) => b.success !== undefined || b.problems !== undefined,
  );

  it('the table declares statuses somewhere, so the cases below are not empty', () => {
    expect(declaring.length).toBeGreaterThan(0);
  });

  it.each(declaring.map(([name, b]) => [name, b] as const))(
    '%s emits its declared success status and no other',
    (_name, binding) => {
      const statuses = Object.keys(doc.paths[binding.path!]![binding.method!]!.responses);
      const success = statuses.filter((s) => Number(s) < 400);
      expect(success).toEqual([String(binding.success ?? 200)]);
    },
  );

  it.each(declaring.map(([name, b]) => [name, b] as const))(
    '%s emits every problem status it declares, with the declared types',
    (_name, binding) => {
      const op = doc.paths[binding.path!]![binding.method!]!;
      for (const [status, types] of Object.entries(binding.problems ?? {})) {
        const response = op.responses[status] as
          | { content: Record<string, { examples: Record<string, unknown> }> }
          | undefined;
        expect(response, `${binding.method} ${binding.path} declares ${status} and emits none`).toBeDefined();
        const emitted = Object.keys(response!.content['application/problem+json']!.examples);
        expect(emitted.sort()).toEqual([...types].sort());
      }
    },
  );

  it('a 204 carries no response body', () => {
    const op = doc.paths['/documents/{id}']!.delete!;
    expect(op.responses['200']).toBeUndefined();
    expect((op.responses['204'] as { content?: unknown }).content).toBeUndefined();
  });

  // §2 scopes If-Match to writes addressing a document, and a delete is one. It was absent
  // only because no MCP tool raises HANDLE_STALE for a delete, there being no MCP delete.
  // scopesFor returned hdf:read for anything it did not recognise, so a mistyped class
  // emitted a read-only scope on a write and suppressed If-Match with it.
  it('refuses a class outside the declared vocabulary', () => {
    expect(() =>
      generateApiDocument({
        tableOverride: {
          synthetic: { probe: { method: 'delete', path: '/documents/{id}', class: 'writes', scopes: ['hdf:write'] } },
        },
      }),
    ).toThrow(/class writes is not one of/);
  });

  // A declared type the taxonomy already owns must agree with it, or the document would
  // carry one type URI under two statuses and a client could not branch on either.
  it('refuses a declared type whose status contradicts ADR-0010 §6', () => {
    expect(() =>
      generateApiDocument({
        tableOverride: {
          synthetic: {
            probe: {
              method: 'delete',
              path: '/documents/{id}',
              class: 'admin',
              scopes: ['hdf:admin'],
              problems: { '409': ['handle-stale'] },
            },
          },
        },
      }),
    ).toThrow(/handle-stale is 409 in the binding table and 412 in ADR-0010/);
  });

  it('the conditional delete requires If-Match', () => {
    const op = doc.paths['/documents/{id}']!.delete!;
    const header = (op.parameters ?? []).find(
      (p) => (p as { name: string }).name === 'If-Match',
    ) as { required: boolean; in: string } | undefined;
    expect(header, 'DELETE /documents/{id} declares a 412 and no If-Match').toBeDefined();
    expect(header!.in).toBe('header');
    expect(header!.required).toBe(true);
    expect(Object.keys(op.responses)).toContain('412');
  });
});

// hdf_diff returns a comparison-level `summary` — the rollup that answers "what changed" —
// and the envelope was {changes, next, total, limit} with additionalProperties: false, so
// the HTTP response could not carry it. Three of its members could not be recovered from
// the rows either: `unchanged`, `total` and `matchedCount` all count unchanged entries,
// which never enter the array. Caught by trying to GENERATE an envelope example from the
// real MCP reply: the projected instance could not validate against its own schema.
describe('a paged envelope carries the summary its tool returns', () => {
  const withSummary = Object.entries(table.tools ?? {}).filter(
    ([, b]) => b.summaryRef !== undefined,
  );

  it('the table names a summary shape for the comparison operation', () => {
    // Also the guard for the two it.each blocks below: an empty filter makes them produce
    // zero cases, which vitest reports as neither passing nor failing.
    expect(withSummary.length, 'no binding names a summary, so the cases below are empty')
      .toBeGreaterThan(0);
    expect(withSummary.map(([name]) => name)).toContain('hdf_diff');
  });

  it.each(withSummary.map(([name, b]) => [name, b] as const))(
    '%s names a shape that exists in the contract',
    (_name, binding) => {
      const shapes = (contract as { fullShapes: Record<string, unknown> }).fullShapes;
      expect(shapes[binding.summaryRef!], `${binding.summaryRef} is in no fullShapes`).toBeDefined();
    },
  );

  it.each(withSummary.map(([name, b]) => [name, b] as const))(
    '%s emits summary as a $ref to that component, inside the envelope',
    (_name, binding) => {
      const schema = (
        doc.paths[binding.path!]![binding.method!]!.responses['200'] as {
          content: Record<string, { schema: Record<string, unknown> }>;
        }
      ).content['application/json']!.schema;
      const properties = schema.properties as Record<string, Record<string, unknown>>;
      expect(Object.keys(properties)).toContain('summary');
      expect(properties.summary!.$ref).toBe(`#/components/schemas/${binding.summaryRef}`);
      // Still closed: the summary is a declared member, not a hole opened to admit it.
      expect(schema.additionalProperties).toBe(false);
    },
  );

  it('the summary component carries the rollup members, not an empty object', () => {
    const shapes = (doc.components as { schemas: Record<string, Record<string, unknown>> })
      .schemas;
    const summary = shapes['diff.summary'];
    expect(summary, 'no diff.summary component').toBeDefined();
    const members = Object.keys(
      (summary!.properties ?? {}) as Record<string, unknown>,
    ).sort();
    expect(members).toEqual([
      'absent',
      'fixed',
      'matchedCount',
      'new',
      'regressed',
      'total',
      'unchanged',
      'unmatchedNewCount',
      'unmatchedOldCount',
      'updated',
    ]);
  });

  // The envelope's `total` counts the pageable rows, which exclude unchanged entries; the
  // summary's own counts every entry the diff compared — requirement diffs in temporal mode,
  // component diffs in system-drift, both including unchanged. They coincide at 2 on the
  // capture fixture only because unchanged is 0, so neither may be derived from the other.
  it('keeps the envelope total and the summary total as separate members', () => {
    const schema = (
      doc.paths['/comparisons']!.get!.responses['200'] as {
        content: Record<string, { schema: Record<string, unknown> }>;
      }
    ).content['application/json']!.schema;
    const properties = schema.properties as Record<string, Record<string, unknown>>;
    expect(properties.total!.type).toBe('integer');
    expect(properties.summary!.$ref).toBeDefined();
  });
});

// summaryRef only reaches the document through the paged envelope, which okResponse builds
// only when the table also names the row array and its shape. On a binding without them the
// key emits nothing, and the build, Redocly and Spectral all pass; the suite does catch it,
// but as a TypeError dereferencing `content` on a response that has none. This faults where
// the cause is.
describe('a summaryRef that cannot reach a response is a fault', () => {
  it('faults a summaryRef on a binding with no items or fullResponse', () => {
    const planted = JSON.parse(JSON.stringify(table)) as typeof table;
    // hdf_compliance has neither, which is what makes it the right plant.
    expect(planted.tools!.hdf_compliance!.items).toBeUndefined();
    expect(planted.tools!.hdf_compliance!.fullResponse).toBeUndefined();
    planted.tools!.hdf_compliance!.summaryRef = 'diff.summary';
    const faults = bindingFaults(planted, { toolsList, contract });
    expect(faults.join('\n')).toMatch(/hdf_compliance: summaryRef needs items and fullResponse/);
  });

  // bodyRef is checked in the same loop and no real tool uses one — all three uses are
  // synthetic — so without a plant no test reaches that branch. It would still fire in
  // production on a bad real-tool bodyRef; what it lacked was coverage, not a caller.
  it('faults a bodyRef naming neither a reflected shape nor a conventions component', () => {
    const planted = JSON.parse(JSON.stringify(table)) as typeof table;
    planted.tools!.hdf_diff!.bodyRef = 'NotAShapeAnywhere';
    const faults = bindingFaults(planted, { toolsList, contract, conventions: conventionNames });
    expect(faults.join('\n')).toMatch(
      /hdf_diff: bodyRef names NotAShapeAnywhere, which is neither a reflected shape nor a conventions component/,
    );
  });

  // bodyRef is checked against reflected shapes PLUS the conventions components, and that
  // second half only means something when conventions are supplied: without them
  // shapeNames collapses to fullShapes, and narrowing the check would red nothing.
  it('accepts a bodyRef naming a conventions component rather than a reflected shape', () => {
    expect(conventionNames.length, 'no conventions loaded, so the wider set is the narrow one')
      .toBeGreaterThan(0);
    const planted = JSON.parse(JSON.stringify(table)) as typeof table;
    planted.tools!.hdf_diff!.bodyRef = 'IngestRequest';
    const faults = bindingFaults(planted, { toolsList, contract, conventions: conventionNames });
    expect(faults.join('\n')).not.toMatch(/hdf_diff: bodyRef names IngestRequest/);
    expect((contract as { fullShapes: Record<string, unknown> }).fullShapes.IngestRequest,
      'IngestRequest must NOT be a reflected shape, or this proves nothing').toBeUndefined();
  });

  it('faults a summaryRef naming a shape the contract does not carry', () => {
    const planted = JSON.parse(JSON.stringify(table)) as typeof table;
    planted.tools!.hdf_diff!.summaryRef = 'diff.nope';
    const faults = bindingFaults(planted, { toolsList, contract });
    expect(faults.join('\n')).toMatch(/hdf_diff: summaryRef names diff\.nope, absent from the contract/);
  });
});

// Each paged operation publishes an envelope schema; these pin that it also publishes an
// EXAMPLE, projected by the generator from a captured MCP reply rather than written here.
describe('the paged operations publish an example projected from a captured reply', () => {
  const envelopes = JSON.parse(
    readFileSync(join(SRC, 'mcp-envelopes.golden.json'), 'utf-8'),
  ) as { captures: Record<string, Record<string, unknown>> };

  const pagedTools = Object.entries(table.tools ?? {}).filter(([, b]) => b.items !== undefined);
  const captured = pagedTools.filter(([tool]) => envelopes.captures[tool] !== undefined);

  const exampleFor = (binding: (typeof pagedTools)[number][1]): Record<string, unknown> => {
    const media = (
      doc.paths[binding.path!]![binding.method!]!.responses['200'] as {
        content?: Record<string, { example?: Record<string, unknown> }>;
      }
    ).content?.['application/json'];
    return media?.example ?? {};
  };

  it('every paged tool is either captured or exempt with a reason', () => {
    expect(pagedTools.length, 'no paged bindings, so the cases below are empty').toBeGreaterThan(2);
    expect(captured.length, 'nothing is captured, so the cases below are empty').toBeGreaterThan(1);
    for (const [tool] of pagedTools) {
      const hasCapture = envelopes.captures[tool] !== undefined;
      const reason = ENVELOPE_EXAMPLE_EXEMPT[tool];
      expect(
        hasCapture || (reason !== undefined && reason.length > 20),
        `${tool} is paged with neither a capture nor a reason`,
      ).toBe(true);
      expect(hasCapture && reason !== undefined, `${tool} is both captured and exempt`).toBe(false);
    }
  });

  // Guards the GENERATOR, not the capture: both sides read one golden, so a corrupted
  // capture passes here and is caught by sync --check and the Go drift test instead.
  it.each(captured.map(([tool, b]) => [tool, b] as const))(
    '%s publishes rows byte-equal to its capture',
    (tool, binding) => {
      const rows = envelopes.captures[tool]![binding.items!];
      expect(rows, `${tool}'s capture has no ${binding.items} array`).toBeDefined();
      expect(exampleFor(binding)[binding.items!]).toEqual(rows);
    },
  );

  it.each(captured.map(([tool, b]) => [tool, b] as const))(
    '%s publishes no cursor, which is ADR-0011s to define',
    (_tool, binding) => {
      expect(Object.keys(exampleFor(binding))).not.toContain('next');
    },
  );

  it.each(captured.map(([tool, b]) => [tool, b] as const))(
    '%s publishes no MCP transport state',
    (_tool, binding) => {
      for (const member of Object.keys(exampleFor(binding))) {
        expect(STRIPPED_OUTPUT_FIELDS.has(member), `${member} is transport state`).toBe(false);
      }
    },
  );

  // An example may only carry members the envelope declares, which is what stops a capture
  // smuggling a member the schema forbids past additionalProperties: false.
  it.each(captured.map(([tool, b]) => [tool, b] as const))(
    '%s publishes only members its envelope declares',
    (_tool, binding) => {
      const schema = (
        doc.paths[binding.path!]![binding.method!]!.responses['200'] as {
          content: Record<string, { schema: { properties?: Record<string, unknown> } }>;
        }
      ).content['application/json']!.schema;
      const declared = Object.keys(schema.properties ?? {});
      for (const member of Object.keys(exampleFor(binding))) {
        expect(declared, `${member} is in the example and not in the envelope`).toContain(member);
      }
    },
  );

  it('every exempt entry names a tool that is actually paged', () => {
    const pagedNames = pagedTools.map(([tool]) => tool);
    for (const tool of Object.keys(ENVELOPE_EXAMPLE_EXEMPT)) {
      expect(pagedNames, `${tool} is exempt and is not a paged binding`).toContain(tool);
    }
  });
});
