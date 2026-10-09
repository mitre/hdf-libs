import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { createRequire } from 'module';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { generateApiDocument, main as writeApiDocument, MAX_PAGE_SIZE, OPEN_LEAF_EXEMPT, PROBLEM_TYPES, rewriteInputShape, STRIPPED_OUTPUT_FIELDS, UNMAPPED_CODES } from '../src/generate-api.js';
import { FILESYSTEM_FIELDS, loadBindings } from '../src/bindings.js';

const HERE = new URL('.', import.meta.url).pathname;
const SRC = join(HERE, '..', 'src');
const toolsList = JSON.parse(readFileSync(join(SRC, 'tools-list.golden.json'), 'utf-8'));
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
        const ok = op.responses?.['200'] as { headers?: Record<string, unknown> } | undefined;
        if (ok?.headers?.[header] === undefined) missing.push(`${method.toUpperCase()} ${path}`);
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
