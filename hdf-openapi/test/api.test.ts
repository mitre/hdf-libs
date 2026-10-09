import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { createRequire } from 'module';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { generateApiDocument, main as writeApiDocument, PROBLEM_TYPES, UNMAPPED_CODES } from '../src/generate-api.js';
import { loadBindings } from '../src/bindings.js';

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
