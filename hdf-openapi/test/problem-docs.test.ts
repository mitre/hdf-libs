import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { loadProblemDocs } from '../src/problems.js';
import { generateApiDocument } from '../src/generate-api.js';

const docs = loadProblemDocs();
const api = generateApiDocument();

/** Every problem type the emitted document declares, read back out of it. */
function declaredTypes(): Set<string> {
  const found = new Set<string>();
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const value = (node as { type?: unknown }).type;
    if (typeof value === 'string' && value.includes('/problems/')) {
      found.add(value.slice(value.lastIndexOf('/') + 1));
    }
    Object.values(node).forEach(walk);
  };
  walk(api);
  return found;
}

/**
 * Each declared problem type paired with the status the document states for it. Read from
 * the example's own `status` member, not from the response key: the conventional responses
 * live in components.responses behind a $ref, so walking operations alone found 9 of 14.
 */
function declaredWithStatus(): [string, number][] {
  const pairs = new Map<string, number>();
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const { type, status } = node as { type?: unknown; status?: unknown };
    if (typeof type === 'string' && type.includes('/problems/') && typeof status === 'number') {
      pairs.set(type.slice(type.lastIndexOf('/') + 1), status);
    }
    Object.values(node).forEach(walk);
  };
  walk(api);
  return [...pairs];
}

describe('every problem type the API declares is documented', () => {
  const declared = declaredTypes();

  it('the document declares some, so the comparisons below cannot pass vacuously', () => {
    expect(declared.size).toBeGreaterThan(10);
  });

  it.each([...declared])('%s has a documentation entry', (type) => {
    expect(Object.keys(docs), `${type} dereferences to nothing`).toContain(type);
  });

  // ADR-0008 §3 names two convention-owned types. One of them is raised before the store by
  // ADR-0011 and so appears in no operation here, which is why coverage is not symmetric.
  it.each(Object.keys(docs))('%s is declared by the document or owned by a convention', (type) => {
    if (declared.has(type)) return;
    expect(docs[type]!.owner).toBe('convention');
  });

  // Read back out of the document rather than compared to PROBLEM_TYPES, which maps only
  // the seven mcperr-derived types: the other eight statuses would have gone unchecked, and
  // a page advertising a status the API does not return is worse than no page.
  it.each([...declaredWithStatus()])(
    '%s is documented with the status the document returns it under',
    (type, status) => {
      expect(docs[type]!.status).toBe(status);
    },
  );

  // §2's rewrite map keeps MCP vocabulary off the HTTP surface, and card .7 carries an AC
  // forbidding it in any problem example. mcperr's own nextCall strings would violate both,
  // which is why this prose is written for HTTP rather than copied from there.
  it.each(Object.entries(docs))('%s names no MCP tool or environment variable', (_type, entry) => {
    const prose = `${entry.cause} ${entry.remedy}`;
    expect(prose).not.toMatch(/HDF_MCP_|\bhdf_[a-z]+/);
  });
});

describe('the problem-type table refuses a malformed entry', () => {
  const broken: [string, string, string][] = [
    ['a missing field', 'x:\n  status: 404\n  owner: taxonomy\n  cause: c\n', 'expected cause,owner,remedy,status'],
    ['a status outside 4xx/5xx', 'x:\n  status: 204\n  owner: taxonomy\n  cause: c\n  remedy: r\n', 'not a 4xx or 5xx'],
    ['an unknown owner', 'x:\n  status: 404\n  owner: nobody\n  cause: c\n  remedy: r\n', 'has owner nobody'],
    ['empty prose', 'x:\n  status: 404\n  owner: taxonomy\n  cause: "  "\n  remedy: r\n', 'has no cause'],
    ['a list instead of a mapping', '- one\n- two\n', 'did not parse to a mapping'],
    ['an entry that is not a mapping', 'x: 3\n', 'x is not a mapping'],
  ];

  it.each(broken)('refuses %s', (_label, yaml, message) => {
    const dir = mkdtempSync(join(tmpdir(), 'hdf-problems-'));
    try {
      const file = join(dir, 'problems.yaml');
      writeFileSync(file, yaml);
      expect(() => loadProblemDocs(file)).toThrow(new RegExp(message));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the shipped table is the one the build published', () => {
    const published = JSON.parse(
      readFileSync(join(new URL('.', import.meta.url).pathname, '..', 'dist', 'problems.json'), 'utf-8'),
    );
    expect(published).toEqual(docs);
  });
});
