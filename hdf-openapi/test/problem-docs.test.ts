import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { PROBLEM_BASE, loadProblemDocs, problemTypes } from '../src/problems.js';

const docs = loadProblemDocs();

/**
 * The problem-type table, after the reference API moved to the sibling repository.
 *
 * What it can no longer check: that the table covers every type an API declares. That
 * needed a document with operations in it, and the operations are the sibling's now — so
 * the coverage direction is asserted there, against its own document. Recorded here so the
 * next reader does not take this file's silence for the absence of the question.
 *
 * What it still checks is what makes the table usable: the shape of every entry, agreement
 * with ADR-0010 §6 where an entry names a code, prose written for HTTP rather than for the
 * MCP, and that the published JSON is the table the build produced.
 */
describe('the problem-type table is well formed and HTTP-facing', () => {
  it('there are entries to check', () => {
    expect(Object.keys(docs).length).toBeGreaterThan(10);
  });

  it.each(Object.entries(docs))('%s carries a hosted type URI that is its own key', (type) => {
    expect(`${PROBLEM_BASE}/${type}`).toMatch(/^https:\/\/mitre\.github\.io\/hdf-libs\/problems\/[a-z][a-z0-9-]*$/);
  });

  it.each(Object.entries(docs))('%s declares an owner the vocabulary admits', (_type, entry) => {
    expect(['taxonomy', 'convention', 'service']).toContain(entry.owner);
  });

  // An entry naming a code is making a claim about ADR-0010 §6, which test/problem-types.test.ts
  // checks against the ADR text. Here we only assert the two views agree with each other.
  it('every coded entry appears in the derived mapping with the same status', () => {
    const mapping = problemTypes();
    const coded = Object.entries(docs).filter(([, entry]) => entry.code !== undefined);
    expect(coded.length).toBeGreaterThan(5);
    for (const [type, entry] of coded) {
      expect(mapping[entry.code!]).toEqual({ status: entry.status, type });
    }
  });

  // §2's rewrite map kept MCP vocabulary off the HTTP surface, and this prose is the last
  // of that surface left in this repository. mcperr's own recovery strings name tools and
  // HDF_MCP_ROOT, which is why this prose was written separately rather than copied.
  it.each(Object.entries(docs))('%s names no MCP tool or environment variable', (_type, entry) => {
    expect(`${entry.cause} ${entry.remedy} ${entry.title}`).not.toMatch(/HDF_MCP_|\bhdf_[a-z]+/);
  });
});

describe('the problem-type table refuses a malformed entry', () => {
  const broken: [string, string, string][] = [
    ['a missing field', 'x:\n  title: T\n  status: 404\n  owner: taxonomy\n  cause: c\n', 'expected cause,owner,remedy,status,title'],
    ['a status outside 4xx/5xx', 'x:\n  title: T\n  status: 204\n  owner: taxonomy\n  cause: c\n  remedy: r\n', 'not a 4xx or 5xx'],
    ['an unknown owner', 'x:\n  title: T\n  status: 404\n  owner: nobody\n  cause: c\n  remedy: r\n', 'has owner nobody'],
    ['empty prose', 'x:\n  title: T\n  status: 404\n  owner: taxonomy\n  cause: "  "\n  remedy: r\n', 'has no cause'],
    ['a list instead of a mapping', '- one\n- two\n', 'did not parse to a mapping'],
    ['an entry that is not a mapping', 'x: 3\n', 'x is not a mapping'],
    // The key becomes a path segment in the site generator, so its SHAPE is as
    // load-bearing as its contents. Every value was validated here and the key was not.
    ['a traversal key', '../../etc/x:\n  title: T\n  status: 404\n  owner: taxonomy\n  cause: c\n  remedy: r\n', 'is not a problem type name'],
    ['an absolute key', '/etc/x:\n  title: T\n  status: 404\n  owner: taxonomy\n  cause: c\n  remedy: r\n', 'is not a problem type name'],
    ['a key that is not kebab-case', 'Not_Kebab:\n  title: T\n  status: 404\n  owner: taxonomy\n  cause: c\n  remedy: r\n', 'is not a problem type name'],
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
      readFileSync(join(fileURLToPath(new URL('.', import.meta.url)), '..', 'dist', 'problems.json'), 'utf-8'),
    );
    expect(published).toEqual(docs);
  });
});
