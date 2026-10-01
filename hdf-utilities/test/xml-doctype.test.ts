import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  containsXmlDoctype,
  containsXmlEntityDeclarations,
  inspectXmlPrologue,
} from '../src/xml/index.js';

interface DoctypeCase {
  name: string;
  xml: string;
  leadingCommentBytes?: number;
  doctype: boolean;
  entity: boolean;
  externalId: boolean;
  malformed: boolean;
  why: string;
}

const table = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'xml-doctype-cases.json'),
    'utf-8',
  ),
) as { cases: DoctypeCase[] };

/**
 * Builds the case's input, expanding leadingCommentBytes into a prologue comment so a
 * case can exceed any fixed scan window without embedding the filler in the table.
 */
function document(c: DoctypeCase): string {
  return c.leadingCommentBytes ? `<!--${'x'.repeat(c.leadingCommentBytes)}-->${c.xml}` : c.xml;
}

describe('XML prologue declaration detectors', () => {
  // The same table the Go suite reads, so the two languages cannot drift.
  it('reads a non-empty shared case table', () => {
    expect(table.cases.length).toBeGreaterThan(0);
  });

  // The inspector reports the three facts separately; the POLICY over them is the
  // consumer's. This is the test that pins all three at once.
  describe('inspectXmlPrologue — shared table', () => {
    it.each(table.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
      expect(inspectXmlPrologue(document(c)), c.why).toEqual({
        hasDoctype: c.doctype,
        hasEntityDecl: c.entity,
        hasExternalId: c.externalId,
        malformed: c.malformed,
      });
    });
  });

  describe('containsXmlDoctype — shared table', () => {
    it.each(table.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
      expect(containsXmlDoctype(document(c)), c.why).toBe(c.doctype);
    });
  });

  describe('containsXmlEntityDeclarations — shared table', () => {
    it.each(table.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
      expect(containsXmlEntityDeclarations(document(c)), c.why).toBe(c.entity);
    });
  });

  // The prologue has no length bound, so the scan must not have one either — the
  // regression the Go side's fixed 4 KB window allowed.
  it.each([4000, 4096, 4097, 100_000])(
    'finds a declaration after %i bytes of leading comment',
    (pad) => {
      const filler = 'x'.repeat(pad);
      expect(containsXmlDoctype(`<!--${filler}--><!DOCTYPE note><note/>`)).toBe(true);
      expect(
        containsXmlEntityDeclarations(`<!--${filler}--><!DOCTYPE n [<!ENTITY e "v">]><n/>`),
      ).toBe(true);
    },
  );

  // Unbounded scanning must still terminate on adversarial input.
  it.each(['<!--', '<?', '<!', '<', '<!DOCTYPE', '<?xml', '<!--a-->'.repeat(10_000)])(
    'terminates on malformed prologue %#',
    (doc) => {
      expect(() => containsXmlDoctype(doc)).not.toThrow();
      expect(() => containsXmlEntityDeclarations(doc)).not.toThrow();
    },
  );
});
