/**
 * Pins validateXmlInput to Go's shared.ValidateXMLInput: both suites read
 * ../testdata/xml-input-gate-cases.json, so the two gates refuse the same inputs
 * with the same words.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateXmlInput } from './converterutil.js';

interface XmlGateCase {
  name: string;
  xml: string;
  leadingCommentBytes?: number;
  maxSize?: number;
  error: string;
  why: string;
}

const table = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'xml-input-gate-cases.json'),
    'utf-8',
  ),
) as { cases: XmlGateCase[] };

function document(c: XmlGateCase): string {
  return c.leadingCommentBytes ? `<!--${'x'.repeat(c.leadingCommentBytes)}-->${c.xml}` : c.xml;
}

describe('validateXmlInput matches the Go gate', () => {
  it('reads a non-empty shared table', () => {
    expect(table.cases.length).toBeGreaterThan(0);
  });

  it.each(table.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const run = () => validateXmlInput(document(c), 'test', c.maxSize ?? 0);
    if (c.error === '') {
      expect(run, c.why).not.toThrow();
    } else {
      expect(run, c.why).toThrow(new Error(`test: ${c.error}`));
    }
  });
});
