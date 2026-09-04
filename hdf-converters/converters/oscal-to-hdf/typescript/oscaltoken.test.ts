import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { oscalToken } from './shared.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** OSCAL's TokenDatatype pattern, transcribed from the vendored schemas. */
const TOKEN = /^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$/u;

// The same table the Go peer reads, so the two implementations are asserted
// against ONE definition. Written after the first cut used Go's unicode.IsDigit
// against this side's \p{N}, which disagreed on superscripts, fractions and
// Roman numerals — a divergence two hand-written lists would never have surfaced.
describe('oscalToken', () => {
  const table = JSON.parse(
    readFileSync(join(__dirname, '..', '..', '..', 'shared', 'oscal-token-cases.json'), 'utf-8'),
  ) as { cases: Array<{ name: string; in: string; want: string }> };

  it('the shared table is populated', () => {
    expect(table.cases.length).toBeGreaterThan(0);
  });

  it.each(table.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const got = oscalToken(c.in);
    expect(got).toBe(c.want);
    if (got !== '') expect(TOKEN.test(got), `${got} is not a valid OSCAL token`).toBe(true);
  });
});
