import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { PROBLEM_TYPES, UNMAPPED_CODES } from '../src/generate-api.js';

const ADR = join(
  new URL('.', import.meta.url).pathname,
  '..',
  '..',
  'dev-docs',
  'adr-0010-hdf-data-access-layer.md',
);

/**
 * ADR-0010 §6 is the single mapping, and it says so: "a test in `hdf-openapi` and one here
 * assert agreement". This is that test.
 *
 * It PARSES the table rather than restating it. A test that compared the generator's
 * constant to a list written beside it would track the constant instead of checking it —
 * it would pass unchanged if the ADR were revised tomorrow, which is exactly the kind of
 * guard this repo has been bitten by.
 */
function parseAdrTable(): Map<string, { status: string; type: string }> {
  const rows = new Map<string, { status: string; type: string }>();
  for (const line of readFileSync(ADR, 'utf-8').split('\n')) {
    if (!line.startsWith('| `')) continue;
    const cells = line.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
    if (cells.length < 4) continue;
    const [codeCell, , statusCell, typeCell] = cells;
    for (const code of codeCell!.matchAll(/`([A-Z_]+)`/g)) {
      rows.set(code[1]!, { status: statusCell!, type: typeCell! });
    }
  }
  return rows;
}

describe('the problem-type table agrees with ADR-0010 §6', () => {
  const adr = parseAdrTable();

  it('parsed the table, so the comparisons below cannot pass vacuously', () => {
    expect(adr.size).toBeGreaterThan(15);
    expect(adr.has('DOCUMENT_NOT_FOUND')).toBe(true);
  });

  it.each([...Object.entries(PROBLEM_TYPES)])(
    '%s maps to the status and type the ADR gives it',
    (code, mapping) => {
      const row = adr.get(code);
      expect(row, `${code} has no row in ADR-0010 §6`).toBeDefined();
      // The status cell may carry an aside, e.g. "422 (+ `errors[]`)" or "503 (`Retry-After`)".
      expect(row!.status).toMatch(new RegExp(`^${mapping.status}\\b`));
      // §6 states the type is the hosted prefix plus the kebab-cased code, and writes
      // `<kebab-code>` where two codes share a row.
      const expected = row!.type.includes('<kebab-code>')
        ? code.toLowerCase().replace(/_/g, '-')
        : row!.type.replace(/^.*problems\//, '').replace(/`.*$/, '').trim();
      expect(mapping.type).toBe(expected);
    },
  );

  it('every code the ADR gives an HTTP status is mapped, and no other', () => {
    const withStatus = [...adr.entries()]
      .filter(([, r]) => /^\d{3}/.test(r.status))
      .map(([code]) => code);
    const contract = JSON.parse(
      readFileSync(join(new URL('.', import.meta.url).pathname, '..', 'src', 'mcp-contract.golden.json'), 'utf-8'),
    ) as { errorCodes: string[] };
    // Scoped to what the contract actually carries: §6 also covers codes this generator
    // never sees, which belong to the data layer rather than the MCP surface.
    const relevant = withStatus.filter((c) => contract.errorCodes.includes(c)).sort();
    expect(Object.keys(PROBLEM_TYPES).sort()).toEqual(relevant);
  });

  it('every unmapped code is one the ADR marks as never reaching HTTP', () => {
    for (const code of UNMAPPED_CODES) {
      const row = adr.get(code);
      expect(row, `${code} has no row in ADR-0010 §6`).toBeDefined();
      expect(row!.status).toMatch(/never/);
    }
  });
});
