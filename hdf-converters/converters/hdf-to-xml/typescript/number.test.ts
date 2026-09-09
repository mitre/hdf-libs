import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { convertHdfToXml } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface NumberCase {
  json: string;
  text: string;
  why: string;
}

const CASES = (
  JSON.parse(
    readFileSync(join(__dirname, '..', '..', '..', 'shared', 'xml-number-cases.json'), 'utf-8'),
  ) as { cases: NumberCase[] }
).cases;

/** The document is assembled as raw text: a JS number literal would already have
 * lost the distinction the table is pinning (-0 among them). */
function convert(rawNumber: string): string {
  return convertHdfToXml(
    `{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,` +
      `"tags":{"n":${rawNumber}},` +
      `"descriptions":[{"label":"default","data":"d"}],` +
      `"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`,
  );
}

// Rendering is implemented twice, so the expectations live in one shared file
// both languages read rather than in two hand-kept copies.
describe('hdf-to-xml number rendering', () => {
  it('has a populated shared table', () => {
    expect(CASES.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(CASES.map((c) => [c.json, c] as const))('renders %s like the Go peer', (_json, c) => {
    expect(convert(c.json), c.why).toContain(`<n>${c.text}</n>`);
  });
});
