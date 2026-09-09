import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { convertHdfToXml } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface DivergenceCase {
  name: string;
  tags: string;
  go: [string, string][];
  ts: [string, string][];
  why: string;
}

const CASES = (
  JSON.parse(
    readFileSync(join(__dirname, '..', '..', '..', 'shared', 'xml-divergence-cases.json'), 'utf-8'),
  ) as { cases: DivergenceCase[] }
).cases;

/** The (element name, text) of each child of the first <tags>, in document order.
 * Assumes every row in the table is flat: a nested row would mis-extract here
 * silently and read as a behaviour change, so add rows flat or parse properly. */
function tagSequence(xml: string): [string, string][] {
  const block = /<tags>([\s\S]*?)<\/tags>/.exec(xml)?.[1] ?? '';
  return [...block.matchAll(/<([\w.\-]+)(?:\s+[^>]*)?>([^<]*)<\/\1>/g)].map((m) => [
    m[1] as string,
    m[2] as string,
  ]);
}

// These divergences are documented and deliberate, not latent. Pinning them
// means a change to either language is a test failure rather than a silent
// widening, and it keeps the module doc comment's claim honest.
describe('hdf-to-xml documented Go/TypeScript divergences', () => {
  it('has a populated shared table', () => {
    expect(CASES.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(CASES.map((c) => [c.name, c] as const))('%s still diverges as recorded', (_name, c) => {
    expect(
      c.go,
      'a row that no longer diverges should be deleted, not kept as a passing no-op',
    ).not.toEqual(c.ts);

    const xml = convertHdfToXml(
      `{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,` +
        `"tags":${c.tags},` +
        `"descriptions":[{"label":"default","data":"d"}],` +
        `"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`,
    );
    expect(tagSequence(xml), c.why).toEqual(c.ts);
  });
});
