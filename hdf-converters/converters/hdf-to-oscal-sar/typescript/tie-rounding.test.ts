import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { convertHdfToOscalSar } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'tie-rounding.json'), 'utf-8');

// The Go peer asserts this same string on this same fixture. Impact 0.25 ties at
// one decimal, where toFixed rounds away from zero and Go's fmt rounds to even.
describe('hdf-to-oscal-sar renders exact ties the way Go now does', () => {
  it('rounds impact 0.25 to 0.3 at one decimal', async () => {
    const out = await convertHdfToOscalSar(input);
    expect(out).toContain('Impact: 0.3 (');
    expect(out).not.toContain('Impact: 0.2 (');
  });
});
