import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertConveyorToHdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Starts from the real capture and overrides only the two numeric fields under
// test, so the document stays real-shaped. Conveyor is access-gated, so whether
// it can emit a non-integral depth or score cannot be confirmed from here —
// both sides render the value as given, which is right either way.
function documentWithNonIntegralNumbers(): string {
  const doc = JSON.parse(
    readFileSync(join(__dirname, '..', 'fixtures', 'input', 'sample-results.json'), 'utf-8'),
  ) as Record<string, never>;
  const results = (doc as Record<string, Record<string, Record<string, never>>>).api_response
    .results;
  for (const key of Object.keys(results)) {
    const sections = (results[key] as Record<string, Record<string, unknown[]>>).result?.sections;
    if (!Array.isArray(sections) || sections.length === 0) continue;
    const s = sections[0] as Record<string, unknown>;
    s.depth = 2.5;
    if (s.heuristic) (s.heuristic as Record<string, unknown>).score = 137.5;
    break;
  }
  return JSON.stringify(doc);
}

// The Go peer asserts these same strings on the same override.
describe('conveyor-to-hdf renders numbers losslessly, matching Go', () => {
  it('keeps a non-integral depth and heuristic score intact', async () => {
    const out = await convertConveyorToHdf(documentWithNonIntegralNumbers(), '1.0.0');
    expect(out).toContain('depth:2.5');
    expect(out).toContain('heuristic_score:137.5');
  });
});
