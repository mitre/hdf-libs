import { describe, it, expect } from 'vitest';
import { resultsCorpus, runSchemaCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToEcs } from './converter.js';

// NO PUBLISHED SCHEMA. Confirmed independently 2026-09-11: elastic/ecs publishes ecs_flat.yml and ecs_nested.yml (field definitions), Elasticsearch index templates (mappings), fields.csv and Beats fields.ecs.yml. None is a JSON Schema; ECS conformance is enforced by index mappings, so there is no document schema to validate an event against.
//
// What remains checkable is that every emitted line is a JSON object, which the
// NDJSON contract requires. A no-op validator would make every MustConvert
// contract pass vacuously. Mirrors the Go peer.
const ndjsonObjects = (doc: unknown): string | null => {
  const text = typeof doc === 'string' ? doc : '';
  if (text === '') return null;
  const lines = text.trim().split('\n');
  for (const [i, line] of lines.entries()) {
    if (line === '') continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch (e) {
      return `line ${i + 1} is not JSON: ${(e as Error).message}`;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return `line ${i + 1} is not a JSON object`;
    }
  }
  return null;
};

describe('ECS adversarial corpus', () => {
  it('satisfies every contract for every case', async () => {
    const cases = resultsCorpus();
    expect(cases.length, 'an empty corpus would pass vacuously').toBeGreaterThan(0);
    await runSchemaCorpus(ndjsonObjects, cases, (input) => convertHdfToEcs(input, '1.0.0'));
  });
});
