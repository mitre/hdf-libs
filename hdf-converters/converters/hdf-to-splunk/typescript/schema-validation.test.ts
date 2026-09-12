import { describe, it, expect } from 'vitest';
import { resultsCorpus, runSchemaCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToSplunk } from './converter.js';

// NO PUBLISHED SCHEMA. Searched 2026-09-11: Splunk documents the HTTP Event Collector event envelope in prose and publishes no JSON Schema for it; the payload under `event` is explicitly free-form, so there is nothing a document schema could constrain.
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

describe('Splunk adversarial corpus', () => {
  it('satisfies every contract for every case', async () => {
    const cases = resultsCorpus();
    expect(cases.length, 'an empty corpus would pass vacuously').toBeGreaterThan(0);
    await runSchemaCorpus(ndjsonObjects, cases, (input) => convertHdfToSplunk(input, '1.0.0'));
  });
});
