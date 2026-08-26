import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { load, detectFormat } from '../src/loader.js';

// Shared cross-language fixtures (also read by go/loader_test.go and the Go
// parity test), so both loader cores run the same input.
const testdata = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata');
const read = (name: string): string => readFileSync(join(testdata, name), 'utf-8');

describe('load — parity with go/loader.go Load', () => {
  it('loads a valid results document', () => {
    const res = load(read('query-fixture.json'));
    expect(res.format).toBe('json');
    expect(res.docType).toBe('results');
    expect(res.valid).toBe(true);
    expect(res.results).toBeDefined();
    expect(res.baseline).toBeUndefined();
  });

  it('loads a valid baseline document', () => {
    const res = load(read('baseline-fixture.json'));
    expect(res.docType).toBe('baseline');
    expect(res.valid).toBe(true);
    expect(res.baseline).toBeDefined();
    expect(res.results).toBeUndefined();
  });

  it('runs the size guard FIRST (throws before parse)', () => {
    expect(() => load('this is not json and is over the tiny limit', 4)).toThrow(/exceeds maximum/);
  });

  it('detects NDJSON input', () => {
    expect(load('{"a":1}\n{"b":2}\n').format).toBe('ndjson');
  });

  it('a pretty-printed single object is json, not ndjson', () => {
    expect(load(read('query-fixture.json')).format).toBe('json');
  });

  it('invalid results reports parseError, not a throw', () => {
    const res = load('{"baselines": "not an array", "components": [], "statistics": {}}');
    expect(res.docType).toBe('results');
    expect(res.valid).toBe(false);
    expect(res.parseError).toBeTruthy();
  });

  it('unknown type: empty docType, not valid, no parseError', () => {
    const res = load('{"unrecognized": true}');
    expect(res.docType).toBe('');
    expect(res.valid).toBe(false);
    expect(res.parseError).toBeUndefined();
  });

  it('non-JSON: empty docType, format json (single line)', () => {
    const res = load('not json at all');
    expect(res.docType).toBe('');
    expect(res.format).toBe('json');
  });
});

// Mirror of go/loader_parity_test.go TestLoader_CrossLanguageParity: the SAME
// shared fixtures asserted to the SAME (format, docType, valid) on the TS side.
describe('cross-language parity (mirror of go/loader_parity_test.go)', () => {
  const cases: { fixture: string; format: string; docType: string; valid: boolean }[] = [
    { fixture: 'query-fixture.json', format: 'json', docType: 'results', valid: true },
    { fixture: 'baseline-fixture.json', format: 'json', docType: 'baseline', valid: true },
  ];
  for (const c of cases) {
    it(c.fixture, () => {
      const res = load(read(c.fixture));
      expect(res.format).toBe(c.format);
      expect(res.docType).toBe(c.docType);
      expect(res.valid).toBe(c.valid);
    });
  }
});

describe('detectFormat', () => {
  it('single object → json', () => {
    expect(detectFormat('{"a":1}')).toBe('json');
  });
  it('two JSON lines → ndjson', () => {
    expect(detectFormat('{"a":1}\n{"b":2}')).toBe('ndjson');
  });
  it('blank input → json', () => {
    expect(detectFormat('')).toBe('json');
  });
});
