import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  validate, validateResults, validateBaseline, validateSystem, validatePlan,
  validateAmendments, validateComparison, validateEvidencePackage,
  validateRequirementChangeEvent,
} from './index.js';

const validators = {
  results: validateResults,
  baseline: validateBaseline,
  system: validateSystem,
  plan: validatePlan,
  amendments: validateAmendments,
  comparison: validateComparison,
  'evidence-package': validateEvidencePackage,
  'requirement-change-event': validateRequirementChangeEvent,
};
interface ConformanceCase {
  name: string;
  type: keyof typeof validators;
  document: string;
  path: (string | number)[];
  properties: Record<string, unknown>;
  valid: boolean;
  keyword?: string;
  field?: string;
}
const table = JSON.parse(readFileSync(
  new URL('../testdata/shipped-schema-conformance-cases.json', import.meta.url), 'utf8',
)) as { documents: Record<string, Record<string, unknown>>; cases: ConformanceCase[] };

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Conformance case must target an object');
  }
  return value as Record<string, unknown>;
}

function documentFor(tc: ConformanceCase): Record<string, unknown> {
  const doc = structuredClone(table.documents[tc.document]);
  let target: unknown = doc;
  for (const key of tc.path) {
    if (typeof key === 'number') {
      if (!Array.isArray(target)) throw new Error('Conformance path must target an array');
      target = target[key];
    } else {
      target = record(target)[key];
    }
  }
  Object.assign(record(target), tc.properties);
  return doc;
}

describe('shipped schema conformance', () => {
  it('covers every modern document validator', () => {
    expect(new Set(table.cases.map(tc => tc.type))).toEqual(new Set(Object.keys(validators)));
  });

  it.each(table.cases.filter(tc => tc.path.length === 0))('auto-detect: $name', tc => {
    const result = validate(documentFor(tc));
    expect(result.valid, result.getErrorMessage()).toBe(tc.valid);
    if (!tc.valid) {
      expect(result.errors).toEqual(expect.arrayContaining([
        expect.objectContaining({ keyword: tc.keyword, field: tc.field }),
      ]));
    }
  });

  it.each([null, 'malformed input', 42, [], {}])('rejects unrecognizable input: %j', value => {
    const result = validate(value);
    expect(result.valid).toBe(false);
    expect(result.errors).not.toHaveLength(0);
    expect(result.getErrorMessage()).not.toBe('');
  });

  it('reports an empty-name undeclared root property without losing the error', () => {
    const doc = { ...structuredClone(table.documents.results), '': true };
    const result = validateResults(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([{
      field: '(root)', keyword: 'unevaluatedProperties',
      message: 'is not allowed', value: doc,
    }]);
    expect(result.getErrorMessage()).toBe('is not allowed');
  });

  it('preserves the offending value and format in a timestamp error', () => {
    const doc = { ...structuredClone(table.documents.results), timestamp: 'not-a-timestamp' };
    const result = validateResults(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({
      field: 'timestamp', keyword: 'format', format: 'date-time', value: 'not-a-timestamp',
    })]);
    expect(result.getErrorMessage()).toContain('timestamp:');
  });

  it('preserves the offending value and keyword in a type error', () => {
    const result = validate({ baselines: 42 });
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({
      field: 'baselines', keyword: 'type', value: 42,
    })]);
    expect(result.getErrorMessage()).toBe('baselines: must be array');
  });

  it.each([{}, { name: 'incomplete baseline' }, { requirements: [] }])(
    'retains results diagnostics when no document type matches: %j', doc => {
      const result = validate(doc);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(expect.arrayContaining([expect.objectContaining({
        field: 'required.baselines', keyword: 'required', message: 'is required', value: doc,
      })]));
      expect(result.getErrorMessage()).toContain('required.baselines: is required');
    },
  );

  it.each(table.cases)('$name', tc => {
    const doc = documentFor(tc);
    const before = structuredClone(doc);
    const result = validators[tc.type](doc);
    expect(result.valid, result.getErrorMessage()).toBe(tc.valid);
    expect(doc).toEqual(before);
    if (!tc.valid) {
      expect(result.errors).toEqual(expect.arrayContaining([
        expect.objectContaining({ keyword: tc.keyword, field: tc.field }),
      ]));
      expect(result.getErrorMessage()).toContain(tc.field);
    }
  });
});
