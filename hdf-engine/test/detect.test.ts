import { describe, it, expect } from 'vitest';
import {
  hdfResultsSchema,
  hdfBaselineSchema,
  hdfSystemSchema,
  hdfPlanSchema,
  hdfAmendmentsSchema,
  hdfEvidencePackageSchema,
  hdfRequirementChangeEventSchema,
} from '@mitre/hdf-schema';
import {
  validateResults,
  validateBaseline,
  validateSystem,
  validatePlan,
  validateAmendments,
  validateEvidencePackage,
  validateComparison,
  validateRequirementChangeEvent,
} from '@mitre/hdf-validators';
import { detect, type HdfDocType } from '../src/index.js';

// Minimal valid comparison document — the comparison schema carries no
// top-level example; mirrors go/detect_test.go minimalComparison and
// hdf-schema/test/setup.ts createMinimalComparisonDoc.
const minimalComparison = {
  formatVersion: '1.0.0',
  comparisonMode: 'temporal',
  sources: [
    { role: 'old', label: 'Before scan' },
    { role: 'new', label: 'After scan' },
  ],
  summary: { total: 0, matchedCount: 0, unmatchedOldCount: 0, unmatchedNewCount: 0 },
  requirementDiffs: [],
};

// example pulls the first top-level example from a bundled schema object and
// strips the "$comment" annotation (documentation metadata, not part of the
// document). This is the SAME schema-example source the Go parity test reads
// via validators.SchemaBytes — the two implementations share one contract.
function example(schema: unknown): Record<string, unknown> {
  const ex = (schema as { examples?: unknown[] }).examples?.[0];
  if (!ex || typeof ex !== 'object') {
    throw new Error('schema carries no top-level example');
  }
  const doc = { ...(ex as Record<string, unknown>) };
  delete doc['$comment'];
  return doc;
}

interface ParityCase {
  name: Exclude<HdfDocType, ''>;
  doc: Record<string, unknown>;
  validate: (data: unknown) => { valid: boolean };
}

const cases: ParityCase[] = [
  { name: 'results', doc: example(hdfResultsSchema), validate: validateResults },
  { name: 'baseline', doc: example(hdfBaselineSchema), validate: validateBaseline },
  { name: 'system', doc: example(hdfSystemSchema), validate: validateSystem },
  { name: 'plan', doc: example(hdfPlanSchema), validate: validatePlan },
  { name: 'amendments', doc: example(hdfAmendmentsSchema), validate: validateAmendments },
  { name: 'evidence-package', doc: example(hdfEvidencePackageSchema), validate: validateEvidencePackage },
  { name: 'requirement-change-event', doc: example(hdfRequirementChangeEventSchema), validate: validateRequirementChangeEvent },
  { name: 'comparison', doc: minimalComparison, validate: validateComparison },
];

describe('hdf-engine detect — cross-language parity with go/detect.go', () => {
  for (const c of cases) {
    it(`classifies ${c.name} from a schema-valid document`, () => {
      // Provenance guard: the fixture is a real, schema-valid document.
      expect(c.validate(c.doc).valid, `fixture for ${c.name} must be schema-valid`).toBe(true);
      // The assertion under test: detection resolves to the correct type.
      expect(detect(JSON.stringify(c.doc))).toBe(c.name);
    });
  }

  it('resolves overlapping discriminators in the fixed precedence order', () => {
    // Load-bearing parity with Go: a real results doc carries both baselines and
    // components, and the change-event quad must win over any other key.
    expect(detect('{"baselines":[],"components":[]}')).toBe('results');
    expect(detect('{"requirementId":"x","state":"updated","before":{},"after":{},"baselines":[]}')).toBe(
      'requirement-change-event',
    );
    expect(detect('{"contents":[],"baselines":[]}')).toBe('evidence-package');
    expect(detect('{"overrides":[],"requirements":[]}')).toBe('amendments');
  });

  it('returns "" for non-object, invalid, or unknown input', () => {
    expect(detect('{}')).toBe('');
    expect(detect('not json')).toBe('');
    expect(detect('{"foo":"bar"}')).toBe('');
    expect(detect('[]')).toBe('');
    expect(detect('"a string"')).toBe('');
  });
});
