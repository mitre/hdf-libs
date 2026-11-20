import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CANDIDATE_SCHEMA,
  CandidateFaultCode,
  UnadjudicatedError,
  resolveNistFromCandidates,
  validateCandidates,
  type CandidateCorpus,
} from '../src/control-mapping/index.js';

// The Go peer (go/controlmapping/validate_test.go) asserts this same table,
// which is what keeps the two validators refusing the same documents.
interface ValidationCase {
  name: string;
  codes: string[];
  why: string;
  doc?: unknown;
  raw?: string;
}

// The bytes to validate: a case carries either a JSON value or, for documents
// no JSON value can express, the literal text.
const documentOf = (c: ValidationCase): string => c.raw ?? JSON.stringify(c.doc);

const casesPath = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'go',
  'controlmapping',
  'testdata',
  'candidate-validation-cases.json'
);
const { cases } = JSON.parse(readFileSync(casesPath, 'utf-8')) as { cases: ValidationCase[] };

const codesOf = (faults: { code: string }[]): string[] => [...new Set(faults.map((f) => f.code))].sort();

const caseNamed = (name: string): ValidationCase => {
  const found = cases.find((c) => c.name === name);
  if (found === undefined) {
    throw new Error(`shared table has no ${name} case`);
  }
  return found;
};

const corpusOf = (name: string): CandidateCorpus => {
  const { corpus, faults } = validateCandidates(documentOf(caseNamed(name)));
  expect(faults).toEqual([]);
  if (corpus === undefined) {
    throw new Error(`${name} was accepted but returned no corpus`);
  }
  return corpus;
};

describe('candidate corpus validation (shared case table)', () => {
  it('has cases, each with a unique name', () => {
    expect(cases.length).toBeGreaterThan(0);
    expect(new Set(cases.map((c) => c.name)).size).toBe(cases.length);
  });

  it.each(cases.map((c) => [c.name, c.codes, c.why] as const))(
    'refuses %s with %j',
    (name, codes, why) => {
      const { corpus, faults } = validateCandidates(documentOf(caseNamed(name)));
      expect(codesOf(faults), why).toEqual([...codes].sort());

      // Ingestion is all-or-nothing per corpus: one fault refuses the whole
      // import, because a partial import leaves adjudication running against
      // an unknown subset.
      if (codes.length === 0) {
        expect(corpus, why).toBeDefined();
      } else {
        expect(corpus, why).toBeUndefined();
      }
    }
  );

  it.each(cases.filter((c) => c.codes.length > 0).map((c) => [c.name] as const))(
    'every fault from %s carries a path',
    (name) => {
      const { faults } = validateCandidates(documentOf(caseNamed(name)));
      for (const fault of faults) {
        // A whole-document fault has no member to name; every other fault
        // must point at the record at fault.
        if (fault.code === CandidateFaultCode.DocumentUnparseable) {
          continue;
        }
        expect(fault.path, fault.code).not.toBe('');
      }
    }
  );
});

describe('candidate corpus validation', () => {
  it('refuses malformed JSON', () => {
    const { corpus, faults } = validateCandidates('{not json');
    expect(faults.length).toBeGreaterThan(0);
    expect(corpus).toBeUndefined();
  });

  it('refuses a document that is not an object', () => {
    const { corpus, faults } = validateCandidates('[]');
    expect(faults.map((f) => f.code)).toEqual(['document_unparseable']);
    expect(corpus).toBeUndefined();
  });

  it('accepts only its own schema literal', () => {
    expect(CANDIDATE_SCHEMA).toBe('control-mapping-candidates/v1');
  });

  it('preserves the scanner, catalog and scored candidates it accepted', () => {
    const corpus = corpusOf('valid-minimal');
    expect(corpus.scanner).toEqual({ name: 'kics', version: 'v2.1.20', checks: 1 });
    expect(corpus.catalog.revision).toBe(5);
    expect(corpus.catalog.pinnedCommit).not.toBe('');

    const candidates = corpus.checks.get('a1bc27c6-7115-48d8-bf9d-5a7e836845ba')?.candidates;
    expect(candidates).toHaveLength(2);
    expect(candidates?.[0].control).toBe('SA-10.4');
    expect(candidates?.[0].score).toBe(1.0);
    // The sub-part granularity the CWE table cannot express at all.
    expect(candidates?.[1].control).toBe('SA-15 a');
  });

  it('carries both upstream and canonical spellings of every control id', () => {
    const candidates = corpusOf('valid-minimal').checks.get('a1bc27c6-7115-48d8-bf9d-5a7e836845ba')
      ?.candidates;
    expect(candidates?.[0].normalizedControl).toBe('SA-10 04');
    expect(candidates?.[1].normalizedControl).toBe('SA-15 a');
  });
});

// The gate. A scored candidate is a review queue, not a mapping: nothing here
// turns one into a tags.nist value, and the refusal is explicit so a caller
// cannot mistake an empty result for "no controls apply".
describe('the unadjudicated gate', () => {
  it.each([['a1bc27c6-7115-48d8-bf9d-5a7e836845ba'], ['absent-check']])(
    'refuses to resolve %s into NIST controls',
    (checkId) => {
      const corpus = corpusOf('valid-minimal');
      expect(() => resolveNistFromCandidates(corpus, checkId)).toThrow(UnadjudicatedError);
    }
  );
});

// The contract document states the shape; the validator enforces it. This
// asserts they agree: every property candidate-schema.json marks required is a
// property whose absence the validator actually refuses. Adding a required
// field to the schema extends this test on its own.
describe('contract schema and validator agree on required properties', () => {
  interface JsonObject {
    [key: string]: unknown;
  }

  const schemaPath = join(
    dirname(fileURLToPath(import.meta.url)),
    '..',
    'go',
    'controlmapping',
    'candidate-schema.json'
  );
  const schema = JSON.parse(readFileSync(schemaPath, 'utf-8')) as JsonObject;

  const object = (parent: JsonObject, key: string): JsonObject => {
    const child = parent[key];
    if (child === undefined || typeof child !== 'object' || child === null) {
      throw new Error(`contract schema has no object at ${key}`);
    }
    return child as JsonObject;
  };

  const requiredList = (node: JsonObject, where: string): string[] => {
    const list = node.required;
    if (!Array.isArray(list)) {
      throw new Error(`contract schema declares no required list at ${where}`);
    }
    return list as string[];
  };

  const eachCheck = (doc: JsonObject, fn: (check: JsonObject) => void): void => {
    for (const check of Object.values(object(doc, 'checks'))) {
      fn(check as JsonObject);
    }
  };

  const props = object(schema, 'properties');
  const checkSchema = object(object(props, 'checks'), 'additionalProperties');
  const candidateSchema = object(object(object(checkSchema, 'properties'), 'candidates'), 'items');

  type Mutate = (doc: JsonObject, nullify: boolean) => void;

  // Both mutations must be refused: a null read as absence suppresses the
  // property's own missing fault.
  const drop = (parent: JsonObject, key: string, nullify: boolean): void => {
    if (nullify) {
      parent[key] = null;
    } else {
      delete parent[key];
    }
  };

  const sites: [string, Mutate][] = [
    ...requiredList(schema, '(root)').map(
      (field): [string, Mutate] => [`/${field}`, (doc, nullify) => drop(doc, field, nullify)]
    ),
    ...(['catalog', 'scanner'] as const).flatMap((section) =>
      requiredList(object(props, section), section).map(
        (field): [string, Mutate] => [
          `/${section}/${field}`,
          (doc, nullify) => drop(object(doc, section), field, nullify),
        ]
      )
    ),
    ...requiredList(checkSchema, 'checks.additionalProperties').map(
      (field): [string, Mutate] => [
        `/checks/*/${field}`,
        (doc, nullify) => {
          eachCheck(doc, (check) => drop(check, field, nullify));
        },
      ]
    ),
    ...requiredList(candidateSchema, 'candidates.items').map(
      (field): [string, Mutate] => [
        `/checks/*/candidates/*/${field}`,
        (doc, nullify) => {
          eachCheck(doc, (check) => {
            for (const candidate of (check.candidates ?? []) as JsonObject[]) {
              drop(candidate, field, nullify);
            }
          });
        },
      ]
    ),
  ];

  it('finds required properties to check', () => {
    expect(sites.length).toBeGreaterThan(0);
  });

  // The mutator comes last so the subtest title names the site and the mode
  // rather than interpolating the function's source.
  const mutations = sites.flatMap(([where, mutate]): [string, string, boolean, Mutate][] => [
    [where, 'deleted', false, mutate],
    [where, 'nulled', true, mutate],
  ]);

  it.each(mutations)('refuses a document with %s %s', (where, lost, nullify, mutate) => {
    const doc = JSON.parse(JSON.stringify(caseNamed('valid-minimal').doc)) as JsonObject;
    mutate(doc, nullify);
    const { corpus, faults } = validateCandidates(JSON.stringify(doc));
    expect(
      faults.length,
      `schema requires ${where} but the validator accepted a document ${lost}`
    ).toBeGreaterThan(0);
    expect(corpus).toBeUndefined();
  });
});

// Everything an adjudicator needs besides the control and its score must
// survive ingestion. Without this, deleting the handling for any of these
// members fails no test.
describe('an accepted corpus carries the adjudication fields', () => {
  const check = (): NonNullable<ReturnType<CandidateCorpus['checks']['get']>> => {
    const corpus = corpusOf('valid-full');
    const found = corpus.checks.get('a1bc27c6-7115-48d8-bf9d-5a7e836845ba');
    if (found === undefined) {
      throw new Error('the real upstream check is not retrievable');
    }
    return found;
  };

  it('carries the scanner check metadata', () => {
    expect(check()).toMatchObject({
      queryName: 'Run Using apt',
      platform: 'Buildah',
      cwe: '1188',
      category: 'Supply-Chain',
    });
  });

  it('carries each candidate title and what the match drew on', () => {
    expect(check().candidates[0].controlTitle).toBe('Trusted Generation');
    expect(check().candidates[0].matchedOn).toEqual(['statement', 'objective', 'guidance']);
  });
});
