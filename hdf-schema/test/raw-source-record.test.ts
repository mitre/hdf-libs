import { describe, it, expect, beforeAll } from 'vitest';
import type Ajv2020 from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';
import {
  createAjvWithPrimitives,
  loadSchema,
  createMinimalResult,
  createMinimalResultsDoc,
  createMinimalEvaluatedBaseline,
  createMinimalRequirement,
} from './setup';

type Node = Record<string, unknown>;

const resultSchema = loadSchema('primitives/result.schema.json') as Node;

function defs(schema: Node): Node {
  return (schema.$defs ?? {}) as Node;
}

function properties(node: Node | undefined): Node {
  return ((node?.properties ?? {}) as Node) ?? {};
}

function requirementResult(): Node {
  return defs(resultSchema).Requirement_Result as Node;
}

function rawSourceRecordDef(): Node {
  return defs(resultSchema).Raw_Source_Record as Node;
}

/** A record for the one grype match that produced a result: the shape the
 *  relocation out of `code` writes. */
function validRecord(overrides: Node = {}): Node {
  return {
    content: '{"vulnerability":{"id":"CVE-2022-48174"},"artifact":{"name":"ssl_client"}}',
    encoding: 'utf-8',
    mediaType: 'application/json',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Structure: the record must be a DEFINED member of a result, not something an
// open `additionalProperties` happens to tolerate.
// ---------------------------------------------------------------------------
describe('Requirement_Result.rawSourceRecord — structure', () => {
  it('is declared on Requirement_Result', () => {
    expect(properties(requirementResult())).toHaveProperty('rawSourceRecord');
  });

  it('points at the Raw_Source_Record definition', () => {
    const prop = properties(requirementResult()).rawSourceRecord as Node;
    expect(prop.$ref).toBe('#/$defs/Raw_Source_Record');
  });

  // Draft-07 treats a $ref as REPLACING its schema object, and the shipped Go
  // validator is a draft-07 engine — so a validation keyword beside the $ref
  // would be enforced by ajv and silently ignored by `hdf validate`.
  // Annotations assert nothing and are fine.
  it('puts no validation keyword beside the $ref', () => {
    const prop = properties(requirementResult()).rawSourceRecord as Node;
    const annotations = new Set(['$ref', 'description', '$comment', 'title', 'examples', 'default']);
    expect(Object.keys(prop).filter((k) => !annotations.has(k))).toEqual([]);
  });

  it('is not required — a result need carry no record', () => {
    const required = (requirementResult().required ?? []) as string[];
    expect(required).not.toContain('rawSourceRecord');
  });

  // Closed with additionalProperties, not the house unevaluatedProperties: the
  // definition composes nothing, and the Go validator does not implement
  // unevaluatedProperties — a closure only one validator enforces is no closure.
  it('is closed with additionalProperties: false', () => {
    expect(rawSourceRecordDef().additionalProperties).toBe(false);
    expect(rawSourceRecordDef()).not.toHaveProperty('unevaluatedProperties');
  });

  it('defines exactly content, encoding, mediaType and pointer', () => {
    expect(Object.keys(properties(rawSourceRecordDef())).sort()).toEqual([
      'content',
      'encoding',
      'mediaType',
      'pointer',
    ]);
  });

  it('requires content, encoding and mediaType, but not pointer', () => {
    expect(((rawSourceRecordDef().required ?? []) as string[]).sort()).toEqual([
      'content',
      'encoding',
      'mediaType',
    ]);
  });

  it('admits exactly the two encodings the artifact carriage uses', () => {
    const encoding = properties(rawSourceRecordDef()).encoding as Node;
    expect(encoding.enum).toEqual(['utf-8', 'base64']);
  });

  it('carries examples and a $comment describing them, per the schema convention', () => {
    expect(Array.isArray(rawSourceRecordDef().examples)).toBe(true);
    expect((rawSourceRecordDef().examples as unknown[]).length).toBeGreaterThan(0);
    expect(typeof rawSourceRecordDef().$comment).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// Validation behaviour, compiled through the same $ref chain a consumer sees.
// ---------------------------------------------------------------------------
describe('Requirement_Result.rawSourceRecord — validation', () => {
  let ajv: Ajv2020;
  let validateResult: ValidateFunction;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validateResult = ajv.compile({
      // Derived from the schema's own $id so a version bump does not break this.
      $ref: `${resultSchema.$id as string}#/$defs/Requirement_Result`,
    });
  });

  const expectValid = (doc: unknown) => {
    const ok = validateResult(doc);
    if (!ok) console.error(JSON.stringify(validateResult.errors, null, 2));
    expect(ok).toBe(true);
  };

  it('accepts a result with no record at all', () => {
    expectValid(createMinimalResult());
  });

  it('accepts a utf-8 record', () => {
    expectValid(createMinimalResult({ rawSourceRecord: validRecord() }));
  });

  it('accepts a base64 record, for a source whose bytes are not text', () => {
    expectValid(
      createMinimalResult({
        rawSourceRecord: validRecord({
          content: 'UEsDBBQAAAAIAEVnPF20b/JoHgAAABwAAAAKAAAAYXVkaXQuZnZkbA==',
          encoding: 'base64',
          mediaType: 'application/zip',
        }),
      }),
    );
  });

  it('accepts a pointer locating the record inside the carried artifact', () => {
    expectValid(createMinimalResult({ rawSourceRecord: validRecord({ pointer: '/matches/3' }) }));
  });

  it.each(['content', 'encoding', 'mediaType'])('rejects a record missing %s', (member) => {
    const record = validRecord();
    delete record[member];
    expect(validateResult(createMinimalResult({ rawSourceRecord: record }))).toBe(false);
  });

  // The whole point of a bounded field rather than a passthrough bag: a member
  // nobody defined is a validation error, not silently-carried private data.
  it('rejects a member the schema does not define', () => {
    expect(
      validateResult(createMinimalResult({ rawSourceRecord: validRecord({ rawr: 'nope' }) })),
    ).toBe(false);
  });

  it('rejects an encoding outside the enum', () => {
    expect(
      validateResult(createMinimalResult({ rawSourceRecord: validRecord({ encoding: 'hex' }) })),
    ).toBe(false);
  });

  it('rejects a non-object record', () => {
    expect(validateResult(createMinimalResult({ rawSourceRecord: 'raw bytes' }))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Document level: the record has to survive the ref chain from a whole
// hdf-results document down to a result, or converters cannot emit it.
// ---------------------------------------------------------------------------
describe('rawSourceRecord in a whole hdf-results document', () => {
  let ajv: Ajv2020;
  let validateResults: ValidateFunction;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validateResults = ajv.compile(loadSchema('hdf-results.schema.json'));
  });

  const docWithRecord = (record: unknown) =>
    createMinimalResultsDoc({
      baselines: [
        createMinimalEvaluatedBaseline({
          requirements: [
            createMinimalRequirement({
              results: [createMinimalResult({ rawSourceRecord: record })],
            }),
          ],
        }),
      ],
    });

  it('validates a document whose result carries a record', () => {
    const ok = validateResults(docWithRecord(validRecord()));
    if (!ok) console.error(JSON.stringify(validateResults.errors, null, 2));
    expect(ok).toBe(true);
  });

  it('rejects a document whose record carries an undefined member', () => {
    expect(validateResults(docWithRecord(validRecord({ extra: 1 })))).toBe(false);
  });

  // Each duplicate-id group in the grype corpus carries a DIFFERENT match
  // record per package. Roll-up concatenates results, so a record on the
  // result survives the merge that `code` first-wins would have discarded.
  it('keeps one distinct record per result when a requirement carries several', () => {
    const doc = createMinimalResultsDoc({
      baselines: [
        createMinimalEvaluatedBaseline({
          requirements: [
            createMinimalRequirement({
              results: [
                createMinimalResult({
                  rawSourceRecord: validRecord({ content: '{"artifact":{"name":"busybox"}}' }),
                }),
                createMinimalResult({
                  rawSourceRecord: validRecord({ content: '{"artifact":{"name":"ssl_client"}}' }),
                }),
              ],
            }),
          ],
        }),
      ],
    });
    const ok = validateResults(doc);
    if (!ok) console.error(JSON.stringify(validateResults.errors, null, 2));
    expect(ok).toBe(true);
  });
});
