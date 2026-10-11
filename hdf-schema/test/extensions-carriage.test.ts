import { describe, it, expect, beforeAll } from 'vitest';
import type Ajv2020 from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';
import { createAjvWithPrimitives, loadSchema } from './setup';

type Node = Record<string, unknown>;

// Every document schema that carries a producer envelope (`generator` and/or
// `integrity`) must be able to carry that producer's extension data. The lone
// exclusion is hdf-requirement-change-event, which carries neither: it is an
// entry in an append-only stream, not a produced document.
const ENVELOPE_DOCUMENTS = [
  'hdf-results',
  'hdf-baseline',
  'hdf-comparison',
  'hdf-system',
  'hdf-plan',
  'hdf-amendments',
  'hdf-evidence-package',
] as const;

const STREAM_EVENT_DOCUMENT = 'hdf-requirement-change-event';

const ALL_DOCUMENTS = [...ENVELOPE_DOCUMENTS, STREAM_EVENT_DOCUMENT];

const commonSchema = loadSchema('primitives/common.schema.json') as Node;
const extensionsSchema = loadSchema('primitives/extensions.schema.json') as Node;

function defs(schema: Node): Node {
  return (schema.$defs ?? {}) as Node;
}

function externalReference(): Node {
  return defs(commonSchema).External_Reference as Node;
}

function extensionsDef(): Node {
  return defs(extensionsSchema).Extensions as Node;
}

function properties(node: Node | undefined): Node {
  return ((node?.properties ?? {}) as Node) ?? {};
}

/** The `extensions` property as declared on a document root, resolved through
 *  a `$ref` when the document points at the shared Extensions definition. */
function documentExtensions(docName: string): Node | undefined {
  const schema = loadSchema(`${docName}.schema.json`) as Node;
  const prop = properties(schema).extensions as Node | undefined;
  if (!prop) return undefined;
  if (typeof prop.$ref === 'string' && prop.$ref.includes('/$defs/Extensions')) {
    return extensionsDef();
  }
  return prop;
}

// ---------------------------------------------------------------------------
// Structure: passthrough and rawSourceArtifacts must be DEFINED, not merely
// tolerated by an open `additionalProperties`.
// ---------------------------------------------------------------------------

describe('extensions carriage — schema structure', () => {
  it.each(ENVELOPE_DOCUMENTS)('%s declares a root `extensions` property', (doc) => {
    const schema = loadSchema(`${doc}.schema.json`) as Node;
    expect(Object.keys(properties(schema))).toContain('extensions');
  });

  it(`${STREAM_EVENT_DOCUMENT} does not declare \`extensions\``, () => {
    const schema = loadSchema(`${STREAM_EVENT_DOCUMENT}.schema.json`) as Node;
    expect(Object.keys(properties(schema))).not.toContain('extensions');
  });

  it.each(ENVELOPE_DOCUMENTS)(
    '%s reaches an Extensions definition that names passthrough and rawSourceArtifacts',
    (doc) => {
      const ext = documentExtensions(doc);
      expect(ext).toBeDefined();
      const names = Object.keys(properties(ext));
      expect(names).toContain('passthrough');
      expect(names).toContain('rawSourceArtifacts');
    },
  );

  it('the shared Extensions definition exists in the extensions primitive', () => {
    expect(extensionsDef()).toBeDefined();
  });

  it('passthrough is described, not just declared', () => {
    const passthrough = properties(extensionsDef()).passthrough as Node;
    expect(typeof passthrough?.description).toBe('string');
    expect((passthrough.description as string).length).toBeGreaterThan(40);
  });

  it('passthrough stays deliberately permissive — unenumerated properties by design', () => {
    const passthrough = properties(extensionsDef()).passthrough as Node;
    expect(passthrough.type).toBe('object');
    expect(passthrough.additionalProperties).toBe(true);
    expect(passthrough.unevaluatedProperties).toBeUndefined();
  });

  // `additionalProperties: false` rather than the house `unevaluatedProperties:
  // false`: Extensions composes nothing, and the Go validator (gojsonschema, a
  // draft-07 engine) does not implement `unevaluatedProperties`, so only
  // `additionalProperties` makes the closure real in both languages.
  it("extensions is closed — an undeclared key is passthrough's job, not its own", () => {
    const ext = extensionsDef();
    expect(ext.additionalProperties).toBe(false);
  });

  it('the baseline-level extensions points at the same shared definition', () => {
    const results = loadSchema('hdf-results.schema.json') as Node;
    const baseline = defs(results).Evaluated_Baseline as Node;
    const prop = properties(baseline).extensions as Node;
    expect(prop.$ref).toContain('/$defs/Extensions');
    expect(prop.type).toBeUndefined();
    expect(prop.additionalProperties).toBeUndefined();
  });

  it('rawSourceArtifacts is an array of External_Reference-shaped entries', () => {
    const raw = properties(extensionsDef()).rawSourceArtifacts as Node;
    expect(raw.type).toBe('array');
    expect(typeof raw.description).toBe('string');
    const items = raw.items as Node;
    expect(items).toBeDefined();
    expect(JSON.stringify(items)).toContain('Raw_Source_Artifact');
  });

  it('Raw_Source_Artifact builds on External_Reference', () => {
    const artifact = defs(extensionsSchema).Raw_Source_Artifact as Node;
    expect(artifact).toBeDefined();
    expect(JSON.stringify(artifact)).toContain('External_Reference');
  });

  // hdf-validators' Go implementation is gojsonschema, a draft-07 validator, and
  // draft-07 says a `$ref` REPLACES its schema object — so a validation keyword
  // written beside a `$ref` is enforced by the TypeScript validator and silently
  // skipped by the Go one. Such a constraint belongs in an `allOf` branch.
  // Annotations (description, title, examples, $comment) beside a `$ref` are
  // fine: they carry no assertion either way.
  it('no source schema puts a validation keyword beside a $ref', () => {
    const VALIDATION_KEYWORDS = new Set([
      'if', 'then', 'else', 'allOf', 'anyOf', 'oneOf', 'not',
      'required', 'dependentRequired', 'dependentSchemas', 'properties',
      'patternProperties', 'additionalProperties', 'unevaluatedProperties',
      'items', 'prefixItems', 'contains', 'minItems', 'maxItems', 'uniqueItems',
      'enum', 'const', 'type', 'minimum', 'maximum', 'minLength', 'maxLength',
      'pattern', 'format', 'multipleOf',
    ]);
    const offenders: string[] = [];
    const walk = (node: unknown, path: string, file: string): void => {
      if (Array.isArray(node)) {
        node.forEach((v, i) => walk(v, `${path}[${i}]`, file));
        return;
      }
      if (!node || typeof node !== 'object') return;
      const obj = node as Node;
      if (typeof obj.$ref === 'string') {
        for (const key of Object.keys(obj)) {
          if (VALIDATION_KEYWORDS.has(key)) offenders.push(`${file}${path}: $ref + ${key}`);
        }
      }
      // `examples` holds instance data, not subschemas — a "$ref" in there is a value.
      for (const [key, value] of Object.entries(obj)) {
        if (key !== 'examples') walk(value, `${path}/${key}`, file);
      }
    };
    for (const name of [
      ...ALL_DOCUMENTS.map((d) => `${d}.schema.json`),
      'primitives/common.schema.json',
      'primitives/extensions.schema.json',
    ]) {
      walk(loadSchema(name), '', name);
    }
    expect(offenders).toEqual([]);
  });

  // The companion trap to the one above, and the one that actually bit: a
  // keyword introduced in 2019-09 or later is not "enforced in TypeScript and
  // skipped in Go" — it is skipped by BOTH shipped validators, because
  // hdf-validators' Go side is gojsonschema (draft-07) and its TypeScript side
  // constructs a default `Ajv` (also draft-07). Only hdf-schema's own test
  // harness builds Ajv2020. So such a keyword states a rule that `hdf validate`
  // never applies. `dependentRequired` was added to External_Reference and sat
  // unenforced until a reviewer noticed; it is now an if/then pair instead.
  //
  // `unevaluatedProperties` is the one accepted exception: it is house style on
  // every composing definition, its skip in draft-07 is understood, and where a
  // closure has to be real in both languages `additionalProperties` is used.
  it('no source schema relies on a 2019-09+ keyword the shipped validators ignore', () => {
    const POST_DRAFT_07 = new Set([
      'dependentRequired', 'dependentSchemas', 'prefixItems', 'unevaluatedItems',
      'minContains', 'maxContains', 'contentSchema',
      '$recursiveRef', '$recursiveAnchor', '$dynamicRef', '$dynamicAnchor',
    ]);
    const offenders: string[] = [];
    const walk = (node: unknown, path: string, file: string): void => {
      if (Array.isArray(node)) {
        node.forEach((v, i) => walk(v, `${path}[${i}]`, file));
        return;
      }
      if (!node || typeof node !== 'object') return;
      for (const [key, value] of Object.entries(node as Node)) {
        if (POST_DRAFT_07.has(key)) offenders.push(`${file}${path}: ${key}`);
        if (key !== 'examples') walk(value, `${path}/${key}`, file);
      }
    };
    for (const name of [
      ...ALL_DOCUMENTS.map((d) => `${d}.schema.json`),
      'primitives/common.schema.json',
      'primitives/extensions.schema.json',
      'primitives/result.schema.json',
    ]) {
      walk(loadSchema(name), '', name);
    }
    expect(offenders).toEqual([]);
  });
});

describe('External_Reference — content and encoding', () => {
  it('declares a `content` string for the artifact bytes', () => {
    const content = properties(externalReference()).content as Node;
    expect(content).toBeDefined();
    expect(content.type).toBe('string');
    expect(typeof content.description).toBe('string');
  });

  it('declares an `encoding` limited to utf-8 and base64', () => {
    const encoding = properties(externalReference()).encoding as Node;
    expect(encoding).toBeDefined();
    expect(encoding.enum).toEqual(['utf-8', 'base64']);
  });

  it('keeps `document` JSON-object-only — it is not widened to hold text', () => {
    const document = properties(externalReference()).document as Node;
    expect(document.type).toBe('object');
  });

  it('no longer scopes mediaType to href alone', () => {
    const mediaType = properties(externalReference()).mediaType as Node;
    expect(mediaType.description as string).not.toMatch(/Meaningful only with/i);
    expect(mediaType.description as string).toMatch(/embed/i);
  });

  it('no longer scopes checksum to href alone', () => {
    const checksum = properties(externalReference()).checksum as Node;
    expect(checksum.description as string).not.toMatch(/Meaningful only with/i);
    expect(checksum.description as string).toMatch(/embed/i);
  });
});

// ---------------------------------------------------------------------------
// Validation: documents carrying these payloads must actually validate.
// ---------------------------------------------------------------------------

const minimalResultsDoc = (extensions: unknown): Node => ({
  baselines: [
    {
      name: 'grype-scan',
      requirements: [
        {
          id: 'CVE-2021-36159',
          impact: 0.7,
          tags: {},
          descriptions: [{ label: 'default', data: 'apk-tools out-of-bounds read' }],
          results: [
            { status: 'failed', codeDesc: 'apk-tools 2.12.5-r1', startTime: '2026-09-27T12:00:00Z' },
          ],
        },
      ],
    },
  ],
  extensions,
});

/** The same document with the extensions hung off the baseline instead of the root. */
const withBaselineExtensions = (extensions: unknown): Node => {
  const doc = minimalResultsDoc(undefined);
  delete doc.extensions;
  (doc.baselines as Node[])[0].extensions = extensions;
  return doc;
};

const minimalAmendmentsDoc = (extensions: unknown): Node => ({
  name: 'OpenVEX import',
  overrides: [
    {
      type: 'falsePositive',
      requirementId: 'CVE-2021-44228',
      status: 'notApplicable',
      reason: 'Vulnerable code path is not present in the built artifact',
      appliedBy: { type: 'email', identifier: 'secops@agency.gov' },
      appliedAt: '2026-09-27T12:00:00Z',
      expiresAt: '2099-12-31T00:00:00Z',
    },
  ],
  extensions,
});

// Artifact shapes the ADR names. All three embed BYTES: ADR-0017 §2 forbids
// `document` here, because a parsed object cannot hold the bytes the checksum
// describes.
const jsonArtifact = {
  sourceName: 'grype',
  rel: 'raw-source',
  mediaType: 'application/json',
  encoding: 'utf-8',
  content: '{"matches":[{"vulnerability":{"id":"CVE-2021-36159","severity":"Critical"}}]}',
  checksum: {
    algorithm: 'sha256',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
};

/** The shape (A) rules out: a JSON input embedded as a parsed object. */
const documentArtifact = {
  sourceName: 'grype',
  rel: 'raw-source',
  mediaType: 'application/json',
  document: {
    matches: [{ vulnerability: { id: 'CVE-2021-36159', severity: 'Critical' } }],
  },
};

const xmlArtifact = {
  sourceName: 'nessus',
  rel: 'raw-source',
  mediaType: 'application/xml',
  encoding: 'utf-8',
  content:
    '<?xml version="1.0" ?>\n<NessusClientData_v2><Report name="scan"/></NessusClientData_v2>',
  checksum: {
    algorithm: 'sha256',
    value: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  },
};

const binaryArtifact = {
  sourceName: 'fortify',
  rel: 'raw-source',
  mediaType: 'application/zip',
  encoding: 'base64',
  content: 'UEsDBBQAAAAIAI1ZX1YhQp8FHgAAABIAAAAIAAAAdGVzdC50eHRLy8nPS8lQSgIAUmNEBhQAAAA=',
};

/** A copy of `entry` with one member removed, for the rejection cases. */
function without(entry: Node, key: string): Node {
  const copy = { ...entry };
  delete copy[key];
  return copy;
}

describe('extensions carriage — document validation', () => {
  let ajv: Ajv2020;
  let validateResults: ValidateFunction;
  let validateAmendments: ValidateFunction;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    validateResults = ajv.compile(loadSchema('hdf-results.schema.json'));
    validateAmendments = ajv.compile(loadSchema('hdf-amendments.schema.json'));
  });

  const expectValid = (validate: ValidateFunction, doc: unknown) => {
    const ok = validate(doc);
    if (!ok) console.error(JSON.stringify(validate.errors, null, 2));
    expect(ok).toBe(true);
  };

  describe('passthrough', () => {
    it('accepts a representative passthrough payload', () => {
      expectValid(
        validateResults,
        minimalResultsDoc({
          passthrough: {
            auxiliary_data: [{ name: 'Grype', data: { imageDigest: 'sha256:abc' } }],
            raw: { descriptor: { name: 'grype', version: '0.74.0' } },
          },
        }),
      );
    });

    // hdf-parsers/{go/saf_supplement.go,typescript/saf-supplement.ts} move a
    // legacy top-level `passthrough` here verbatim.
    it('accepts the SAF-supplement normalizer output', () => {
      expectValid(validateResults, minimalResultsDoc({ passthrough: { audit: { runId: 'r-123' } } }));
    });

    // legacyhdf-to-hdf carries the unknown v1 fields it found, plus v1_version,
    // in both languages — all of it inside passthrough.
    it('accepts the legacy converter provenance map', () => {
      expectValid(
        validateResults,
        minimalResultsDoc({
          passthrough: {
            v1_version: '1.0',
            anything: 'at all',
            nested: { deeply: [1, 2, 3] },
            count: 7,
          },
        }),
      );
    });
  });

  // The ruling: `extensions` is a closed, defined object. Anything HDF does not
  // define goes in `passthrough` — that is what `passthrough` is for.
  describe('extensions is closed', () => {
    it('rejects an undeclared key at the document root', () => {
      expect(validateResults(minimalResultsDoc({ someToolKey: { a: 1 } }))).toBe(false);
    });

    it('rejects an undeclared key even alongside the defined members', () => {
      expect(
        validateResults(
          minimalResultsDoc({ passthrough: { ok: true }, checklistFormat: 'ckl' }),
        ),
      ).toBe(false);
    });

    it('rejects an undeclared key on an amendments document too', () => {
      expect(validateAmendments(minimalAmendmentsDoc({ openvex_metadata: {} }))).toBe(false);
    });

    it('rejects an undeclared key at baseline level', () => {
      expect(validateResults(withBaselineExtensions({ stigid: 'Firefox_STIG' }))).toBe(false);
    });

    // Every key the converters and engines used to write at the top of
    // `extensions` now lives under `passthrough`.
    it.each([
      ['checklist root metadata', { checklistFormat: 'ckl', cklbVersion: '1.5', cklbActive: true, cklbMode: 2, cklbHasPath: true, assetExtras: { marking: 'CUI', webOrDatabase: true } }],
      ['hdf-merge provenance', { 'hdf-merge': { version: '3.7.0', sources: [{ index: 0, name: 'gosec' }] } }],
      ['legacy v1 provenance', { v1_version: '1.0' }],
    ])('accepts migrated root key set: %s', (_label, payload) => {
      expectValid(validateResults, minimalResultsDoc({ passthrough: payload }));
    });

    it.each([
      ['checklist stig metadata', { stigid: 'Mozilla_Firefox_STIG', uuid: '6b6f1a1f-0000-4000-8000-000000000001', releaseInfo: 'Release: 7 Benchmark Date: 24 Jul 2024', displayName: 'Firefox', referenceIdentifier: '4394', classification: 'UNCLASSIFIED' }],
      ['gosec scan metadata', { gosec: { golangVersion: '1.22.0', stats: { files: 12, lines: 3400 } } }],
      ['neuvector scan metadata', { neuvector: { cmds: ['scan'] } }],
      ['ionchannel run metadata', { ionchannel: { analysis_id: 'a-1' } }],
      ['hdf-diff legacy attributes', { legacyAttributes: [{ name: 'disable_slow_controls' }] }],
    ])('accepts migrated baseline key set: %s', (_label, payload) => {
      expectValid(validateResults, withBaselineExtensions({ passthrough: payload }));
    });

    it('accepts rawSourceArtifacts at baseline level as well', () => {
      expectValid(validateResults, withBaselineExtensions({ rawSourceArtifacts: [jsonArtifact] }));
    });
  });

  describe('rawSourceArtifacts', () => {
    it('accepts a JSON artifact embedded as utf-8 content', () => {
      expectValid(validateResults, minimalResultsDoc({ rawSourceArtifacts: [jsonArtifact] }));
    });

    // ADR-0017 §2: byte carriage only. `document` holds a parsed object, so the
    // original whitespace, key order and duplicate keys are gone and the
    // checksum cannot be verified against what is stored. Enforced, not merely
    // described — and deliberately stricter than v2's passthrough.raw.
    it('rejects a JSON artifact embedded as a parsed document', () => {
      expect(validateResults(minimalResultsDoc({ rawSourceArtifacts: [documentArtifact] }))).toBe(
        false,
      );
    });

    it('accepts an XML artifact embedded as utf-8 content', () => {
      expectValid(validateResults, minimalResultsDoc({ rawSourceArtifacts: [xmlArtifact] }));
    });

    it('accepts non-text bytes embedded as base64 content', () => {
      expectValid(validateResults, minimalResultsDoc({ rawSourceArtifacts: [binaryArtifact] }));
    });

    it('accepts several artifacts, as the OSCAL profile-plus-catalog path needs', () => {
      expectValid(
        validateResults,
        minimalResultsDoc({ rawSourceArtifacts: [jsonArtifact, xmlArtifact] }),
      );
    });

    it('accepts an href-bearing entry that does not embed', () => {
      expectValid(
        validateResults,
        minimalResultsDoc({
          rawSourceArtifacts: [
            {
              sourceName: 'nessus',
              rel: 'raw-source',
              href: 'https://scans.example.gov/reports/2026-09-27.nessus',
              mediaType: 'application/xml',
            },
          ],
        }),
      );
    });

    it('rejects an embedding entry with no mediaType', () => {
      const entry = without(xmlArtifact, 'mediaType');
      expect(validateResults(minimalResultsDoc({ rawSourceArtifacts: [entry] }))).toBe(false);
    });

    it('rejects a document-embedding entry even when it is otherwise complete', () => {
      expect(
        validateResults(
          minimalResultsDoc({
            rawSourceArtifacts: [{ ...documentArtifact, checksum: jsonArtifact.checksum }],
          }),
        ),
      ).toBe(false);
    });

    it('rejects content without an encoding to read it by', () => {
      const entry = without(xmlArtifact, 'encoding');
      expect(validateResults(minimalResultsDoc({ rawSourceArtifacts: [entry] }))).toBe(false);
    });

    it('rejects an unknown encoding', () => {
      expect(
        validateResults(
          minimalResultsDoc({ rawSourceArtifacts: [{ ...xmlArtifact, encoding: 'hex' }] }),
        ),
      ).toBe(false);
    });

    it('rejects a non-array rawSourceArtifacts', () => {
      expect(validateResults(minimalResultsDoc({ rawSourceArtifacts: jsonArtifact }))).toBe(false);
    });
  });

  // The VEX family and oscal-poam-to-hdf emit amendments; without extensions
  // there they have nowhere to put the artifact the converter policy requires.
  describe('amendments documents', () => {
    it('accepts extensions carrying both members', () => {
      expectValid(
        validateAmendments,
        minimalAmendmentsDoc({
          passthrough: { openvex_metadata: { author: 'Example Corp' } },
          rawSourceArtifacts: [jsonArtifact],
        }),
      );
    });
  });
});

// ---------------------------------------------------------------------------
// The bundled output is what consumers and the docs site read.
// ---------------------------------------------------------------------------

describe('extensions carriage — bundled schemas', () => {
  it.each(ALL_DOCUMENTS)('%s bundles without dangling refs', (doc) => {
    const ajv = createAjvWithPrimitives();
    expect(() => ajv.validateSchema(loadSchema(`${doc}.schema.json`))).not.toThrow();
  });
});
