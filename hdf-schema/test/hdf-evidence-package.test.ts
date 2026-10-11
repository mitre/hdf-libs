import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import extensionsSchema from '../src/schemas/primitives/extensions.schema.json';
import hdfEvidenceSchema from '../src/schemas/hdf-evidence-package.schema.json';

describe('hdf-evidence-package.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(extensionsSchema);
  const validate = ajv.compile(hdfEvidenceSchema);

  const minimalContent = { type: 'hdf-results', uri: 'scan.json' };
  const minimal = { name: 'Test Evidence', contents: [minimalContent] };

  it('should validate a minimal evidence package', () => {
    expect(validate(minimal)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  it('should accept packageId UUID', () => {
    const withId = { ...minimal, packageId: '550e8400-e29b-41d4-a716-446655440000' };
    expect(validate(withId)).toBe(true);
  });

  it('should reject invalid packageId format', () => {
    const badId = { ...minimal, packageId: 'not-a-uuid' };
    expect(validate(badId)).toBe(false);
  });

  it('should accept planRef', () => {
    const withPlan = { ...minimal, planRef: 'quarterly-plan.hdf-plan.json' };
    expect(validate(withPlan)).toBe(true);
  });

  it('should validate a fully specified evidence package', () => {
    const full = {
      packageId: '550e8400-e29b-41d4-a716-446655440000',
      name: 'Enterprise Portal ATO Evidence - Q1 2026',
      description: 'Quarterly ATO evidence bundle',
      planRef: 'quarterly-plan.hdf-plan.json',
      systemRef: 'portal-prod.hdf-system.json',
      preparedBy: { type: 'email', identifier: 'compliance@agency.gov' },
      preparedAt: '2026-03-31T12:00:00Z',
      version: '1.0.0',
      labels: { quarter: 'Q1-2026' },
      integrity: { algorithm: 'sha256', checksum: 'abc123' },
      generator: { name: 'hdf-cli', version: '0.1.0' },
      signature: {
        type: 'Ed25519Signature2020',
        created: '2026-03-31T12:00:00Z',
        creator: { type: 'email', identifier: 'ao@agency.gov' },
        proofPurpose: 'attestation',
        signatureValue: 'z3FXq7abc',
        verificationMethod: { type: 'Ed25519VerificationKey2020', controller: 'did:key:z6Mk' },
      },
      contents: [
        { type: 'hdf-system', uri: 'portal-prod.hdf-system.json', checksum: { algorithm: 'sha256', value: 'aaa' } },
        { type: 'hdf-baseline', uri: 'rhel9-stig.json', checksum: { algorithm: 'sha256', value: 'bbb' } },
        { type: 'hdf-plan', uri: 'scan-plan.json', checksum: { algorithm: 'sha256', value: 'ccc' } },
        { type: 'hdf-results', uri: 'scan.json', checksum: { algorithm: 'sha256', value: 'ddd' }, description: 'March scan' },
        { type: 'hdf-amendments', uri: 'waivers.json', checksum: { algorithm: 'sha256', value: 'eee' } },
        { type: 'hdf-comparison', uri: 'diff.json', checksum: { algorithm: 'sha256', value: 'fff' } },
        { type: 'bom', uri: 'https://artifacts.example.com/sbom.cdx.json', description: 'CycloneDX SBOM' },
      ],
      completenessCheck: {
        allBaselinesAssessed: true,
        allComponentsCovered: true,
        expiredWaivers: 0,
        unresolvedPoams: 2,
        compliancePercent: 95.8,
        sbomCoverage: { componentsWithSbom: 3, totalComponents: 5 },
      },
    };
    expect(validate(full)).toBe(true);
  });

  // -- Required fields --

  it('should reject package missing name', () => {
    expect(validate({ contents: [minimalContent] })).toBe(false);
  });

  it('should reject package missing contents', () => {
    expect(validate({ name: 'Test' })).toBe(false);
  });

  it('should reject empty contents array', () => {
    expect(validate({ name: 'Test', contents: [] })).toBe(false);
  });

  it('should reject unknown top-level properties', () => {
    expect(validate({ ...minimal, unknownField: 'bad' })).toBe(false);
  });

  // -- Content_Reference --

  it('should accept all valid content types', () => {
    const types = ['hdf-system', 'hdf-baseline', 'hdf-plan', 'hdf-results', 'hdf-amendments', 'hdf-comparison', 'bom'];
    for (const type of types) {
      const doc = { name: 'Test', contents: [{ type, uri: 'file.json' }] };
      expect(validate(doc)).toBe(true);
    }
  });

  it('should reject invalid content type', () => {
    const doc = { name: 'Test', contents: [{ type: 'hdf-unknown', uri: 'file.json' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject the removed sbom content type (generalized to bom)', () => {
    const doc = { name: 'Test', contents: [{ type: 'sbom', uri: 'file.json' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject content reference missing type', () => {
    const doc = { name: 'Test', contents: [{ uri: 'file.json' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject content reference missing uri', () => {
    const doc = { name: 'Test', contents: [{ type: 'hdf-results' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should accept content reference with checksum', () => {
    const doc = {
      name: 'Test',
      contents: [{ type: 'hdf-results', uri: 'scan.json', checksum: { algorithm: 'sha256', value: 'abc' } }],
    };
    expect(validate(doc)).toBe(true);
  });

  it('should accept content reference with description', () => {
    const doc = {
      name: 'Test',
      contents: [{ type: 'hdf-results', uri: 'scan.json', description: 'March scan' }],
    };
    expect(validate(doc)).toBe(true);
  });

  it('should reject content reference with unknown properties', () => {
    const doc = {
      name: 'Test',
      contents: [{ type: 'hdf-results', uri: 'scan.json', extra: 'bad' }],
    };
    expect(validate(doc)).toBe(false);
  });

  it('should accept content reference with componentRef UUID', () => {
    const doc = {
      name: 'Test',
      contents: [{
        type: 'bom',
        uri: 'webtier.cdx.json',
        componentRef: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      }],
    };
    expect(validate(doc)).toBe(true);
  });

  it('should reject content reference with invalid componentRef', () => {
    const doc = {
      name: 'Test',
      contents: [{
        type: 'hdf-results',
        uri: 'scan.json',
        componentRef: 'not-a-uuid',
      }],
    };
    expect(validate(doc)).toBe(false);
  });

  // -- External_Evidence_Reference --

  const ecsRef = { uri: 'https://evidence.agency.gov/logs/2026-q1.ndjson', format: 'ecs' };

  it('should accept an external evidence reference (ecs)', () => {
    expect(validate({ ...minimal, externalEvidence: [ecsRef] })).toBe(true);
    expect(validate.errors).toBeNull();
  });

  it('should accept a fully specified external evidence reference', () => {
    const doc = {
      ...minimal,
      externalEvidence: [{
        uri: 'https://evidence.agency.gov/ocsf/portal-2026-q1.parquet',
        format: 'ocsf',
        formatVersion: '1.8.0',
        mediaType: 'application/vnd.apache.parquet',
        checksum: { algorithm: 'sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        description: 'Portal OCSF telemetry, Q1 2026',
        metadata: {
          recordCount: 1500000,
          timeRange: { start: '2026-01-01T00:00:00Z', end: '2026-03-31T23:59:59Z' },
          collector: 'aws-security-lake',
        },
      }],
    };
    expect(validate(doc)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  it('should accept the reserved format values', () => {
    for (const format of ['ecs', 'ocsf', 'cyclonedx', 'spdx', 'raw-log']) {
      expect(validate({ ...minimal, externalEvidence: [{ uri: 'x.json', format }] })).toBe(true);
    }
  });

  it('should accept an x- custom format (e.g. a Splunk/Sentinel export)', () => {
    const doc = { ...minimal, externalEvidence: [{ uri: 'siem-export.json', format: 'x-splunk-export' }] };
    expect(validate(doc)).toBe(true);
  });

  it('should reject query-time normalization models as formats (splunk-cim, ms-asim, schema-one deferred)', () => {
    for (const format of ['splunk-cim', 'ms-asim', 'schema-one']) {
      expect(validate({ ...minimal, externalEvidence: [{ uri: 'x.json', format }] })).toBe(false);
    }
  });

  it('should reject a non-x custom format value', () => {
    const doc = { ...minimal, externalEvidence: [{ uri: 'x.json', format: 'bogus' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject external evidence missing uri', () => {
    expect(validate({ ...minimal, externalEvidence: [{ format: 'ecs' }] })).toBe(false);
  });

  it('should reject external evidence missing format', () => {
    expect(validate({ ...minimal, externalEvidence: [{ uri: 'x.json' }] })).toBe(false);
  });

  it('should reject external evidence with unknown properties', () => {
    const doc = { ...minimal, externalEvidence: [{ ...ecsRef, embedded: 'no' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject a negative recordCount', () => {
    const doc = { ...minimal, externalEvidence: [{ ...ecsRef, metadata: { recordCount: -1 } }] };
    expect(validate(doc)).toBe(false);
  });

  // -- Completeness_Check --

  it('should accept package with partial completeness check', () => {
    const doc = {
      ...minimal,
      completenessCheck: { compliancePercent: 95.8 },
    };
    expect(validate(doc)).toBe(true);
  });

  it('should accept package with empty completeness check', () => {
    const doc = { ...minimal, completenessCheck: {} };
    expect(validate(doc)).toBe(true);
  });

  it('should reject compliancePercent over 100', () => {
    const doc = { ...minimal, completenessCheck: { compliancePercent: 101 } };
    expect(validate(doc)).toBe(false);
  });

  it('should reject compliancePercent below 0', () => {
    const doc = { ...minimal, completenessCheck: { compliancePercent: -1 } };
    expect(validate(doc)).toBe(false);
  });

  it('should reject negative expiredWaivers', () => {
    const doc = { ...minimal, completenessCheck: { expiredWaivers: -1 } };
    expect(validate(doc)).toBe(false);
  });

  it('should reject non-integer unresolvedPoams', () => {
    const doc = { ...minimal, completenessCheck: { unresolvedPoams: 2.5 } };
    expect(validate(doc)).toBe(false);
  });

  it('should reject completeness check with unknown properties', () => {
    const doc = { ...minimal, completenessCheck: { extra: 'bad' } };
    expect(validate(doc)).toBe(false);
  });

  // -- SBOM_Coverage --

  it('should accept sbomCoverage', () => {
    const doc = {
      ...minimal,
      completenessCheck: { sbomCoverage: { componentsWithSbom: 3, totalComponents: 5 } },
    };
    expect(validate(doc)).toBe(true);
  });

  it('should reject negative componentsWithSbom', () => {
    const doc = {
      ...minimal,
      completenessCheck: { sbomCoverage: { componentsWithSbom: -1, totalComponents: 5 } },
    };
    expect(validate(doc)).toBe(false);
  });

  // -- Labels --

  it('should accept labels', () => {
    expect(validate({ ...minimal, labels: { q: 'Q1' } })).toBe(true);
  });

  it('should reject labels with non-string values', () => {
    expect(validate({ ...minimal, labels: { count: 42 } })).toBe(false);
  });
});

// The schema is a published contract an integrator builds against, so a description
// promising a capability the toolchain refuses is worse than one stating the constraint.
// A content reference MEANS a path relative to the package document's own directory. How
// each consumer resolves one varies — the CLI handles an absolute in-package path through
// packageSubtreeRef before SafePath sees it, and the MCP's inline-content mode resolves
// against its root rather than the package's directory — which is why this description
// states the MEANING and leaves resolution to the consumer. Nothing fetches a remote one,
// and nothing is going to:
// externalEvidence exists so a remote artifact is carried by URI plus hash and never
// retrieved. Asserted on the source schema, which is what build:schemas bundles into
// dist and syncs into the validator embeds.
describe('Content_Reference.uri describes what the toolchain actually does', () => {
  const uri = (hdfEvidenceSchema as { $defs: Record<string, { properties: Record<string, { description: string }> }> })
    .$defs.Content_Reference.properties.uri;

  it('does not promise an absolute URL', () => {
    expect(uri.description).not.toMatch(/absolute URL/i);
  });

  // Denotational on purpose: the field has a MEANING independent of any consumer, and
  // every implementation-shaped phrasing of it was falsified by one consumer or another —
  // the CLI resolves an absolute in-package path before SafePath sees it, and the MCP's
  // inline-content mode resolves against its own root. "Never fetched" survives because it
  // is true of the whole toolchain: net/http appears in none of the evidence commands, the
  // engine, or the MCP.
  it('states the meaning and the never-fetched invariant', () => {
    expect(uri.description).toMatch(/relative to the package document's own directory/i);
    expect(uri.description).toMatch(/never fetched/i);
    expect(uri.description).toMatch(/externalEvidence/);
  });

  // A schema description is consumed by integrators who may never run this CLI and is the
  // one artifact here with no test that can compare it against a binary. Two successive
  // drafts named per-command behaviour and got it wrong — "not read … does not travel" is
  // false for an absolute path landing INSIDE the package (it is read, verified and
  // carried), and "report it and carry on" is false for a schemeless URI (bundle refuses
  // the package). So the rule is: state only what holds for every consumer. The per-command
  // matrix belongs with the commands.
  // An earlier version of this guard listed three command names. Five of six per-command
  // rewrites passed it — including the previous draft's own false sentence, "such a document
  // is not read, so its checksum goes unverified and it does not travel in a bundle", which
  // names nothing and was wrong anyway. The defect was never that a command is named; it is
  // that a per-consumer OUTCOME gets stated as a property of the document. So this rejects
  // the vocabulary such a claim needs. It is NOT airtight and is not pretending to be: a
  // word list is bounded by whoever wrote it, and a reviewer's probe of the first version
  // walked straight past it. It raises the cost of reintroducing the defect; it cannot make
  // the claim testable, which is why the per-command matrix belongs where a test can run the
  // binaries (hdf-libs-52n0c.19) rather than in a published description.
  it('makes no per-command claim, in any wording', () => {
    // The backtick is REQUIRED: without it this also failed legitimate prose such as "the HDF
    // document", which the parent definition's own description contains.
    expect(uri.description, 'description names an hdf command').not.toMatch(/`hdf[ _][a-z]/i);
    for (const word of ['bundle', 'archive', 'verified', 'refuse', 'travel', 'exit ', 'mcp', 'invalid']) {
      expect(uri.description.toLowerCase(), `description uses the per-command word "${word}"`)
        .not.toContain(word);
    }
  });

  // The examples ship in dist and reach consumers through IDE tooltips, so one
  // demonstrating a package the CLI refuses is a worked example of a mistake.
  it('ships no example whose uri is remote', () => {
    const examples = (hdfEvidenceSchema as { $defs: Record<string, { examples?: { uri?: string }[] }> })
      .$defs.Content_Reference.examples;
    expect(examples?.length).toBeGreaterThan(0);
    // An ALLOWLIST, not a list of remote shapes to reject: enumerating schemes let
    // protocol-relative `//host/path` and schemeless opaque uris through, and `mailto:a@b.c`
    // is the shape `hdf evidence verify` turns into a hard error at exit 1 rather than a
    // report. Requiring a package-relative path admits only what the tooling resolves.
    for (const e of examples ?? []) {
      expect(e.uri, `example uri ${e.uri} is not a package-relative path`).toMatch(
        /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/,
      );
      expect(e.uri, `example uri ${e.uri} escapes the package directory`).not.toMatch(/(^|\/)\.\.(\/|$)/);
    }
  });

  // External_Evidence_Reference's absolute/remote support is REAL and must be untouched.
  it('leaves External_Evidence_Reference.uri promising an absolute URL', () => {
    const ext = (hdfEvidenceSchema as { $defs: Record<string, { properties: Record<string, { description: string }> }> })
      .$defs.External_Evidence_Reference.properties.uri;
    expect(ext.description).toMatch(/absolute URL/i);
  });
});
