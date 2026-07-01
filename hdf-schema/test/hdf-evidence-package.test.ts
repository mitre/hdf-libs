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
