import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import extensionsSchema from '../src/schemas/primitives/extensions.schema.json';
import resultSchema from '../src/schemas/primitives/result.schema.json';
import amendmentsSchema from '../src/schemas/primitives/amendments.schema.json';
import hdfAmendmentsSchema from '../src/schemas/hdf-amendments.schema.json';

describe('hdf-amendments.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(amendmentsSchema);
  const validate = ajv.compile(hdfAmendmentsSchema);

  const minimalOverride = {
    type: 'waiver',
    requirementId: 'SV-257777',
    status: 'passed',
    reason: 'Compensating control',
    appliedBy: { type: 'email', identifier: 'ao@agency.gov' },
    appliedAt: '2026-01-15T10:00:00Z',
    expiresAt: '2026-06-30T00:00:00Z',
  };

  const minimal = {
    name: 'Test Amendments',
    overrides: [minimalOverride],
  };

  it('should validate a minimal amendments document', () => {
    expect(validate(minimal)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  it('should accept amendmentId UUID', () => {
    const withId = { ...minimal, amendmentId: '550e8400-e29b-41d4-a716-446655440000' };
    expect(validate(withId)).toBe(true);
  });

  it('should reject invalid amendmentId format', () => {
    const badId = { ...minimal, amendmentId: 'not-a-uuid' };
    expect(validate(badId)).toBe(false);
  });

  it('should validate a fully specified document', () => {
    const full = {
      amendmentId: '550e8400-e29b-41d4-a716-446655440000',
      name: 'Portal Q1 2026 Waivers',
      description: 'Quarterly waiver review for portal production',
      systemRef: 'portal-prod.hdf-system.json',
      appliedBy: { type: 'email', identifier: 'assessor@agency.gov' },
      approvedBy: { type: 'email', identifier: 'ao@agency.gov' },
      version: '1.0.0',
      labels: { quarter: 'Q1-2026', system: 'Portal' },
      integrity: { algorithm: 'sha256', checksum: 'abc123' },
      generator: { name: 'hdf-cli', version: '0.1.0' },
      signature: {
        type: 'Ed25519Signature2020',
        created: '2026-01-15T10:00:00Z',
        creator: { type: 'email', identifier: 'ao@agency.gov' },
        proofPurpose: 'attestation',
        signatureValue: 'z3FXq7abc',
        verificationMethod: {
          type: 'Ed25519VerificationKey2020',
          controller: 'did:key:z6MkhaXg',
        },
      },
      overrides: [
        {
          ...minimalOverride,
          baselineRef: 'RHEL9-STIG',
          evidence: [{
            type: 'url',
            data: 'https://jira.agency.gov/CYBER-4521',
            description: 'ISSM approval',
          }],
          signature: {
            type: 'Ed25519Signature2020',
            created: '2026-01-15T10:00:00Z',
            creator: { type: 'email', identifier: 'ao@agency.gov' },
            proofPurpose: 'attestation',
            signatureValue: 'z3FXq7abc',
            verificationMethod: {
              type: 'Ed25519VerificationKey2020',
              controller: 'did:key:z6MkhaXg',
            },
          },
          previousChecksum: { algorithm: 'sha256', value: 'prev123' },
        },
      ],
    };
    expect(validate(full)).toBe(true);
  });

  // -- Required fields --

  it('should reject document missing name', () => {
    expect(validate({ overrides: [minimalOverride] })).toBe(false);
  });

  it('should reject document missing overrides', () => {
    expect(validate({ name: 'Test' })).toBe(false);
  });

  it('should reject empty overrides array', () => {
    expect(validate({ name: 'Test', overrides: [] })).toBe(false);
  });

  it('should reject unknown top-level properties', () => {
    expect(validate({ ...minimal, unknownField: 'bad' })).toBe(false);
  });

  // -- Labels --

  it('should accept labels', () => {
    expect(validate({ ...minimal, labels: { q: 'Q1' } })).toBe(true);
  });

  it('should reject labels with non-string values', () => {
    expect(validate({ ...minimal, labels: { count: 42 } })).toBe(false);
  });
});

describe('amendments.schema.json — Standalone_Override', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(amendmentsSchema);

  const validate = ajv.compile({
    $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/amendments/v2.0.0#/$defs/Standalone_Override',
  });

  const valid = {
    type: 'waiver',
    requirementId: 'SV-257777',
    status: 'passed',
    reason: 'Risk accepted',
    appliedBy: { type: 'email', identifier: 'ao@agency.gov' },
    appliedAt: '2026-01-15T10:00:00Z',
    expiresAt: '2026-06-30T00:00:00Z',
  };

  it('should validate a minimal override', () => {
    expect(validate(valid)).toBe(true);
  });

  // -- All override types --

  it('should accept all override types', () => {
    for (const type of ['waiver', 'attestation', 'exception', 'poam', 'inherited']) {
      expect(validate({ ...valid, type })).toBe(true);
    }
  });

  it('should reject invalid override type', () => {
    expect(validate({ ...valid, type: 'approval' })).toBe(false);
  });

  // -- Required fields --

  it('should reject override missing requirementId', () => {
    const obj = { ...valid } as Record<string, unknown>;
    delete obj.requirementId;
    expect(validate(obj)).toBe(false);
  });

  it('should reject override missing status', () => {
    const obj = { ...valid } as Record<string, unknown>;
    delete obj.status;
    expect(validate(obj)).toBe(false);
  });

  it('should reject override missing reason', () => {
    const obj = { ...valid } as Record<string, unknown>;
    delete obj.reason;
    expect(validate(obj)).toBe(false);
  });

  it('should reject override missing appliedBy', () => {
    const obj = { ...valid } as Record<string, unknown>;
    delete obj.appliedBy;
    expect(validate(obj)).toBe(false);
  });

  it('should reject override missing appliedAt', () => {
    const obj = { ...valid } as Record<string, unknown>;
    delete obj.appliedAt;
    expect(validate(obj)).toBe(false);
  });

  it('should reject override missing expiresAt', () => {
    const obj = { ...valid } as Record<string, unknown>;
    delete obj.expiresAt;
    expect(validate(obj)).toBe(false);
  });

  // -- Optional fields --

  it('should accept override with baselineRef', () => {
    expect(validate({ ...valid, baselineRef: 'RHEL9-STIG' })).toBe(true);
  });

  it('should accept override with evidence', () => {
    const override = {
      ...valid,
      evidence: [{ type: 'url', data: 'https://jira.example.com/SEC-123', description: 'Ticket' }],
    };
    expect(validate(override)).toBe(true);
  });

  it('should accept override with milestones (POA&M)', () => {
    const override = {
      ...valid,
      type: 'poam',
      milestones: [{
        description: 'Apply vendor patch',
        estimatedCompletion: '2026-04-15T00:00:00Z',
        status: 'pending',
      }],
    };
    expect(validate(override)).toBe(true);
  });

  it('should accept override with previousChecksum', () => {
    const override = {
      ...valid,
      previousChecksum: { algorithm: 'sha256', value: 'abc123' },
    };
    expect(validate(override)).toBe(true);
  });

  it('should reject unknown properties', () => {
    expect(validate({ ...valid, extra: 'bad' })).toBe(false);
  });

  // -- Valid status values --

  it('should accept all result status values', () => {
    for (const status of ['passed', 'failed', 'notApplicable', 'notReviewed', 'error']) {
      expect(validate({ ...valid, status })).toBe(true);
    }
  });

  it('should reject invalid status', () => {
    expect(validate({ ...valid, status: 'skipped' })).toBe(false);
  });

  // -- Date format --

  it('should reject invalid appliedAt format', () => {
    expect(validate({ ...valid, appliedAt: 'not-a-date' })).toBe(false);
  });

  it('should reject invalid expiresAt format', () => {
    expect(validate({ ...valid, expiresAt: '2026-06-30' })).toBe(false);
  });

  // -- Inherited amendment type --

  it('should validate an inherited amendment with inheritedFrom', () => {
    const inherited = {
      ...valid,
      type: 'inherited',
      status: 'notApplicable',
      reason: 'IA-2 provided by Keycloak SSO. No local authentication.',
      inheritedFrom: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    };
    expect(validate(inherited)).toBe(true);
  });

  it('should validate an inherited amendment without inheritedFrom (external provider)', () => {
    const inherited = {
      ...valid,
      type: 'inherited',
      status: 'notApplicable',
      reason: 'PE-2 provided by AWS GovCloud per FedRAMP authorization.',
    };
    expect(validate(inherited)).toBe(true);
  });

  it('should reject inheritedFrom with invalid UUID', () => {
    const inherited = {
      ...valid,
      type: 'inherited',
      inheritedFrom: 'not-a-uuid',
    };
    expect(validate(inherited)).toBe(false);
  });

  it('should accept inheritedFrom on non-inherited types (field is not type-restricted)', () => {
    const waiver = {
      ...valid,
      type: 'waiver',
      inheritedFrom: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    };
    expect(validate(waiver)).toBe(true);
  });

  // -- componentRef scoping --

  it('should accept override with componentRef UUID', () => {
    const override = {
      ...valid,
      componentRef: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    };
    expect(validate(override)).toBe(true);
  });

  it('should reject override with invalid componentRef', () => {
    expect(validate({ ...valid, componentRef: 'not-a-uuid' })).toBe(false);
  });

  it('should accept override with both componentRef and inheritedFrom', () => {
    const override = {
      ...valid,
      type: 'inherited',
      componentRef: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      inheritedFrom: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    };
    expect(validate(override)).toBe(true);
  });

  it('should validate inherited amendment in a full amendments document', () => {
    const doc = {
      name: 'Inheritance Overrides',
      overrides: [
        {
          type: 'inherited',
          requirementId: 'SV-230368',
          baselineRef: 'RHEL9-STIG',
          status: 'notApplicable',
          reason: 'IA-2 common control provided by SSO.',
          inheritedFrom: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          appliedBy: { type: 'email', identifier: 'issm@agency.gov' },
          appliedAt: '2026-03-26T10:00:00Z',
          expiresAt: '2026-09-26T00:00:00Z',
        },
      ],
    };
    const docValidate = ajv.compile(hdfAmendmentsSchema);
    expect(docValidate(doc)).toBe(true);
  });
});
