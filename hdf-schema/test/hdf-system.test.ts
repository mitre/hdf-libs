import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import extensionsSchema from '../src/schemas/primitives/extensions.schema.json';
import systemSchema from '../src/schemas/primitives/system.schema.json';
import componentSchema from '../src/schemas/primitives/component.schema.json';
import bomSchema from '../src/schemas/primitives/bom.schema.json';
import dataFlowSchema from '../src/schemas/primitives/data-flow.schema.json';
import hdfSystemSchema from '../src/schemas/hdf-system.schema.json';
import { schemaRef } from './schema-ref';

describe('hdf-system.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(bomSchema);
  ajv.addSchema(componentSchema);
  ajv.addSchema(dataFlowSchema);
  const validate = ajv.compile(hdfSystemSchema);

  // -- Minimal valid document --

  const minimal = {
    name: 'Test System',
    components: [{ name: 'AppTier', type: 'application', componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }],
  };

  it('should validate a minimal hdf-system document', () => {
    expect(validate(minimal)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  // -- Fully specified document --

  const full = {
    name: 'Enterprise Portal Production',
    identifier: 'SYS-2024-00142',
    identifierScheme: 'https://emass.mil',
    description: 'Production portal system',
    authorizationStatus: 'authorized',
    authorizationDate: '2025-06-15T00:00:00Z',
    categorizationLevel: 'moderate',
    boundaryDescription: 'All resources in prod VPC (10.0.0.0/16)',
    version: '2.0.0',
    labels: { environment: 'production', agency: 'DOD' },
    generator: { name: 'hdf-cli', version: '0.1.0' },
    integrity: { algorithm: 'sha256', checksum: 'abc123def456' },
    components: [
      {
        name: 'WebTier',
        type: 'application',
        componentId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        description: 'RHEL 9 web servers',
        targetSelector: { 'labels.component': 'WebTier' },
        baselineRefs: ['RHEL9-STIG', 'DISA-Container-STIG'],
        boms: [{ bomType: 'sbom', format: 'cyclonedx', ref: 'https://artifacts.agency.gov/sbom/webtier.cdx.json' }],
        inputOverrides: [
          {
            baselineRef: 'RHEL9-STIG',
            inputName: 'max_concurrent_sessions',
            value: 5,
            justification: 'Admin team needs 5 sessions for shift handoff',
            approvedBy: { type: 'email', identifier: 'issm@agency.gov' },
          },
        ],
      },
      {
        name: 'DatabaseTier',
        type: 'database',
        componentId: '11111111-2222-3333-4444-555555555555',
        targetSelector: { 'labels.component': 'DatabaseTier' },
        baselineRefs: ['PostgreSQL-15-STIG'],
      },
    ],
    dataFlows: [
      {
        from: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        to: '11111111-2222-3333-4444-555555555555',
        protocol: 'jdbc',
        port: 5432,
        direction: 'unidirectional',
        description: 'Web tier connects to database',
      },
    ],
  };

  it('should validate a fully specified hdf-system document', () => {
    expect(validate(full)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  // -- Required fields --

  it('should reject document missing required name', () => {
    const doc = { components: [{ name: 'App', type: 'application', componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject document missing required components', () => {
    const doc = { name: 'Test System' };
    expect(validate(doc)).toBe(false);
  });

  it('should reject document with empty components array', () => {
    const doc = { name: 'Test System', components: [] };
    expect(validate(doc)).toBe(false);
  });

  it('should reject unknown top-level properties', () => {
    const doc = { ...minimal, unknownField: 'bad' };
    expect(validate(doc)).toBe(false);
  });

  // -- systemId --

  it('should accept system with systemId UUID', () => {
    const doc = { ...minimal, systemId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' };
    expect(validate(doc)).toBe(true);
  });

  it('should reject system with invalid systemId', () => {
    const doc = { ...minimal, systemId: 'not-a-uuid' };
    expect(validate(doc)).toBe(false);
  });

  it('should accept system without systemId (optional)', () => {
    expect(validate(minimal)).toBe(true);
  });

  // -- owner --

  it('should accept system with owner Identity', () => {
    const doc = { ...minimal, owner: { type: 'email', identifier: 'platform-team@agency.gov' } };
    expect(validate(doc)).toBe(true);
  });

  it('should accept system with owner including description', () => {
    const doc = { ...minimal, owner: { type: 'other', identifier: 'TEAM-INFRA', description: 'Infrastructure Operations Team' } };
    expect(validate(doc)).toBe(true);
  });

  it('should reject system with invalid owner (missing type)', () => {
    const doc = { ...minimal, owner: { identifier: 'someone@example.com' } };
    expect(validate(doc)).toBe(false);
  });

  // -- Authorization status enum --

  it('should accept all valid authorization statuses', () => {
    const statuses = ['authorized', 'denied', 'pendingAuthorization', 'conditionallyAuthorized', 'notYetRequested', 'revoked'];
    for (const status of statuses) {
      const doc = { ...minimal, authorizationStatus: status };
      expect(validate(doc)).toBe(true);
    }
  });

  it('should reject invalid authorization status', () => {
    const doc = { ...minimal, authorizationStatus: 'expired' };
    expect(validate(doc)).toBe(false);
  });

  // -- Categorization level enum --

  it('should accept all valid categorization levels', () => {
    for (const level of ['low', 'moderate', 'high']) {
      const doc = { ...minimal, categorizationLevel: level };
      expect(validate(doc)).toBe(true);
    }
  });

  it('should reject invalid categorization level', () => {
    const doc = { ...minimal, categorizationLevel: 'critical' };
    expect(validate(doc)).toBe(false);
  });

  // -- Labels --

  it('should accept document with labels', () => {
    const doc = { ...minimal, labels: { env: 'prod', team: 'ops' } };
    expect(validate(doc)).toBe(true);
  });

  it('should reject labels with non-string values', () => {
    const doc = { ...minimal, labels: { count: 42 } };
    expect(validate(doc)).toBe(false);
  });

  // -- Integrity --

  it('should accept document with integrity', () => {
    const doc = { ...minimal, integrity: { algorithm: 'sha256', checksum: 'abc' } };
    expect(validate(doc)).toBe(true);
  });

  // -- Data flows --

  it('should accept document with dataFlows', () => {
    const doc = {
      ...minimal,
      dataFlows: [
        {
          from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          to: '11111111-2222-3333-4444-555555555555',
          protocol: 'https',
          description: 'API calls',
        },
      ],
    };
    expect(validate(doc)).toBe(true);
  });

  it('should accept empty dataFlows array', () => {
    const doc = { ...minimal, dataFlows: [] };
    expect(validate(doc)).toBe(true);
  });

  it('should reject invalid dataFlow items', () => {
    const doc = {
      ...minimal,
      dataFlows: [{ protocol: 'https' }], // missing from + to
    };
    expect(validate(doc)).toBe(false);
  });

  it('should accept cross-system data flow', () => {
    const doc = {
      ...minimal,
      dataFlows: [
        {
          from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          to: { systemRef: '../other-system.json', componentId: '22222222-3333-4444-5555-666666666666' },
          protocol: 'https',
          description: 'Cross-system API call',
        },
      ],
    };
    expect(validate(doc)).toBe(true);
  });

  it('should accept external data flow', () => {
    const doc = {
      ...minimal,
      dataFlows: [
        {
          from: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          to: { external: true, description: 'CDN Provider' },
          protocol: 'https',
          description: 'Public traffic via CDN',
        },
      ],
    };
    expect(validate(doc)).toBe(true);
  });

  // -- Interconnections removed --

  it('should reject interconnections field (replaced by dataFlows)', () => {
    const doc = {
      ...minimal,
      interconnections: [
        { name: 'External API', externalSystem: 'CDN', direction: 'inbound' },
      ],
    };
    expect(validate(doc)).toBe(false);
  });

  // -- Components use full hdf-component type --

  it('should accept component with componentId and externalIds', () => {
    const doc = {
      ...minimal,
      components: [{
        type: 'host',
        name: 'web-server-01',
        componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        externalIds: { aws: 'i-abc123', cmdb: 'ASSET-101' },
      }],
    };
    expect(validate(doc)).toBe(true);
  });
});

describe('system.schema.json — Input_Override', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);

  const validate = ajv.compile({
    ...schemaRef(systemSchema, 'Input_Override'),
  });

  it('should validate a minimal override', () => {
    expect(validate({ inputName: 'max_sessions', value: 5 })).toBe(true);
  });

  it('should validate a full override with approvedBy', () => {
    const override = {
      baselineRef: 'RHEL9-STIG',
      inputName: 'max_sessions',
      value: 5,
      justification: 'Shift handoff requires more sessions',
      approvedBy: { type: 'email', identifier: 'issm@agency.gov' },
    };
    expect(validate(override)).toBe(true);
  });

  it('should reject override missing inputName', () => {
    expect(validate({ value: 5 })).toBe(false);
  });

  it('should reject override missing value', () => {
    expect(validate({ inputName: 'max_sessions' })).toBe(false);
  });

  it('should accept any JSON type for value', () => {
    for (const value of [42, 'string', true, [1, 2], { key: 'val' }]) {
      expect(validate({ inputName: 'test', value })).toBe(true);
    }
  });

  it('should reject unknown properties', () => {
    expect(validate({ inputName: 'test', value: 1, extra: 'bad' })).toBe(false);
  });
});

describe('system.schema.json — Control_Designation', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);

  const validate = ajv.compile({
    ...schemaRef(systemSchema, 'Control_Designation'),
  });

  const minimal = {
    controlId: 'SC-7',
    designation: 'common',
    description: 'Network boundary protection provided by cloud platform.',
  };

  it('should validate a minimal designation (controlId + designation + description)', () => {
    expect(validate(minimal)).toBe(true);
  });

  it('should validate a designation with providedBy (local component UUID)', () => {
    const desig = { ...minimal, providedBy: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' };
    expect(validate(desig)).toBe(true);
  });

  it('should reject providedBy that is not a valid UUID', () => {
    const desig = { ...minimal, providedBy: 'not-a-uuid' };
    expect(validate(desig)).toBe(false);
  });

  it('should validate a designation with systemRef (cross-system provider)', () => {
    const desig = { ...minimal, systemRef: '../network-team/waf-system.json' };
    expect(validate(desig)).toBe(true);
  });

  it('should validate a designation with inheritedBy array of UUIDs', () => {
    const desig = {
      ...minimal,
      inheritedBy: [
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      ],
    };
    expect(validate(desig)).toBe(true);
  });

  it('should reject inheritedBy with non-UUID strings', () => {
    const desig = { ...minimal, inheritedBy: ['not-a-uuid'] };
    expect(validate(desig)).toBe(false);
  });

  it('should accept all valid designation enum values', () => {
    for (const d of ['common', 'system-specific', 'hybrid']) {
      expect(validate({ ...minimal, designation: d })).toBe(true);
    }
  });

  it('should reject invalid designation value', () => {
    expect(validate({ ...minimal, designation: 'delegated' })).toBe(false);
  });

  it('should reject missing controlId', () => {
    const obj = { designation: 'common', description: 'test' };
    expect(validate(obj)).toBe(false);
  });

  it('should reject missing designation', () => {
    const obj = { controlId: 'SC-7', description: 'test' };
    expect(validate(obj)).toBe(false);
  });

  it('should reject missing description', () => {
    const obj = { controlId: 'SC-7', designation: 'common' };
    expect(validate(obj)).toBe(false);
  });

  it('should reject unknown properties', () => {
    expect(validate({ ...minimal, extra: 'bad' })).toBe(false);
  });

  it('should validate a full designation with all optional fields', () => {
    const full = {
      controlId: 'AC-2',
      designation: 'hybrid',
      providedBy: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      systemRef: '../auth/keycloak-system.json',
      inheritedBy: ['11111111-2222-3333-4444-555555555555'],
      description: 'Account lifecycle provided by Keycloak; RBAC implemented locally.',
    };
    expect(validate(full)).toBe(true);
  });

  it('should validate external-only designation (no providedBy or systemRef)', () => {
    const external = {
      controlId: 'PE-2',
      designation: 'common',
      description: 'Physical access provided by AWS GovCloud per FedRAMP High authorization.',
    };
    expect(validate(external)).toBe(true);
  });
});

describe('hdf-system.schema.json — controlDesignations array', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(bomSchema);
  ajv.addSchema(componentSchema);
  ajv.addSchema(dataFlowSchema);
  const validate = ajv.compile(hdfSystemSchema);

  const minimalSystem = {
    name: 'Test System',
    components: [{ name: 'AppTier', type: 'application', componentId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }],
  };

  it('should validate a system document with controlDesignations', () => {
    const doc = {
      ...minimalSystem,
      controlDesignations: [
        {
          controlId: 'IA-2',
          designation: 'common',
          description: 'SSO provides authentication.',
        },
      ],
    };
    expect(validate(doc)).toBe(true);
  });

  it('should validate a system document with empty controlDesignations array', () => {
    const doc = { ...minimalSystem, controlDesignations: [] };
    expect(validate(doc)).toBe(true);
  });

  it('should validate a system document without controlDesignations (optional)', () => {
    expect(validate(minimalSystem)).toBe(true);
  });

  it('should reject controlDesignations with invalid items', () => {
    const doc = {
      ...minimalSystem,
      controlDesignations: [{ controlId: 'SC-7' }], // missing designation + description
    };
    expect(validate(doc)).toBe(false);
  });

  it('should validate a system with multiple designations', () => {
    const doc = {
      ...minimalSystem,
      controlDesignations: [
        {
          controlId: 'IA-2',
          designation: 'common',
          providedBy: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          description: 'Authentication by SSO.',
        },
        {
          controlId: 'PE-2',
          designation: 'common',
          description: 'Physical security by AWS.',
        },
        {
          controlId: 'AC-2',
          designation: 'hybrid',
          description: 'Account lifecycle shared between IdP and apps.',
        },
      ],
    };
    expect(validate(doc)).toBe(true);
  });
});
