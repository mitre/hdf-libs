import { describe, it, expect, beforeAll } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  createAjvWithPrimitives,
  loadSchema,
  createMinimalComparisonDoc,
  createMinimalRequirement,
} from './setup';

describe('hdf-comparison.schema.json', () => {
  let ajv: Ajv2020;
  let validate: ReturnType<Ajv2020['compile']>;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    // The comparison schema $refs into hdf-results for Evaluated_Requirement,
    // so we must register hdf-results before compiling the comparison schema.
    ajv.addSchema(loadSchema('hdf-results.schema.json'));
    validate = ajv.compile(loadSchema('hdf-comparison.schema.json'));
  });

  describe('metaschema validation', () => {
    it('should validate hdf-comparison.schema.json against JSON Schema 2020-12 metaschema', () => {
      const schema = loadSchema('hdf-comparison.schema.json');
      const isValid = ajv.validateSchema(schema);
      if (!isValid) {
        console.error('Metaschema validation errors:', ajv.errors);
      }
      expect(isValid).toBe(true);
    });
  });

  describe('minimal valid document', () => {
    it('should validate a minimal valid comparison document', () => {
      const doc = createMinimalComparisonDoc();
      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', validate.errors);
      }
      expect(isValid).toBe(true);
      expect(validate.errors).toBeNull();
    });
  });

  describe('required fields', () => {
    it('should reject document missing formatVersion', () => {
      const doc = createMinimalComparisonDoc();
      delete (doc as Record<string, unknown>).formatVersion;
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should reject document missing comparisonMode', () => {
      const doc = createMinimalComparisonDoc();
      delete (doc as Record<string, unknown>).comparisonMode;
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should reject document missing sources', () => {
      const doc = createMinimalComparisonDoc();
      delete (doc as Record<string, unknown>).sources;
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should reject document missing summary', () => {
      const doc = createMinimalComparisonDoc();
      delete (doc as Record<string, unknown>).summary;
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should reject document missing requirementDiffs', () => {
      const doc = createMinimalComparisonDoc();
      delete (doc as Record<string, unknown>).requirementDiffs;
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });

  describe('invalid comparisonMode', () => {
    it('should reject an invalid comparison mode', () => {
      const doc = createMinimalComparisonDoc({ comparisonMode: 'invalid_mode' });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });

  describe('sources minimum items', () => {
    it('should reject sources array with fewer than 2 items', () => {
      const doc = createMinimalComparisonDoc({
        sources: [{ role: 'old', label: 'Only one source' }],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should reject empty sources array', () => {
      const doc = createMinimalComparisonDoc({ sources: [] });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });

  describe('invalid source role', () => {
    it('should reject a source with an invalid role', () => {
      const doc = createMinimalComparisonDoc({
        sources: [
          { role: 'invalid_role', label: 'Bad source' },
          { role: 'new', label: 'After scan' },
        ],
      });
      expect(validate(doc)).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });

  describe('RequirementDiff with full before/after', () => {
    it('should accept a RequirementDiff with state "fixed" and full EvaluatedRequirement before/after', () => {
      const beforeReq = createMinimalRequirement({
        id: 'SV-100001',
        results: [
          {
            status: 'failed',
            codeDesc: 'Check failed before remediation',
            startTime: '2025-11-20T10:00:00Z',
          },
        ],
      });
      const afterReq = createMinimalRequirement({
        id: 'SV-100001',
        results: [
          {
            status: 'passed',
            codeDesc: 'Check passed after remediation',
            startTime: '2025-11-25T10:00:00Z',
          },
        ],
      });

      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-100001',
            state: 'fixed',
            changeReasons: ['resultChanged'],
            before: beforeReq,
            after: afterReq,
            fieldChanges: [
              {
                op: 'replace',
                path: '/results/0/status',
                oldValue: 'failed',
                newValue: 'passed',
              },
            ],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 1,
          unmatchedOldCount: 0,
          unmatchedNewCount: 0,
          fixed: 1,
        },
      });

      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });

    it('should accept the amendment-axis change reasons the diff engine emits', () => {
      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-100001',
            state: 'updated',
            changeReasons: ['dispositionChanged', 'effectiveImpactChanged'],
            before: createMinimalRequirement({ id: 'SV-100001' }),
            after: createMinimalRequirement({ id: 'SV-100001' }),
            fieldChanges: [
              {
                op: 'replace',
                path: '/disposition',
                oldValue: 'riskAdjustment',
                newValue: 'waiver',
              },
            ],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 1,
          unmatchedOldCount: 0,
          unmatchedNewCount: 0,
          updated: 1,
        },
      });

      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });

  describe('RequirementDiff with null before (state=new)', () => {
    it('should accept a RequirementDiff where before is null', () => {
      const afterReq = createMinimalRequirement({ id: 'SV-200001' });

      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-200001',
            state: 'new',
            changeReasons: ['resultChanged'],
            before: null,
            after: afterReq,
            fieldChanges: [],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 0,
          unmatchedOldCount: 0,
          unmatchedNewCount: 1,
          new: 1,
        },
      });

      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });

  describe('RequirementDiff with null after (state=absent)', () => {
    it('should accept a RequirementDiff where after is null', () => {
      const beforeReq = createMinimalRequirement({ id: 'SV-300001' });

      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-300001',
            state: 'absent',
            changeReasons: ['resultChanged'],
            before: beforeReq,
            after: null,
            fieldChanges: [],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 0,
          unmatchedOldCount: 1,
          unmatchedNewCount: 0,
          absent: 1,
        },
      });

      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });

  describe('all comparison modes accepted', () => {
    const modes = ['temporal', 'baseline', 'fleet', 'multiSource'];

    for (const mode of modes) {
      it(`should accept comparisonMode "${mode}"`, () => {
        const doc = createMinimalComparisonDoc({ comparisonMode: mode });
        const isValid = validate(doc);
        if (!isValid) {
          console.error(`Validation errors for mode "${mode}":`, validate.errors);
        }
        expect(isValid).toBe(true);
      });
    }
  });

  describe('optional fields accepted', () => {
    it('should accept timestamp', () => {
      const doc = createMinimalComparisonDoc({
        timestamp: '2025-12-01T10:00:00Z',
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept generator', () => {
      const doc = createMinimalComparisonDoc({
        generator: { name: 'hdf-diff', version: '1.0.0' },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept matching config', () => {
      const doc = createMinimalComparisonDoc({
        matching: {
          primaryStrategy: 'exactId',
          fallbackStrategies: ['cciMatch', 'fuzzyTitle'],
          minimumConfidence: 0.8,
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept baselineDiffs', () => {
      const doc = createMinimalComparisonDoc({
        baselineDiffs: [
          {
            name: 'ubuntu-22.04-stig',
            state: 'updated',
            oldVersion: '1.0.0',
            newVersion: '1.1.0',
          },
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept drift array', () => {
      const afterReq = createMinimalRequirement({ id: 'SV-DRIFT-001' });
      const doc = createMinimalComparisonDoc({
        drift: [
          {
            id: 'SV-DRIFT-001',
            state: 'updated',
            changeReasons: ['metadataChanged'],
            before: null,
            after: afterReq,
            fieldChanges: [],
          },
        ],
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept annotations map', () => {
      const doc = createMinimalComparisonDoc({
        annotations: {
          'ann-1': { label: 'Remediation note' },
          'ann-2': {
            label: 'Drift detected',
            description: 'Configuration drift detected in firewall rules',
            category: 'drift',
            needsConfirmation: true,
          },
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept integrity', () => {
      const doc = createMinimalComparisonDoc({
        integrity: {
          algorithm: 'sha256',
          checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept extensions', () => {
      const doc = createMinimalComparisonDoc({
        extensions: {
          customField: 'custom value',
          nestedData: { key: 'value' },
        },
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('annotations map', () => {
    it('should accept annotations with string keys mapping to Annotation objects', () => {
      const doc = createMinimalComparisonDoc({
        annotations: {
          'remediation-001': {
            label: 'Apply patch XYZ',
            description: 'Install security patch XYZ to fix the regression',
            category: 'remediation',
            needsConfirmation: false,
          },
          'waiver-002': {
            label: 'Waived by CISO',
            category: 'waiver',
          },
        },
      });
      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', validate.errors);
      }
      expect(isValid).toBe(true);
    });

    it('should reject annotation with invalid category', () => {
      const doc = createMinimalComparisonDoc({
        annotations: {
          'bad-ann': {
            label: 'Bad annotation',
            category: 'invalidCategory',
          },
        },
      });
      expect(validate(doc)).toBe(false);
    });
  });

  describe('BaselineDiff', () => {
    it('should accept a valid baseline diff with state "updated"', () => {
      const doc = createMinimalComparisonDoc({
        baselineDiffs: [
          {
            name: 'rhel-9-stig',
            state: 'updated',
            oldVersion: 'V1R1',
            newVersion: 'V1R2',
            mappingSource: 'DISA STIG ID mapping table',
          },
        ],
      });
      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', validate.errors);
      }
      expect(isValid).toBe(true);
    });

    it('should reject a baseline diff with invalid state', () => {
      const doc = createMinimalComparisonDoc({
        baselineDiffs: [
          {
            name: 'test-baseline',
            state: 'invalidState',
          },
        ],
      });
      expect(validate(doc)).toBe(false);
    });
  });

  describe('FieldChange', () => {
    it('should accept a valid field change with op "replace"', () => {
      const beforeReq = createMinimalRequirement({
        id: 'SV-FC-001',
        impact: 0.5,
        results: [
          {
            status: 'failed',
            codeDesc: 'Old check',
            startTime: '2025-11-20T10:00:00Z',
          },
        ],
      });
      const afterReq = createMinimalRequirement({
        id: 'SV-FC-001',
        impact: 0.7,
        results: [
          {
            status: 'passed',
            codeDesc: 'New check',
            startTime: '2025-11-25T10:00:00Z',
          },
        ],
      });

      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-FC-001',
            state: 'fixed',
            changeReasons: ['resultChanged', 'impactChanged'],
            before: beforeReq,
            after: afterReq,
            fieldChanges: [
              {
                op: 'replace',
                path: '/impact',
                oldValue: 0.5,
                newValue: 0.7,
              },
              {
                op: 'replace',
                path: '/results/0/status',
                oldValue: 'failed',
                newValue: 'passed',
              },
            ],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 1,
          unmatchedOldCount: 0,
          unmatchedNewCount: 0,
          fixed: 1,
        },
      });

      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });

    it('should accept a field change with op "add"', () => {
      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-FC-002',
            state: 'updated',
            changeReasons: ['metadataChanged'],
            before: createMinimalRequirement({ id: 'SV-FC-002' }),
            after: createMinimalRequirement({ id: 'SV-FC-002' }),
            fieldChanges: [
              {
                op: 'add',
                path: '/tags/severity',
                newValue: 'high',
              },
            ],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 1,
          unmatchedOldCount: 0,
          unmatchedNewCount: 0,
        },
      });
      expect(validate(doc)).toBe(true);
    });

    it('should accept a field change with op "remove"', () => {
      const doc = createMinimalComparisonDoc({
        requirementDiffs: [
          {
            id: 'SV-FC-003',
            state: 'updated',
            changeReasons: ['metadataChanged'],
            before: createMinimalRequirement({ id: 'SV-FC-003' }),
            after: createMinimalRequirement({ id: 'SV-FC-003' }),
            fieldChanges: [
              {
                op: 'remove',
                path: '/tags/obsoleteTag',
                oldValue: 'value',
              },
            ],
          },
        ],
        summary: {
          total: 1,
          matchedCount: 1,
          unmatchedOldCount: 0,
          unmatchedNewCount: 0,
        },
      });
      expect(validate(doc)).toBe(true);
    });
  });

  describe('summary with severity breakdown', () => {
    it('should accept a summary with bySeverity populated', () => {
      const doc = createMinimalComparisonDoc({
        summary: {
          total: 100,
          matchedCount: 90,
          unmatchedOldCount: 5,
          unmatchedNewCount: 5,
          fixed: 10,
          regressed: 3,
          unchanged: 77,
          new: 5,
          absent: 5,
          oldCompliancePercent: 75.5,
          newCompliancePercent: 82.3,
          complianceDelta: 6.8,
          averageMatchConfidence: 0.95,
          bySeverity: {
            critical: {
              fixed: 2,
              regressed: 1,
              unchanged: 5,
            },
            high: {
              fixed: 5,
              regressed: 2,
              unchanged: 20,
              new: 3,
            },
            medium: {
              fixed: 3,
              unchanged: 40,
              absent: 2,
            },
            low: {
              unchanged: 12,
              new: 2,
              absent: 3,
            },
          },
          perSource: [
            {
              sourceIndex: 0,
              label: 'Before scan',
              unchanged: 77,
              absent: 5,
            },
            {
              sourceIndex: 1,
              label: 'After scan',
              unchanged: 77,
              new: 5,
              fixed: 10,
              regressed: 3,
            },
          ],
        },
      });

      const isValid = validate(doc);
      if (!isValid) {
        console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
      }
      expect(isValid).toBe(true);
    });
  });

  describe('unevaluatedProperties rejection', () => {
    it('should reject unknown top-level properties', () => {
      const doc = createMinimalComparisonDoc({
        unknownField: 'should be rejected',
      });
      expect(validate(doc)).toBe(false);
    });
  });
});
