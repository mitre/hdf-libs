import { describe, it, expect, beforeAll } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { createAjvWithPrimitives, loadSchema } from './setup';

const testDirname = path.dirname(fileURLToPath(import.meta.url));

function createMinimalAfterRequirement(): Record<string, unknown> {
  return {
    id: 'RHEL-09-255065',
    impact: 0.5,
    tags: {},
    descriptions: [
      { label: 'default', data: 'The SSH server must use FIPS-validated ciphers.' },
    ],
    results: [
      { status: 'passed', codeDesc: 'SSH FIPS ciphers configured', startTime: '2026-07-22T14:03:11Z' },
    ],
  };
}

function createMinimalChangeEvent(): Record<string, unknown> {
  return {
    eventId: '0190f6f2-1c4e-7c3a-9f2a-3b1d5e7a9c01',
    source: 'inspec://web01/rhel9-stig',
    sequence: 412,
    systemRef: 'apptier.hdf-system.json',
    componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
    timestamp: '2026-07-22T14:03:11Z',
    priorChecksum: {
      algorithm: 'sha256',
      value: '704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021',
    },
    requirementId: 'RHEL-09-255065',
    state: 'fixed',
    changeReasons: ['resultChanged'],
    before: { effectiveStatus: 'failed', effectiveImpact: 0.5 },
    after: createMinimalAfterRequirement(),
  };
}

describe('hdf-requirement-change-event.schema.json', () => {
  let ajv: Ajv2020;
  let validate: ReturnType<Ajv2020['compile']>;

  beforeAll(() => {
    ajv = createAjvWithPrimitives();
    // The event schema $refs hdf-results for the full after payload.
    ajv.addSchema(loadSchema('hdf-results.schema.json'));
    validate = ajv.compile(loadSchema('hdf-requirement-change-event.schema.json'));
  });

  describe('metaschema validation', () => {
    it('validates against the JSON Schema 2020-12 metaschema', () => {
      const schema = loadSchema('hdf-requirement-change-event.schema.json');
      const isValid = ajv.validateSchema(schema);
      if (!isValid) console.error('Metaschema validation errors:', ajv.errors);
      expect(isValid).toBe(true);
    });
  });

  describe('minimal valid event', () => {
    it('validates a minimal fixed event', () => {
      const doc = createMinimalChangeEvent();
      const isValid = validate(doc);
      if (!isValid) console.error('Validation errors:', validate.errors);
      expect(isValid).toBe(true);
    });
  });

  describe('envelope required fields', () => {
    for (const field of [
      'eventId',
      'source',
      'sequence',
      'systemRef',
      'componentId',
      'timestamp',
      'priorChecksum',
    ]) {
      it(`rejects an event missing ${field}`, () => {
        const doc = createMinimalChangeEvent();
        delete doc[field];
        expect(validate(doc)).toBe(false);
      });
    }
  });

  describe('payload required fields', () => {
    for (const field of ['requirementId', 'state', 'before', 'after']) {
      it(`rejects an event missing ${field}`, () => {
        const doc = createMinimalChangeEvent();
        delete doc[field];
        expect(validate(doc)).toBe(false);
      });
    }
  });

  describe('state vocabulary is the producer-computable subset', () => {
    for (const state of ['new', 'absent', 'updated', 'fixed', 'regressed']) {
      it(`accepts state ${state}`, () => {
        const doc = createMinimalChangeEvent();
        doc.state = state;
        if (state === 'new') {
          doc.before = null;
          doc.priorChecksum = null;
        }
        if (state === 'absent') doc.after = null;
        const isValid = validate(doc);
        if (!isValid) console.error(`state=${state} errors:`, validate.errors);
        expect(isValid).toBe(true);
      });
    }

    for (const state of ['moved', 'split', 'merged', 'unchanged']) {
      it(`rejects batch-only/no-op state ${state}`, () => {
        const doc = createMinimalChangeEvent();
        doc.state = state;
        expect(validate(doc)).toBe(false);
      });
    }
  });

  describe('conditional payload rules', () => {
    it('rejects null after for a non-absent state', () => {
      const doc = createMinimalChangeEvent();
      doc.after = null;
      expect(validate(doc)).toBe(false);
    });

    it('rejects a non-null after for state absent', () => {
      const doc = createMinimalChangeEvent();
      doc.state = 'absent';
      expect(validate(doc)).toBe(false);
    });

    it('accepts null after only for state absent', () => {
      const doc = createMinimalChangeEvent();
      doc.state = 'absent';
      doc.after = null;
      expect(validate(doc)).toBe(true);
    });

    it('rejects null before for a non-new state', () => {
      const doc = createMinimalChangeEvent();
      doc.before = null;
      expect(validate(doc)).toBe(false);
    });

    it('accepts null before and null priorChecksum for state new (chain start)', () => {
      const doc = createMinimalChangeEvent();
      doc.state = 'new';
      doc.before = null;
      doc.priorChecksum = null;
      expect(validate(doc)).toBe(true);
    });

    it('rejects a thin after (must be a full Evaluated_Requirement)', () => {
      const doc = createMinimalChangeEvent();
      doc.after = { effectiveStatus: 'passed', effectiveImpact: 0.5 };
      expect(validate(doc)).toBe(false);
    });
  });

  describe('changeReasons vocabulary is the producer-computable subset', () => {
    for (const reason of [
      'resultChanged',
      'overrideAdded',
      'overrideExpired',
      'overrideRemoved',
      'overrideModified',
      'impactChanged',
      'configChanged',
    ]) {
      it(`accepts changeReason ${reason}`, () => {
        const doc = createMinimalChangeEvent();
        doc.changeReasons = [reason];
        expect(validate(doc)).toBe(true);
      });
    }

    for (const reason of ['baselineUpgraded', 'controlMapped', 'scannerChanged']) {
      it(`rejects batch-only changeReason ${reason}`, () => {
        const doc = createMinimalChangeEvent();
        doc.changeReasons = [reason];
        expect(validate(doc)).toBe(false);
      });
    }
  });

  describe('strictness', () => {
    it('rejects unknown top-level properties', () => {
      const doc = createMinimalChangeEvent();
      doc.unexpected = true;
      expect(validate(doc)).toBe(false);
    });

    it('rejects a non-integer sequence', () => {
      const doc = createMinimalChangeEvent();
      doc.sequence = '412';
      expect(validate(doc)).toBe(false);
    });
  });

  describe('embedded examples', () => {
    it('validates every example in the schema', () => {
      const schema = loadSchema('hdf-requirement-change-event.schema.json');
      const examples = (schema.examples ?? []) as Record<string, unknown>[];
      expect(examples.length).toBeGreaterThanOrEqual(5);
      for (const example of examples) {
        // Strip $comment before validation (documentation, not data) per house convention.
        const data = { ...example };
        delete data.$comment;
        const isValid = validate(data);
        if (!isValid) {
          console.error(
            `Example failed ($comment: ${String(example.$comment)}):`,
            validate.errors,
          );
        }
        expect(isValid).toBe(true);
      }
    });

    it('every example carries a documenting $comment', () => {
      const schema = loadSchema('hdf-requirement-change-event.schema.json');
      const examples = (schema.examples ?? []) as Record<string, unknown>[];
      for (const [idx, example] of examples.entries()) {
        expect(typeof example.$comment, `example ${idx} missing $comment`).toBe('string');
      }
    });

    it('covers every producer-computable state across examples', () => {
      const schema = loadSchema('hdf-requirement-change-event.schema.json');
      const examples = (schema.examples ?? []) as Record<string, unknown>[];
      const states = new Set(examples.map((e) => e.state));
      for (const state of ['new', 'absent', 'updated', 'fixed', 'regressed']) {
        expect(states.has(state), `missing example for state ${state}`).toBe(true);
      }
    });
  });
});

describe('subset vocabularies stay anchored to the comparison vocabulary', () => {
  // The event enums are declared as distinct named types (stable generated
  // Go/TS names) rather than $ref intersections; this test is the anchor
  // that prevents silent drift from the parent enums.
  const loadPrimitive = (name: string) =>
    JSON.parse(
      fs.readFileSync(path.join(testDirname, '../src/schemas/primitives', name), 'utf-8'),
    );

  it('Event_Requirement_State is a subset of Requirement_State', () => {
    const comparison = loadPrimitive('comparison.schema.json');
    const events = loadPrimitive('events.schema.json');
    const parent = new Set(comparison.$defs.Requirement_State.enum as string[]);
    for (const value of events.$defs.Event_Requirement_State.enum as string[]) {
      expect(parent.has(value), `${value} missing from Requirement_State`).toBe(true);
    }
  });

  it('Event_Change_Reason is a subset of Change_Reason', () => {
    const comparison = loadPrimitive('comparison.schema.json');
    const events = loadPrimitive('events.schema.json');
    const parent = new Set(comparison.$defs.Change_Reason.enum as string[]);
    for (const value of events.$defs.Event_Change_Reason.enum as string[]) {
      expect(parent.has(value), `${value} missing from Change_Reason`).toBe(true);
    }
  });
});
