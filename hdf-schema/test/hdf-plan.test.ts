import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import systemSchema from '../src/schemas/primitives/system.schema.json';
import planSchema from '../src/schemas/primitives/plan.schema.json';
import hdfPlanSchema from '../src/schemas/hdf-plan.schema.json';

describe('hdf-plan.schema.json', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(planSchema);
  const validate = ajv.compile(hdfPlanSchema);

  const minimal = {
    name: 'Test Plan',
    assessments: [{ baselineRef: 'RHEL9-STIG' }],
  };

  it('should validate a minimal plan', () => {
    expect(validate(minimal)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  const full = {
    name: 'Portal Monthly Assessment',
    type: 'automated',
    description: 'Monthly compliance scan of portal production',
    systemRef: 'portal-prod.hdf-system.json',
    version: '1.0.0',
    labels: { environment: 'production', cadence: 'monthly' },
    generator: { name: 'hdf-cli', version: '0.1.0' },
    checksum: { algorithm: 'sha256', value: 'abc123' },
    assessments: [
      {
        baselineRef: 'RHEL9-STIG',
        targetSelector: { 'labels.component': 'WebTier' },
        inputs: { max_concurrent_sessions: 5, password_min_length: 15 },
        runner: { name: 'cinc-auditor', version: '6.8.1' },
        description: 'STIG compliance for web tier',
      },
      {
        baselineRef: 'PostgreSQL-15-STIG',
        targetSelector: { 'labels.component': 'DatabaseTier' },
      },
    ],
    schedule: {
      cron: '0 2 1 * *',
      startDate: '2026-01-01T00:00:00Z',
      endDate: '2026-12-31T23:59:59Z',
      notifyOnRegression: ['security-team@agency.gov'],
      notifyOnCompletion: ['compliance@agency.gov'],
    },
  };

  it('should validate a fully specified plan', () => {
    expect(validate(full)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  // -- Required fields --

  it('should reject plan missing name', () => {
    expect(validate({ assessments: [{ baselineRef: 'X' }] })).toBe(false);
  });

  it('should reject plan missing assessments', () => {
    expect(validate({ name: 'Test' })).toBe(false);
  });

  it('should reject plan with empty assessments array', () => {
    expect(validate({ name: 'Test', assessments: [] })).toBe(false);
  });

  it('should reject unknown top-level properties', () => {
    expect(validate({ ...minimal, unknownField: 'bad' })).toBe(false);
  });

  // -- Plan type enum --

  it('should accept all valid plan types', () => {
    for (const type of ['automated', 'manual', 'hybrid']) {
      expect(validate({ ...minimal, type })).toBe(true);
    }
  });

  it('should reject invalid plan type', () => {
    expect(validate({ ...minimal, type: 'continuous' })).toBe(false);
  });

  // -- Labels --

  it('should accept plan with labels', () => {
    expect(validate({ ...minimal, labels: { env: 'prod' } })).toBe(true);
  });

  it('should reject labels with non-string values', () => {
    expect(validate({ ...minimal, labels: { count: 42 } })).toBe(false);
  });
});

describe('plan.schema.json — Assessment', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(planSchema);

  const validate = ajv.compile({
    $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/plan/v2.0.0#/$defs/Assessment',
  });

  it('should validate a minimal assessment', () => {
    expect(validate({ baselineRef: 'RHEL9-STIG' })).toBe(true);
  });

  it('should validate assessment with all fields', () => {
    const assessment = {
      baselineRef: 'RHEL9-STIG',
      targetSelector: { 'labels.component': 'WebTier' },
      inputs: { max_sessions: 5 },
      runner: { name: 'inspec', version: '6.0' },
      description: 'Web tier scan',
    };
    expect(validate(assessment)).toBe(true);
  });

  it('should reject assessment missing baselineRef', () => {
    expect(validate({ inputs: { x: 1 } })).toBe(false);
  });

  it('should reject assessment with unknown properties', () => {
    expect(validate({ baselineRef: 'X', extra: 'bad' })).toBe(false);
  });

  it('should accept assessment with empty inputs', () => {
    expect(validate({ baselineRef: 'X', inputs: {} })).toBe(true);
  });
});

describe('plan.schema.json — Schedule', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(planSchema);

  const validate = ajv.compile({
    $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/plan/v2.0.0#/$defs/Schedule',
  });

  it('should validate a minimal schedule', () => {
    expect(validate({ cron: '0 2 * * *' })).toBe(true);
  });

  it('should validate schedule with all fields', () => {
    const schedule = {
      cron: '0 2 1 * *',
      startDate: '2026-01-01T00:00:00Z',
      endDate: '2026-12-31T23:59:59Z',
      notifyOnRegression: ['team@example.com'],
      notifyOnCompletion: ['ops@example.com'],
    };
    expect(validate(schedule)).toBe(true);
  });

  it('should validate empty schedule', () => {
    expect(validate({})).toBe(true);
  });

  it('should reject schedule with unknown properties', () => {
    expect(validate({ cron: '* * * * *', timezone: 'UTC' })).toBe(false);
  });

  it('should reject invalid startDate format', () => {
    expect(validate({ startDate: 'not-a-date' })).toBe(false);
  });

  it('should reject notifyOnRegression with non-string items', () => {
    expect(validate({ notifyOnRegression: [42] })).toBe(false);
  });
});

describe('plan.schema.json — Runner_Config', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(planSchema);

  const validate = ajv.compile({
    $ref: 'https://mitre.github.io/hdf-libs/schemas/primitives/plan/v2.0.0#/$defs/Runner_Config',
  });

  it('should validate a runner config', () => {
    expect(validate({ name: 'inspec', version: '6.0' })).toBe(true);
  });

  it('should validate empty runner config', () => {
    expect(validate({})).toBe(true);
  });

  it('should reject runner with unknown properties', () => {
    expect(validate({ name: 'inspec', args: ['--no-color'] })).toBe(false);
  });
});
