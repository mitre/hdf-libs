import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'vitest';
import { loadSchemaValidator, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import { convertHdfToOscalPoam } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// NIST OSCAL v1.1.2 POA&M schema (draft-07). See ../schemas/PROVENANCE.md.
const validate = loadSchemaValidator(join(__dirname, '..', 'schemas', 'oscal_poam_schema-v1.1.2.json'));

const amendments = JSON.stringify({
  name: 'test-poam',
  overrides: [
    {
      type: 'poam',
      requirementId: 'AC-1',
      reason: 'Pending remediation',
      status: 'failed',
      appliedBy: { type: 'simple', identifier: 'admin@example.com' },
      appliedAt: '2026-01-15T00:00:00Z',
      expiresAt: '2027-01-15T00:00:00Z',
    },
  ],
});

describe('hdf-to-oscal-poam output validates against NIST OSCAL v1.1.2 POA&M schema', () => {
  it('minimal poam override', async () => {
    const out = JSON.parse(await convertHdfToOscalPoam(amendments)) as unknown;
    assertSchemaValid(validate, 'minimal poam override', out);
  });
});
