import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { loadSchemaValidator, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import { amendmentsCorpus, runSchemaCorpus } from '../../../shared/typescript/schema-corpus.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';
import { readFileSync } from 'node:fs';
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

// The shared corpus holds this converter to both contracts an exporter owes,
// rather than only to fully-populated fixtures — the gap that let the defects in
// issue #236 ship.
describe('hdf-to-oscal-poam against the adversarial corpus', () => {
  it('satisfies both corpus contracts', async () => {
    await runSchemaCorpus(validate, amendmentsCorpus(), (input) =>
      convertHdfToOscalPoam(input),
    );
  });
});

describe('hdf-to-oscal-poam rejects input it cannot faithfully convert', () => {
  // Before the structural guard the converter zero-filled an arbitrary JSON
  // object into an amendments shape and emitted a confident, empty,
  // schema-invalid document with no error — the core complaint in issue #236.
  it.each([
    ['arbitrary object', '{"foo":"bar"}'],
    ['empty object', '{}'],
    ['missing overrides', '{"name":"a"}'],
    ['empty overrides', '{"name":"a","overrides":[]}'],
    ['top-level array', '[]'],
    ['top-level null', 'null'],
  ])('rejects %s', async (_label, input) => {
    await expect(convertHdfToOscalPoam(input)).rejects.toThrow();
  });
});

describe('hdf-to-oscal-poam required risk text', () => {
  it('never omits a risk statement when the override reason is empty', async () => {
    // HDF puts no minLength on reason, so this is reachable from a schema-valid
    // document; OSCAL lists statement as required alongside title and status.
    const input = JSON.stringify({
      name: 't',
      overrides: [
        {
          type: 'poam',
          requirementId: 'AC-1',
          reason: '',
          status: 'failed',
          appliedBy: { type: 'simple', identifier: 'a@example.com' },
          appliedAt: '2026-01-15T00:00:00Z',
          expiresAt: '2027-01-15T00:00:00Z',
        },
      ],
    });

    const out = JSON.parse(await convertHdfToOscalPoam(input)) as {
      'plan-of-action-and-milestones': {
        risks: Array<{ statement?: string; description?: string; title?: string }>;
      };
    };
    const risk = out['plan-of-action-and-milestones'].risks[0];
    expect(risk.statement).toBeTruthy();
    expect(risk.description).toBeTruthy();
    expect(risk.title).toBeTruthy();
  });
});

// Whole-output equality against the SAME goldens the Go TestCorpusGoldenParity
// freezes. This is what makes the cross-language claim checkable: the corpus
// exercises the sparse inputs (empty reason, no milestones, undescribed
// evidence) where the two implementations are most likely to drift, which the
// single happy-path golden never touched. Fresh UUIDs and the conversion
// timestamp are masked; the UUID reference graph survives masking, so wiring
// differences still fail.
describe('hdf-to-oscal-poam corpus golden parity (TS↔Go)', () => {
  const POAM_VOLATILE = ['last-modified'];

  it.each(amendmentsCorpus().filter((c) => c.hdfValid).map((c) => [c.name, c] as const))(
    '%s matches the Go-frozen golden',
    async (_name, c) => {
      const out = await convertHdfToOscalPoam(c.input);
      const golden = readFileSync(
        join(__dirname, '..', 'fixtures', 'expected', `corpus-${c.name}.oscal-poam.json`),
        'utf-8',
      );

      expect(maskVolatileJson(JSON.parse(out), POAM_VOLATILE)).toEqual(
        maskVolatileJson(JSON.parse(golden), POAM_VOLATILE),
      );
    },
  );
});

