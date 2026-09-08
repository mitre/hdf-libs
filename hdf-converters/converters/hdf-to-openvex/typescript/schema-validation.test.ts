import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { loadSchemaValidator, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import {
  amendmentsCorpus,
  canonicalJSON,
  runSchemaCorpus,
  jsonDocumentValidator,
} from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToOpenVex } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// OpenVEX v0.2.0 schema (draft 2020-12). Vendored under openvex-to-hdf/fixtures.
const validate = loadSchemaValidator(
  join(__dirname, '..', '..', 'openvex-to-hdf', 'fixtures', 'openvex_json_schema.json'),
);
/** The HDF schema the converter's own inputs must satisfy. */
const validateHdfAmendments = loadSchemaValidator(
  join(__dirname, '..', '..', '..', '..', 'hdf-validators', 'go', 'schemas', 'hdf-amendments.schema.json'),
);
const loadInput = (name: string): string =>
  readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');

/**
 * One row of the shared Go/TS table pinning the text OpenVEX demands on a
 * statement. An expected value of '' means the field must be absent — the schema
 * requires the fields to be PRESENT, so a present-but-empty string passes
 * validation while telling a consumer nothing.
 */
interface StatementTextCase {
  name: string;
  override: {
    type: string;
    requirementId: string;
    status: string;
    reason: string;
    justification?: string;
    affectedPackages?: unknown[];
    milestones?: unknown[];
  };
  status: string;
  actionStatement: string;
  impactStatement: string;
  justification: string;
  why: string;
}

const TEXT_CASES = (
  JSON.parse(
    readFileSync(
      join(__dirname, '..', '..', '..', 'shared', 'openvex-statement-text-cases.json'),
      'utf-8',
    ),
  ) as { cases: StatementTextCase[] }
).cases;

/**
 * Renders a case as an HDF Amendments document, asserted valid against the HDF
 * schema first: a converter fed input its own schema rejects proves nothing
 * about what it does with real documents.
 */
function caseInput(c: StatementTextCase): string {
  const o = testhdf.override(c.override.type, c.override.requirementId, {
    status: c.override.status,
    reason: c.override.reason,
    ...(c.override.milestones && { milestones: c.override.milestones }),
  }) as Record<string, unknown>;
  if (c.override.justification) o.justification = c.override.justification;
  if (c.override.affectedPackages) o.affectedPackages = c.override.affectedPackages;

  const input = JSON.stringify(testhdf.amendments('openvex statement text', o as never));
  assertSchemaValid(validateHdfAmendments, `${c.name} (test input)`, JSON.parse(input));
  return input;
}

type EmittedStatement = Record<string, unknown> & {
  status: string;
  vulnerability: { name: string };
};

async function statementFor(c: StatementTextCase): Promise<EmittedStatement> {
  const out = JSON.parse(await convertHdfToOpenVex(caseInput(c), '1.0.0')) as {
    statements: EmittedStatement[];
  };
  expect(out.statements).toHaveLength(1);
  return out.statements[0]!;
}

describe('hdf-to-openvex output validates against OpenVEX v0.2.0 schema', () => {
  it.each(['multi-status-amendments.json', 'spring-boot-log4j-amendments.json'])('%s', async (name) => {
    const out = JSON.parse(await convertHdfToOpenVex(loadInput(name), '1.0.0')) as unknown;
    assertSchemaValid(validate, name, out);
  });

  // The shared table cases run here too: the conditional requirements they probe
  // are schema rules, so the schema is what must judge them.
  it.each(TEXT_CASES.map((c) => [c.name, c] as const))('%s', async (name, c) => {
    const out = JSON.parse(await convertHdfToOpenVex(caseInput(c), '1.0.0')) as unknown;
    assertSchemaValid(validate, name, out);
  });
});

// The rule is implemented once per language, so the expectations live in one
// shared file both read. Presence is asserted on the parsed JSON rather than a
// typed statement: every field here is optional, so an absent one and an empty
// one are indistinguishable once decoded — which is how a dropped required field
// went unnoticed.
describe('hdf-to-openvex statement text matches the shared table', () => {
  it('has a populated shared table', () => {
    expect(TEXT_CASES.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(TEXT_CASES.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    const s = await statementFor(c);
    expect(s.status, c.why).toBe(c.status);
    for (const [key, want] of [
      ['action_statement', c.actionStatement],
      ['impact_statement', c.impactStatement],
      ['justification', c.justification],
    ] as const) {
      if (want === '') expect(s, `${key} must be absent (${c.why})`).not.toHaveProperty(key);
      else expect(s[key], `${key} (${c.why})`).toBe(want);
    }
  });
});

// Holds the converter to the intent of the two conditional branches rather than
// their letter: the schema requires the fields to be present, so a blank one
// validates while leaving a downstream consumer with nothing to act on.
describe('hdf-to-openvex conditional text is never blank', () => {
  it.each(TEXT_CASES.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    const s = await statementFor(c);
    if (s.status === 'affected') {
      expect(String(s.action_statement ?? '').trim()).not.toBe('');
    } else if (s.status === 'not_affected') {
      expect(
        String(s.justification ?? '').trim() + String(s.impact_statement ?? '').trim(),
      ).not.toBe('');
    }
  });
});

// Whole-output equality against the SAME goldens the Go TestCorpusGoldenParity
// freezes. The corpus exercises the sparse inputs (empty reason, no milestones,
// undescribed evidence) where the two implementations are most likely to drift,
// which the happy-path goldens never touched.
//
// Both sides convert the CANONICALIZED case input. The document @id is a digest
// of the input bytes, and the Go and TS corpora are byte-equal only after
// canonicalization (same document, different key order), so feeding the raw
// bytes would compare two digests of two spellings rather than two converters.
describe('hdf-to-openvex corpus golden parity (TS↔Go)', () => {
  it.each(
    amendmentsCorpus()
      .filter((c) => c.contract === 'MustConvert')
      .map((c) => [c.name, c] as const),
  )('%s matches the Go-frozen golden', async (name, c) => {
    const out = await convertHdfToOpenVex(canonicalJSON(c.input), '1.0.0');
    const golden = readFileSync(
      join(__dirname, '..', 'fixtures', 'expected', `corpus-${name}.openvex.json`),
      'utf-8',
    );
    expect(out).toBe(golden);
  });
});

// The adversarial corpus, adopted with no exemptions, mirroring the Go peer.
// This could not pass while the converter minted a synthetic product id: every
// MustConvert amendments case failed the OpenVEX schema on products[].@id,
// which types as an IRI. Exempting those cases was rejected — exempting every
// case the run has would make the adoption prove nothing.
describe('hdf-to-openvex against the adversarial corpus', () => {
  it('satisfies every contract for every case', async () => {
    await runSchemaCorpus(jsonDocumentValidator(validate), amendmentsCorpus(), (input) =>
      convertHdfToOpenVex(input),
    );
  });
});
