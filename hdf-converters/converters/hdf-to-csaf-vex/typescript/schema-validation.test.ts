import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import {
  loadSchemaValidator,
  loadSchemaValidatorWithResources,
  assertSchemaValid,
} from '../../../shared/typescript/schema-validation.js';
import {
  amendmentsCorpus,
  runSchemaCorpus,
  jsonDocumentValidator,
} from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToCsafVex, referenceSummary, reasonProse } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_VERSION = '1.0.0';
const CVE = 'CVE-2021-44228';

// OASIS CSAF v2.0 (draft 2020-12). The schema $refs the FIRST.org CVSS schemas
// by URL; those are vendored alongside it and registered as companions so it
// compiles offline. Shared with the reverse importer rather than re-vendored.
const csafFixtures = join(__dirname, '..', '..', 'csaf-vex-to-hdf', 'fixtures');
const validate = loadSchemaValidatorWithResources(join(csafFixtures, 'csaf_json_schema.json'), {
  'https://www.first.org/cvss/cvss-v2.0.json': join(csafFixtures, 'cvss-v2.0.json'),
  'https://www.first.org/cvss/cvss-v3.0.json': join(csafFixtures, 'cvss-v3.0.json'),
  'https://www.first.org/cvss/cvss-v3.1.json': join(csafFixtures, 'cvss-v3.1.json'),
});

// The HDF schema the converter's inputs must themselves satisfy, so an input
// this suite calls legal HDF is asserted to be, not assumed.
const validateHdfAmendments = loadSchemaValidator(
  join(__dirname, '..', '..', '..', '..', 'hdf-validators', 'go', 'schemas', 'hdf-amendments.schema.json'),
);

const sparseOverride = () =>
  testhdf.override('waiver', CVE, { status: 'failed', reason: 'accepted' });

describe('hdf-to-csaf-vex output validates against the OASIS CSAF v2.0 schema', () => {
  it('sec-vex-amendments.json', () => {
    const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'sec-vex-amendments.json'), 'utf-8');
    assertSchemaValid(validate, 'sec-vex-amendments.json', JSON.parse(convertHdfToCsafVex(input, TEST_VERSION)));
  });

  const sparse: Array<[string, () => unknown]> = [
    // evidence.description is optional in HDF; CSAF requires
    // references[].summary with minLength 1.
    [
      'evidence without description',
      () => {
        const o = sparseOverride();
        o.evidence = [{ type: 'url', data: 'https://example.com/advisory' }] as never;
        return testhdf.amendments('a', o);
      },
    ],
    // externalReferences.description is optional for the same sink.
    [
      'external reference without description',
      () => {
        const o = sparseOverride();
        o.externalReferences = [
          { sourceName: 'vendor', href: 'https://example.com/vendor-advisory' },
        ] as never;
        return testhdf.amendments('a', o);
      },
    ],
    // A reason written by the reverse importer can be nothing but the
    // machine-generated 'Products:' line, which strips to no prose at all;
    // CSAF requires threats[].details with minLength 1.
    [
      'reason is only a products line',
      () => testhdf.amendments('a', testhdf.override('waiver', CVE, {
        status: 'failed',
        reason: 'Products: CSAFPID-0001',
      })),
    ],
    [
      'reason is whitespace only',
      () => testhdf.amendments('a', testhdf.override('waiver', CVE, { status: 'failed', reason: '   ' })),
    ],
  ];

  it.each(sparse)('%s', (name, build) => {
    const input = JSON.stringify(build());
    assertSchemaValid(validateHdfAmendments, `${name} (input)`, JSON.parse(input));
    assertSchemaValid(validate, name, JSON.parse(convertHdfToCsafVex(input, TEST_VERSION)));
  });
});

// The shared corpus holds this converter to both contracts an exporter owes,
// rather than only to fully-populated fixtures — the gap that let its
// empty-summary defect ship on the TypeScript side with no schema test at all.
describe('hdf-to-csaf-vex against the adversarial corpus', () => {
  it('satisfies both corpus contracts', async () => {
    await runSchemaCorpus(jsonDocumentValidator(validate), amendmentsCorpus(), (input) =>
      convertHdfToCsafVex(input, TEST_VERSION),
    );
  });
});

// The one path that emits a vulnerability without filling any product bucket: an
// override type the HDF enum forbids but a typed decode accepts, carrying
// enrichment that still produces output. CSAF constrains product_status with
// minProperties 1.
describe('hdf-to-csaf-vex product_status', () => {
  it('is omitted rather than emitted empty for an unknown override type', () => {
    const o = testhdf.override('not-a-real-override-type', CVE, { status: 'failed', reason: 'accepted' });
    o.cvss = { version: '3.1', baseScore: 9.8 } as never;
    const input = JSON.stringify(testhdf.amendments('a', o));

    const doc = JSON.parse(convertHdfToCsafVex(input, TEST_VERSION)) as {
      vulnerabilities: Record<string, unknown>[];
    };
    expect(doc.vulnerabilities).toHaveLength(1);
    expect(doc.vulnerabilities[0]).not.toHaveProperty('product_status');
  });
});

// Byte-for-byte equality with the SAME corpus goldens the Go TestCorpusGoldenParity
// freezes. The corpus exercises the sparse inputs (empty reason, no milestones,
// undescribed evidence) where the two implementations are most likely to drift,
// which the happy-path goldens never touched. Every value is deterministic, so
// nothing is masked.
describe('hdf-to-csaf-vex corpus golden parity (TS↔Go)', () => {
  it.each(
    amendmentsCorpus()
      .filter((c) => c.contract === 'MustConvert')
      .map((c) => [c.name, c] as const),
  )('%s matches the Go-frozen golden', (name, c) => {
    const golden = readFileSync(
      join(__dirname, '..', 'fixtures', 'expected', `corpus-${name}.csaf-vex.json`),
      'utf-8',
    );
    expect(convertHdfToCsafVex(c.input, TEST_VERSION)).toBe(golden);
  });
});

// The shared table the Go peer also reads, so the two implementations of these
// two CSAF text rules are asserted against ONE definition rather than two
// literals that can drift apart.
interface TextSinkTable {
  referenceSummary: { cases: Array<{ name: string; description: string; url: string; want: string }> };
  reasonProse: { cases: Array<{ name: string; reason: string; want: string }> };
}

const textSinks = JSON.parse(
  readFileSync(join(__dirname, '..', '..', '..', 'shared', 'csaf-vex-text-cases.json'), 'utf-8'),
) as TextSinkTable;

describe('hdf-to-csaf-vex CSAF text sinks match the shared table', () => {
  it.each(textSinks.referenceSummary.cases.map((c) => [c.name, c] as const))(
    'referenceSummary: %s',
    (_name, c) => {
      expect(referenceSummary(c.description, c.url)).toBe(c.want);
    },
  );

  it.each(textSinks.reasonProse.cases.map((c) => [c.name, c] as const))(
    'reasonProse: %s',
    (_name, c) => {
      expect(reasonProse(c.reason)).toBe(c.want);
    },
  );
});
