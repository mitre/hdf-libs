import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi, afterEach } from 'vitest';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import type { Cvss, CVSSSeverity } from '@mitre/hdf-schema';
import { amendments as sharedAmendments } from '@mitre/hdf-fixtures';
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
import { convertHdfToCsafVex, referenceSummary, reasonProse, csafSeverity } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_VERSION = '1.0.0';
const CVE = 'CVE-2021-44228';

// OASIS CSAF v2.0 (draft 2020-12). The schema $refs the FIRST.org CVSS schemas
// by URL; those are vendored alongside it and registered as companions so it
// compiles offline. See ../schemas/provenance.txt.
const csafSchemas = join(__dirname, '..', 'schemas');
const validate = loadSchemaValidatorWithResources(join(csafSchemas, 'csaf_json_schema.json'), {
  'https://www.first.org/cvss/cvss-v2.0.json': join(csafSchemas, 'cvss-v2.0.json'),
  'https://www.first.org/cvss/cvss-v3.0.json': join(csafSchemas, 'cvss-v3.0.json'),
  'https://www.first.org/cvss/cvss-v3.1.json': join(csafSchemas, 'cvss-v3.1.json'),
});

// The HDF schema the converter's inputs must themselves satisfy, so an input
// this suite calls legal HDF is asserted to be, not assumed.
const validateHdfAmendments = loadSchemaValidator(
  join(__dirname, '..', '..', '..', '..', 'hdf-validators', 'go', 'schemas', 'hdf-amendments.schema.json'),
);

const sparseOverride = () =>
  testhdf.override('waiver', CVE, { status: 'failed', reason: 'accepted' });

describe('hdf-to-csaf-vex output validates against the OASIS CSAF v2.0 schema', () => {
  // Exactly the golden parity inputs, so no frozen golden escapes the schema.
  it.each([
    ['sec-vex-amendments.json', () => readFileSync(join(__dirname, '..', 'fixtures', 'input', 'sec-vex-amendments.json'), 'utf-8')],
    ['uc-01-fixed-amendments.json', () => sharedAmendments.uc01Fixed.read()],
  ])('%s', (name, load) => {
    assertSchemaValid(validate, name, JSON.parse(convertHdfToCsafVex(load(), TEST_VERSION)));
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
    o.cvss = completeCvss31();
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

// The shared table the Go peer also reads, so the completeness rule and the
// severity mapping are asserted against ONE definition in both languages. See
// the table's $comment for data provenance.
interface CvssScoreCase {
  name: string;
  why: string;
  cve: string;
  product: string;
  cvss: Cvss;
  want: Record<string, unknown> | null;
  warning: string | null;
}
interface CvssScoreTable {
  severity: Record<string, string>;
  cases: CvssScoreCase[];
}

const cvssFixtures = join(__dirname, '..', 'fixtures');
const cvssTable = JSON.parse(readFileSync(join(cvssFixtures, 'cvss-score-cases.json'), 'utf-8')) as CvssScoreTable;
// The table's own $comment would otherwise read as a sixth band.
delete cvssTable.severity.$comment;

// The table's v31-complete block: the CVSS shape a test that only needs a score
// to be emitted can rely on.
function completeCvss31(): Cvss {
  const c = cvssTable.cases.find((x) => x.name === 'v31-complete');
  if (!c) throw new Error('shared table has no v31-complete case');
  return c.cvss;
}

// Legal HDF in, a CSAF-valid document out, exactly the table's score (or none,
// with the table's warning), and — through the goldens Go froze — the same bytes
// from both languages.
describe('hdf-to-csaf-vex CVSS scores match the shared table', () => {
  afterEach(() => vi.restoreAllMocks());

  it('reads a non-empty table', () => {
    expect(cvssTable.cases.length).toBeGreaterThan(0);
    expect(Object.keys(cvssTable.severity).length).toBeGreaterThan(0);
  });

  it.each(cvssTable.cases.map((c) => [c.name, c] as const))('%s', (name, c) => {
    const o = testhdf.override('waiver', c.cve, { status: 'failed', reason: 'accepted' });
    // The structured product identity the exporter reads, in the slot its prefix names.
    o.affectedPackages = [c.product.startsWith('cpe:') ? { cpe: c.product } : { purl: c.product }];
    o.cvss = c.cvss;
    const input = JSON.stringify(testhdf.amendments('a', o));
    assertSchemaValid(validateHdfAmendments, `${name} (input)`, JSON.parse(input));

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const out = convertHdfToCsafVex(input, TEST_VERSION);
    const doc = JSON.parse(out) as { vulnerabilities: { scores?: unknown[] }[] };
    assertSchemaValid(validate, name, doc);

    expect(doc.vulnerabilities).toHaveLength(1);
    if (c.want === null) {
      expect(doc.vulnerabilities[0].scores, c.why).toBeUndefined();
    } else {
      expect(doc.vulnerabilities[0].scores, c.why).toEqual([c.want]);
    }

    const warnings = warn.mock.calls.map((args) => String(args[0]));
    if (c.warning === null) {
      expect(warnings, c.why).toEqual([]);
    } else {
      expect(warnings, c.why).toEqual([`WARNING: ${c.warning}`]);
    }

    const golden = readFileSync(join(cvssFixtures, 'expected', `cvss-${name}.csaf-vex.json`), 'utf-8');
    expect(out).toBe(golden);
  });
});

// The band mapping is pinned to the shared table and the table to the enum in
// the vendored FIRST.org schema, so neither language's mapping can drift from
// what CSAF actually accepts.
describe('hdf-to-csaf-vex CSAF severity matches the shared table', () => {
  it.each(Object.entries(cvssTable.severity))('%s', (band, want) => {
    expect(csafSeverity(band as CVSSSeverity)).toBe(want);
  });

  it('uses exactly the FIRST.org severityType enum', () => {
    const first = JSON.parse(readFileSync(join(csafSchemas, 'cvss-v3.1.json'), 'utf-8')) as {
      definitions: { severityType: { enum: string[] } };
    };
    const enumValues = [...first.definitions.severityType.enum].sort();
    expect([...Object.values(cvssTable.severity)].sort()).toEqual(enumValues);
    expect(enumValues.join(',')).toBe(enumValues.join(',').toUpperCase());
  });
});
