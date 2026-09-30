import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi } from 'vitest';
import Ajv from 'ajv';
import { convertOscalSarToHdf } from './converter-sar.js';
import { readCarriedProps, carryForeignProps, carriedFor, appendCarriedProps, validCarriedProp, OSCAL_PROPS_TAG, type CarriedProp } from './carriage.js';
import { vocabularyNamespace, consumedVocabularyProp } from './vocabulary.js';
import { type Property } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONVERTERS = join(__dirname, '..', '..', '..', 'converters');

const oscalPropsSchema = JSON.parse(readFileSync(join(CONVERTERS, '..', 'shared', 'oscal-props.schema.json'), 'utf-8'));
const ajv = new Ajv({ allErrors: true, strict: false });
const validateOscalProps = ajv.compile(oscalPropsSchema);

// A minimal, schema-shaped assessment-results document whose props exercise
// carriage: a foreign-namespace prop, an HDF-namespaced prop the importer
// consumes, and a bare foreign prop with no ns. Mirrors the Go sarWithProps.
const sarWithProps = JSON.stringify({
  'assessment-results': {
    uuid: '11111111-1111-1111-1111-111111111111',
    metadata: { title: 't', 'last-modified': '2023-05-10T00:00:00Z', version: '1', 'oscal-version': '1.1.2' },
    'import-ap': { href: '#' },
    results: [
      {
        uuid: '22222222-2222-2222-2222-222222222222',
        title: 'r',
        description: 'd',
        start: '2023-05-10T00:00:00Z',
        'reviewed-controls': { 'control-selections': [{ 'include-all': {} }] },
        findings: [
          {
            uuid: '33333333-3333-3333-3333-333333333333',
            title: 'f',
            description: 'fd',
            target: { type: 'objective-id', 'target-id': 'ac-1_obj', status: { state: 'not-satisfied' } },
            props: [
              { name: 'marking', value: 'CUI', ns: 'https://fedramp.gov/ns/oscal' },
              { name: 'hdf-requirement-id', value: 'V-1234', ns: 'https://mitre.github.io/hdf-libs/ns/oscal' },
              { name: 'bare', value: 'b1' },
            ],
            'related-observations': [{ 'observation-uuid': '44444444-4444-4444-4444-444444444444' }],
            'related-risks': [{ 'risk-uuid': '55555555-5555-5555-5555-555555555555' }],
          },
        ],
        observations: [
          {
            uuid: '44444444-4444-4444-4444-444444444444',
            description: 'od',
            methods: ['EXAMINE'],
            collected: '2023-05-10T00:00:00Z',
            props: [
              { name: 'obs-marking', value: 'internal', ns: 'https://fedramp.gov/ns/oscal', class: 'c1', group: 'g1', uuid: '66666666-6666-6666-6666-666666666666', remarks: 'rk' },
            ],
          },
        ],
        risks: [
          {
            uuid: '55555555-5555-5555-5555-555555555555',
            title: 'rt',
            description: 'rd',
            statement: 'rs',
            status: 'open',
            props: [{ name: 'priority', value: 'high', ns: 'https://example.org/ns/oscal' }],
          },
        ],
      },
    ],
  },
});

async function importCarriage(): Promise<CarriedProp[]> {
  const hdf = JSON.parse(await convertOscalSarToHdf(sarWithProps));
  expect(hdf.baselines).toHaveLength(1);
  expect(hdf.baselines[0].requirements).toHaveLength(1);
  return readCarriedProps(hdf.baselines[0].requirements[0].tags, hdf.baselines[0].requirements[0].id);
}

describe('oscal-to-hdf SAR foreign-prop carriage', () => {
  it('carries the foreign and bare finding props but not the HDF prop', async () => {
    const entries = await importCarriage();
    const finding = entries.filter((e) => e.on === 'finding');
    expect(finding).toEqual([
      { on: 'finding', name: 'marking', value: 'CUI', ns: 'https://fedramp.gov/ns/oscal' },
      { on: 'finding', name: 'bare', value: 'b1' },
    ]);
    expect(entries.some((e) => e.name === 'hdf-requirement-id')).toBe(false);
  });

  it('carries observation and risk props with every optional member intact', async () => {
    const entries = await importCarriage();
    const obs = entries.find((e) => e.on === 'observation');
    const risk = entries.find((e) => e.on === 'risk');
    expect(obs).toEqual({
      on: 'observation', name: 'obs-marking', value: 'internal',
      ns: 'https://fedramp.gov/ns/oscal', class: 'c1', group: 'g1',
      uuid: '66666666-6666-6666-6666-666666666666', remarks: 'rk',
    });
    expect(risk).toEqual({ on: 'risk', name: 'priority', value: 'high', ns: 'https://example.org/ns/oscal' });
  });

  it('preserves source order: finding, finding, observation, risk', async () => {
    const entries = await importCarriage();
    expect(entries.map((e) => e.on)).toEqual(['finding', 'finding', 'observation', 'risk']);
  });

  it('produces an oscal-props tag that validates against the shared JSON Schema', async () => {
    const hdf = JSON.parse(await convertOscalSarToHdf(sarWithProps));
    const tag = hdf.baselines[0].requirements[0].tags[OSCAL_PROPS_TAG];
    expect(validateOscalProps(tag)).toBe(true);
  });

  it('carries the real FedRAMP SAR fixture props, all schema-valid and non-HDF', async () => {
    const raw = readFileSync(join(CONVERTERS, 'oscal-to-hdf', 'fixtures', 'input', 'sar-fedramp.json'), 'utf-8');
    const hdf = JSON.parse(await convertOscalSarToHdf(raw));
    let total = 0;
    for (const b of hdf.baselines) {
      for (const req of b.requirements) {
        const entries = readCarriedProps(req.tags, req.id);
        total += entries.length;
        for (const e of entries) {
          expect(e.on).toBeTruthy();
          expect(e.ns).not.toBe(vocabularyNamespace());
        }
        const tag = req.tags?.[OSCAL_PROPS_TAG];
        if (tag) expect(validateOscalProps(tag)).toBe(true);
      }
    }
    expect(total).toBeGreaterThan(0);
  });

  // AC (ADR-0014 §3.1): a recognised third-party vocabulary row carried under its
  // owner's namespace is carried (consumed AND carried); the same name with no
  // namespace is a legacy match — consumed, never carried. impacted-control-id is
  // a legacy FedRAMP row, so it exercises both.
  it('carries a recognised third-party prop but not its legacy no-namespace form', () => {
    const fedrampNs = 'https://fedramp.gov/ns/oscal';
    const thirdParty: Property = { name: 'impacted-control-id', value: 'ac-2', ns: fedrampNs };
    const legacy: Property = { name: 'impacted-control-id', value: 'ac-2' };

    expect(consumedVocabularyProp(thirdParty)).toBe(false);
    expect(consumedVocabularyProp(legacy)).toBe(true);

    const entries: CarriedProp[] = [];
    carryForeignProps(entries, 'risk', [thirdParty, legacy]);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({ on: 'risk', name: 'impacted-control-id', value: 'ac-2', ns: fedrampNs });
  });
});

interface CarriageCase {
  label: string;
  entry: unknown;
  valid: boolean;
  why: string;
}

const CARRIAGE_CASES = (
  JSON.parse(readFileSync(join(CONVERTERS, '..', 'shared', 'oscal-carriage-cases.json'), 'utf-8')) as { cases: CarriageCase[] }
).cases;

/** Reads the tag and returns the entries with everything the converter warned. */
function readWithWarnings(tags: Record<string, unknown>, requirementId: string): { entries: CarriedProp[]; warnings: string[] } {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  const entries = readCarriedProps(tags, requirementId);
  const warnings = warn.mock.calls.map((c) => String(c[0]));
  warn.mockRestore();
  return { entries, warnings };
}

describe('oscal-props carriage read-back tolerance', () => {
  // AC (ADR-0014 §3.3): carriage is per-entry tolerant — one malformed entry must
  // not erase the rest of the requirement's carried props, and the drop is
  // reported once for the requirement rather than silently.
  it('keeps the valid entries when a sibling is malformed, warning once', () => {
    const { entries, warnings } = readWithWarnings(
      {
        'oscal-props': [
          { on: 'finding', name: 'a', value: '1' },
          { on: 'finding', name: 'b', value: '2', ns: 42 },
        ],
      },
      'V-1234',
    );
    expect(entries).toEqual([{ on: 'finding', name: 'a', value: '1' }]);
    expect(warnings).toEqual(['WARNING: Dropping 1 malformed oscal-props entry on requirement "V-1234"']);
  });

  it('warns once with the dropped count when several entries are malformed', () => {
    const { entries, warnings } = readWithWarnings(
      {
        'oscal-props': [
          { on: 'task', name: 'a', value: '1' },
          { on: 'finding', name: 'b', value: '2', remarks: true },
          { on: 'risk', name: 'ok', value: '3' },
        ],
      },
      'AC-1',
    );
    expect(entries).toEqual([{ on: 'risk', name: 'ok', value: '3' }]);
    expect(warnings).toEqual(['WARNING: Dropping 2 malformed oscal-props entries on requirement "AC-1"']);
  });

  it('is silent for a well-formed tag', () => {
    const { entries, warnings } = readWithWarnings({ 'oscal-props': [{ on: 'finding', name: 'a', value: '1' }] }, 'AC-1');
    expect(entries).toHaveLength(1);
    expect(warnings).toEqual([]);
  });

  it('is silent when the tag is absent', () => {
    const { entries, warnings } = readWithWarnings({ nist: ['AC-1'] }, 'AC-1');
    expect(entries).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it.each([
    ['object', { on: 'finding' }],
    ['string', 'finding'],
    ['null', null],
  ])('carries nothing and says so when the tag is a %s', (_label, tag) => {
    const { entries, warnings } = readWithWarnings({ 'oscal-props': tag }, 'AC-1');
    expect(entries).toEqual([]);
    expect(warnings).toEqual(['WARNING: Dropping the oscal-props tag on requirement "AC-1": it is not an array']);
  });

  // AC: the predicate that decides whether an entry is carried agrees with
  // shared/oscal-props.schema.json for every case in the shared table, so the two
  // languages' read paths cannot drift from the shape the schema pins.
  it.each(CARRIAGE_CASES.map((c) => [c.label, c] as const))('agrees with the oscal-props schema: %s', (_label, c) => {
    expect(CARRIAGE_CASES.length).toBeGreaterThan(0);
    expect(validateOscalProps([c.entry]), c.why).toBe(c.valid);
    expect(validCarriedProp(c.entry), c.why).toBe(c.valid);
  });

  it('keeps exactly the shared table’s valid entries', () => {
    const want = CARRIAGE_CASES.filter((c) => c.valid).length;
    const { entries, warnings } = readWithWarnings({ 'oscal-props': CARRIAGE_CASES.map((c) => c.entry) }, 'AC-1');
    expect(entries).toHaveLength(want);
    expect(warnings).toEqual([
      `WARNING: Dropping ${CARRIAGE_CASES.length - want} malformed oscal-props entries on requirement "AC-1"`,
    ]);
  });
});

describe('carriage: empty optionals', () => {
  it('treats an empty optional as absent when carrying and when re-emitting, as Go does', () => {
    const entries: CarriedProp[] = [];
    carryForeignProps(entries, 'finding', [{ name: 'a', value: '1', ns: '', remarks: '' }]);
    expect(entries).toStrictEqual([{ on: 'finding', name: 'a', value: '1' }]);

    const read = readCarriedProps({ [OSCAL_PROPS_TAG]: [{ on: 'finding', name: 'a', value: '1', ns: '', remarks: '' }] }, 'V-1');
    expect(read).toHaveLength(1);
    expect(appendCarriedProps([], carriedFor(read, 'finding'))).toStrictEqual([{ name: 'a', value: '1' }]);
  });
});
