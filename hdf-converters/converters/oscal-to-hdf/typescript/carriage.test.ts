import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import { convertOscalSarToHdf } from './converter-sar.js';
import { readCarriedProps, carryForeignProps, OSCAL_PROPS_TAG, type CarriedProp } from './carriage.js';
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
  return readCarriedProps(hdf.baselines[0].requirements[0].tags);
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
        const entries = readCarriedProps(req.tags);
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
