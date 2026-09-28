import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { convertHdfToOscalSar } from './converter.js';
import { convertOscalSarToHdf } from '../../oscal-to-hdf/typescript/converter-sar.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const HDF_NS = 'https://mitre.github.io/hdf-libs/ns/oscal';

// The vendored NIST OSCAL AR schemas the output must satisfy: 1.1.2 (the
// converter's self-declared oscal-version) and 1.2.3 (the current release, which
// types the single-line title sinks as MarkupLine, ^[^\n]+$). See
// ../schemas/provenance.txt.
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateAR112 = ajv.compile(
  JSON.parse(readFileSync(join(__dirname, '..', 'schemas', 'oscal_assessment-results_schema-v1.1.2.json'), 'utf-8')) as object,
);
const validateAR123 = ajv.compile(
  JSON.parse(readFileSync(join(__dirname, '..', 'schemas', 'oscal_assessment-results_schema-v1.2.3.json'), 'utf-8')) as object,
);
const AR_VALIDATORS = [
  ['v1.1.2', validateAR112],
  ['v1.2.3', validateAR123],
] as const;

// A one-baseline, one-requirement, one-component HDF Results document whose
// component name, baseline title and requirement title carry the given values —
// each an identity/prose value the importer reads back from the OSCAL single-line
// title sink it lands in.
const identityTitlesInput = (compName: string, baselineTitle: string, reqTitle: string): string =>
  JSON.stringify({
    baselines: [{
      name: 'b',
      title: baselineTitle,
      requirements: [{
        id: 'AC-1', impact: 0.5, title: reqTitle, tags: { nist: ['AC-1'] },
        descriptions: [{ label: 'default', data: 'd' }],
        results: [{ status: 'passed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }],
      }],
    }],
    components: [{ type: 'host', name: compName, componentId: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d' }],
  });

interface BackHDF {
  baselines: Array<{ title?: string; requirements: Array<{ title?: string }> }>;
  components?: Array<{ name: string }>;
}

const roundTrip = async (input: string): Promise<{ compName: string; baselineTitle: string; reqTitle: string }> => {
  const sar = await convertHdfToOscalSar(input);
  const back = JSON.parse(await convertOscalSarToHdf(sar)) as BackHDF;
  expect(back.components, 'the component must reconstitute').toHaveLength(1);
  expect(back.baselines).toHaveLength(1);
  expect(back.baselines[0]!.requirements).toHaveLength(1);
  return {
    compName: back.components![0]!.name,
    baselineTitle: back.baselines[0]!.title ?? '',
    reqTitle: back.baselines[0]!.requirements[0]!.title ?? '',
  };
};

const validate = (out: unknown): void => {
  for (const [version, validator] of AR_VALIDATORS) {
    expect(validator(out), `${version}: ${JSON.stringify(validator.errors)}`).toBe(true);
  }
};

describe('hdf-to-oscal-sar SAR identity/prose title homes (ADR-0014 §1.7, §4.3)', () => {
  // The card's first-failing case: a component name, a baseline title and a
  // requirement title that each carry a line terminator must convert to a SAR
  // valid on 1.1.2 AND 1.2.3, and HDF -> SAR -> HDF must return each byte-exact.
  it('round-trips newline-bearing values byte-exact and validates on both schemas', async () => {
    const compName = 'web\n01';
    const baselineTitle = 'RHEL 9 STIG\nHost A';
    const reqTitle = 'Session lock\nmust be enabled';
    const input = identityTitlesInput(compName, baselineTitle, reqTitle);

    validate(JSON.parse(await convertHdfToOscalSar(input)));

    const got = await roundTrip(input);
    expect(got.compName, 'component name byte-exact').toBe(compName);
    expect(got.baselineTitle, 'baseline title byte-exact').toBe(baselineTitle);
    expect(got.reqTitle, 'requirement title byte-exact').toBe(reqTitle);
  });

  it.each([
    ['carriage return', 'a\rb'],
    ['CRLF', 'a\r\nb'],
    ['line separator U+2028', 'a b'],
    ['paragraph separator U+2029', 'a b'],
    ['leading and trailing whitespace', '  padded  '],
    ['interior run of terminators', 'a\n\n\nb'],
    ['already valid unchanged', 'Access Control 2'],
  ])('round-trips a %s in all three sinks and validates on both schemas', async (_label, value) => {
    const input = identityTitlesInput(value, value, value);
    validate(JSON.parse(await convertHdfToOscalSar(input)));
    const got = await roundTrip(input);
    expect(got.compName, 'component name').toBe(value);
    expect(got.baselineTitle, 'baseline title').toBe(value);
    expect(got.reqTitle, 'requirement title').toBe(value);
  });

  interface SarOut {
    'assessment-results': {
      results: Array<{
        title: string;
        props?: Array<{ name: string; value: string; remarks?: string; ns?: string }>;
        findings: Array<{ title: string; props?: Array<{ name: string; value: string; remarks?: string; ns?: string }> }>;
        observations: Array<{ subjects?: Array<{ title: string; props?: Array<{ name: string; value: string; remarks?: string; ns?: string }> }> }>;
      }>;
    };
  }

  it('normalizes the display title sinks and keeps the exact value in the prop remarks', async () => {
    const compName = 'web\n01';
    const baselineTitle = 'RHEL 9 STIG\nHost A';
    const reqTitle = 'Session lock\nmust be enabled';
    const out = JSON.parse(await convertHdfToOscalSar(identityTitlesInput(compName, baselineTitle, reqTitle))) as SarOut;
    const result = out['assessment-results'].results[0]!;

    expect(result.title, 'result title is normalized display text').toBe('RHEL 9 STIG Host A');
    const baselineTitleProp = (result.props ?? []).find((p) => p.name === 'baseline-title')!;
    expect(baselineTitleProp).toBeDefined();
    expect(baselineTitleProp.value).toBe('RHEL 9 STIG Host A');
    expect(baselineTitleProp.remarks).toBe(baselineTitle);
    expect(baselineTitleProp.ns).toBe(HDF_NS);

    const finding = result.findings[0]!;
    expect(finding.title, 'finding title is normalized display text').toBe('Session lock must be enabled');
    const reqTitleProp = (finding.props ?? []).find((p) => p.name === 'requirement-title')!;
    expect(reqTitleProp.remarks).toBe(reqTitle);
    expect(reqTitleProp.ns).toBe(HDF_NS);

    const subject = result.observations[0]!.subjects![0]!;
    expect(subject.title, 'subject title is normalized display text').toBe('web 01');
    const compNameProp = (subject.props ?? []).find((p) => p.name === 'component-name')!;
    expect(compNameProp.remarks).toBe(compName);
    expect(compNameProp.ns).toBe(HDF_NS);
  });

  it('emits no remarks for already-valid single-line values', async () => {
    const out = JSON.parse(await convertHdfToOscalSar(identityTitlesInput('web01', 'RHEL 9 STIG', 'Session lock'))) as SarOut;
    const result = out['assessment-results'].results[0]!;

    const bt = (result.props ?? []).find((p) => p.name === 'baseline-title')!;
    expect(bt.value).toBe('RHEL 9 STIG');
    expect(bt.remarks).toBeUndefined();

    const rt = (result.findings[0]!.props ?? []).find((p) => p.name === 'requirement-title')!;
    expect(rt.value).toBe('Session lock');
    expect(rt.remarks).toBeUndefined();

    const cn = (result.observations[0]!.subjects![0]!.props ?? []).find((p) => p.name === 'component-name')!;
    expect(cn.value).toBe('web01');
    expect(cn.remarks).toBeUndefined();
  });

  // No regression for foreign SARs: a document with no HDF-namespaced identity
  // prop still imports the component name from the subject title, the baseline
  // title from the result title, and the requirement title from the finding title.
  it('falls back to the titles for a foreign SAR', async () => {
    const foreign = JSON.stringify({
      'assessment-results': {
        uuid: '11111111-1111-4111-8111-111111111111',
        metadata: { title: 't', 'last-modified': '2026-01-01T00:00:00Z', version: '1', 'oscal-version': '1.1.2' },
        'import-ap': { href: '#' },
        results: [{
          uuid: '22222222-2222-4222-8222-222222222222',
          title: 'Foreign Baseline',
          description: 'd',
          start: '2026-01-01T00:00:00Z',
          'reviewed-controls': { 'control-selections': [{ 'include-all': {} }] },
          findings: [{
            uuid: '33333333-3333-4333-8333-333333333333',
            title: 'Foreign Requirement',
            description: 'd',
            target: { type: 'objective-id', 'target-id': 'ac-1', status: { state: 'satisfied' } },
            'related-observations': [{ 'observation-uuid': '44444444-4444-4444-8444-444444444444' }],
          }],
          observations: [{
            uuid: '44444444-4444-4444-8444-444444444444',
            description: 'd',
            methods: ['TEST'],
            collected: '2026-01-01T00:00:00Z',
            subjects: [{ 'subject-uuid': '55555555-5555-4555-8555-555555555555', type: 'host', title: 'web01' }],
          }],
        }],
      },
    });

    const back = JSON.parse(await convertOscalSarToHdf(foreign)) as BackHDF;
    expect(back.components).toHaveLength(1);
    expect(back.components![0]!.name, 'foreign component name from subject title').toBe('web01');
    expect(back.baselines[0]!.title, 'foreign baseline title from result title').toBe('Foreign Baseline');
    expect(back.baselines[0]!.requirements[0]!.title, 'foreign requirement title from finding title').toBe('Foreign Requirement');
  });
});
