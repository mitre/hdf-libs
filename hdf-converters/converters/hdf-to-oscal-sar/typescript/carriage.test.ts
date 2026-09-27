import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { convertHdfToOscalSar } from './converter.js';
import { convertOscalSarToHdf } from '../../oscal-to-hdf/typescript/converter-sar.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';
import { vocabularyDefaultNamespace } from '../../oscal-to-hdf/typescript/vocabulary.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONVERTERS = join(__dirname, '..', '..', '..', 'converters');

interface CarriageEntry {
  on: string;
  name: string;
  value: string;
  ns?: string;
}

function hdfWithOscalProps(impact: number, withResults: boolean, entries: CarriageEntry[]): string {
  const req: Record<string, unknown> = {
    id: 'AC-1',
    impact,
    title: 'req',
    tags: { nist: ['AC-1'], 'oscal-props': entries },
    descriptions: [{ label: 'default', data: 'd' }],
  };
  if (withResults) {
    req.results = [{ status: 'failed', codeDesc: 'c', startTime: '2026-01-01T00:00:00Z' }];
  }
  return JSON.stringify({ baselines: [{ name: 'b', requirements: [req] }] });
}

async function exportResult(input: string): Promise<Record<string, unknown>> {
  const doc = JSON.parse(await convertHdfToOscalSar(input));
  return doc['assessment-results'].results[0];
}

const arSchemaFiles = ['oscal_assessment-results_schema-v1.1.2.json', 'oscal_assessment-results_schema-v1.2.3.json'];
const arValidators = arSchemaFiles.map((file) => {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return { file, validate: ajv.compile(JSON.parse(readFileSync(join(CONVERTERS, 'hdf-to-oscal-sar', 'schemas', file), 'utf-8'))) };
});

describe('hdf-to-oscal-sar foreign-prop re-emission', () => {
  it('re-emitted carriage validates against both vendored OSCAL AR schemas', async () => {
    const input = hdfWithOscalProps(0.5, true, [
      { on: 'finding', name: 'marking', value: 'CUI', ns: 'https://fedramp.gov/ns/oscal' },
      { on: 'observation', name: 'scan-percentage', value: '100', ns: 'https://fedramp.gov/ns/oscal' },
      { on: 'risk', name: 'priority', value: 'high', ns: 'https://fedramp.gov/ns/oscal' },
    ]);
    const out = JSON.parse(await convertHdfToOscalSar(input));
    for (const { file, validate } of arValidators) {
      expect(validate(out), `${file}: ${JSON.stringify(validate.errors)}`).toBe(true);
    }
  });

  it('re-emits on:finding entries after the finding\'s own props', async () => {
    const result = await exportResult(hdfWithOscalProps(0.5, true, [{ on: 'finding', name: 'marking', value: 'CUI', ns: 'https://fedramp.gov/ns/oscal' }]));
    const props = result.findings[0].props as Array<{ name: string; value: string; ns?: string }>;
    expect(props[0].name).toBe('hdf-requirement-id');
    const last = props[props.length - 1];
    expect(last).toMatchObject({ name: 'marking', value: 'CUI', ns: 'https://fedramp.gov/ns/oscal' });
  });

  it('re-emits on:observation entries on the observation', async () => {
    const result = await exportResult(hdfWithOscalProps(0.5, true, [{ on: 'observation', name: 'scan-percentage', value: '100', ns: 'https://fedramp.gov/ns/oscal' }]));
    const props = result.observations[0].props as Array<{ name: string; ns?: string }>;
    expect(props).toHaveLength(1);
    expect(props[0]).toMatchObject({ name: 'scan-percentage', ns: 'https://fedramp.gov/ns/oscal' });
  });

  it('re-emits on:risk entries on the one emitted risk', async () => {
    const result = await exportResult(hdfWithOscalProps(0.5, true, [{ on: 'risk', name: 'priority', value: 'high', ns: 'https://fedramp.gov/ns/oscal' }]));
    const props = result.risks[0].props as Array<{ name: string }>;
    expect(props).toHaveLength(1);
    expect(props[0].name).toBe('priority');
  });

  it('does not re-emit observation entries when no observation is emitted', async () => {
    const input = hdfWithOscalProps(0.5, false, [{ on: 'observation', name: 'scan-percentage', value: '100', ns: 'https://fedramp.gov/ns/oscal' }]);
    const out = await convertHdfToOscalSar(input);
    const result = await exportResult(input);
    expect(result.observations).toBeUndefined();
    expect(out).not.toContain('scan-percentage');
  });

  it('does not re-emit risk entries when impact is 0 and no risk is emitted', async () => {
    const input = hdfWithOscalProps(0, true, [{ on: 'risk', name: 'priority', value: 'high', ns: 'https://fedramp.gov/ns/oscal' }]);
    const out = await convertHdfToOscalSar(input);
    const result = await exportResult(input);
    expect(result.risks).toBeUndefined();
    expect(out).not.toContain('"priority"');
  });

  it('dedupes identical carried entries', async () => {
    const dup = { on: 'risk', name: 'priority', value: 'high', ns: 'https://fedramp.gov/ns/oscal' };
    const result = await exportResult(hdfWithOscalProps(0.5, true, [dup, { ...dup }]));
    expect(result.risks[0].props).toHaveLength(1);
  });

  it('treats an absent ns as NIST default when deduping', async () => {
    const nist = vocabularyDefaultNamespace();
    const result = await exportResult(hdfWithOscalProps(0.5, true, [
      { on: 'risk', name: 'foo', value: 'bar', ns: nist },
      { on: 'risk', name: 'foo', value: 'bar' },
    ]));
    expect(result.risks[0].props).toHaveLength(1);
  });

  // ADR-0014 §3.5 convergence. See the Go peer for why the pipeline input is the
  // first HDF-produced export of the real FedRAMP SAR.
  it('converges OSCAL→HDF→OSCAL→HDF→OSCAL, carrying foreign FedRAMP props', async () => {
    const raw = readFileSync(join(CONVERTERS, 'oscal-to-hdf', 'fixtures', 'input', 'sar-fedramp.json'), 'utf-8');
    const roundTrip = async (oscalDoc: string): Promise<string> => {
      const hdf = await convertOscalSarToHdf(oscalDoc);
      return convertHdfToOscalSar(hdf);
    };
    const input = await roundTrip(raw);
    const export1 = await roundTrip(input);
    const export2 = await roundTrip(export1);

    expect(export1).toContain('https://fedramp.gov/ns/oscal');
    expect(export1).toContain('"priority"');

    const vk = ['last-modified'];
    const m1 = maskVolatileJson(JSON.parse(export1), vk);
    const m2 = maskVolatileJson(JSON.parse(export2), vk);
    expect(m2).toEqual(m1);
  });
});
