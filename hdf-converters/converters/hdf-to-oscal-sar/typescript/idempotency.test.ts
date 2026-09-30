import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { convertHdfToOscalSar } from './converter.js';
import { convertOscalSarToHdf } from '../../oscal-to-hdf/typescript/converter-sar.js';
import { maskVolatileJson } from '../../../shared/typescript/golden-mask.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONVERTERS = join(__dirname, '..', '..', '..', 'converters');

const roundTrip = async (oscalDoc: string): Promise<string> => {
  const hdf = await convertOscalSarToHdf(oscalDoc);
  return convertHdfToOscalSar(hdf);
};

function observationDescriptions(sar: string): string[] {
  const doc = JSON.parse(sar);
  const out: string[] = [];
  for (const r of doc['assessment-results'].results ?? []) {
    for (const o of r.observations ?? []) {
      out.push(o.description);
    }
  }
  return out;
}

// AC (ADR-0014 §3.5): the SAR round trip is idempotent on observation.description
// from the RAW third-party fixture. The exporter now synthesizes the description
// from the objects it emits, so the first HDF-produced export already equals the
// second rather than regenerating a synthetic string on the second hop.
describe('hdf-to-oscal-sar observation.description idempotency', () => {
  it('does not regenerate observation.description on the second export from the raw SAR', async () => {
    const raw = readFileSync(join(CONVERTERS, 'oscal-to-hdf', 'fixtures', 'input', 'sar-fedramp.json'), 'utf-8');

    const o2 = await roundTrip(raw);
    const o3 = await roundTrip(o2);

    expect(observationDescriptions(o3)).toEqual(observationDescriptions(o2));

    const vk = ['last-modified'];
    expect(maskVolatileJson(JSON.parse(o3), vk)).toEqual(maskVolatileJson(JSON.parse(o2), vk));
  });
});
