import { describe, expect, it } from 'vitest';
import { createAjvWithPrimitives } from './setup';
import amendments from '../src/schemas/hdf-amendments.schema.json';
import baseline from '../src/schemas/hdf-baseline.schema.json';
import evidence from '../src/schemas/hdf-evidence-package.schema.json';
import plan from '../src/schemas/hdf-plan.schema.json';
import system from '../src/schemas/hdf-system.schema.json';
import results from '../src/schemas/hdf-results.schema.json';

describe('document labels and external identities', () => {
  for (const schema of [amendments, baseline, evidence, plan, system]) {
    const validate = createAjvWithPrimitives().compile(schema);

    it(`${schema.$id} carries grouping and producing-run identity together`, () => {
      const document = {
        ...schema.examples[0],
        labels: { pipeline: 'nightly', environment: 'production' },
        externalIds: { 'ci-run': 'https://ci.example.org/projects/portal/runs/4821' },
      };
      expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
    });

    it(`${schema.$id} keeps metadata optional`, () => {
      const document = Object.fromEntries(Object.entries(schema.examples[0])
        .filter(([key]) => key !== 'labels' && key !== 'externalIds'));
      expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
    });

    for (const field of ['labels', 'externalIds']) {
      for (const invalid of [null, [], 'nightly', { pipeline: 4821 }, { pipeline: {} }]) {
        it(`${schema.$id} rejects ${field}=${JSON.stringify(invalid)}`, () => {
          expect(validate({ ...schema.examples[0], [field]: invalid })).toBe(false);
        });
      }
    }
  }

  it('keeps document and component metadata separate on systems', () => {
    const validate = createAjvWithPrimitives().compile(system);
    expect(validate({
      ...system.examples[0],
      labels: { environment: 'assessment' },
      externalIds: { 'ci-run': '4821' },
      components: [{
        name: 'web', type: 'host',
        labels: { environment: 'production' },
        externalIds: { cmdb: 'CI0012345' },
      }],
    }), JSON.stringify(validate.errors)).toBe(true);
  });

  it('does not introduce document metadata on results', () => {
    const validate = createAjvWithPrimitives().compile(results);
    expect(validate({ ...results.examples[0], labels: { pipeline: 'nightly' } })).toBe(false);
    expect(validate({ ...results.examples[0], externalIds: { 'ci-run': '4821' } })).toBe(false);
  });
});
