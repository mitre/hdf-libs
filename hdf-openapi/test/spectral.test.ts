import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { lintDocument } from '../scripts/spectral-lint.mjs';
import { main as writeApiDocument } from '../src/generate-api.js';

const HERE = new URL('.', import.meta.url).pathname;
const PKG = join(HERE, '..');
const API = join(PKG, 'dist', 'hdf-api.oas.json');

// The generator writes the artifact this lints, so write it here rather than trusting a
// previous local run: otherwise this fails in CI and passes locally for the wrong reason.
writeApiDocument();

describe('Spectral on the generated reference API', () => {
  it('reports no errors', async () => {
    const { errors } = await lintDocument(API);
    expect(errors.map((e) => `${e.code} at ${e.path.join('/')}`)).toEqual([]);
  });

  // The waiver is scoped to one path, not applied to the rule. A blanket `array-items: off`
  // would satisfy the check above while hiding every future violation, so the same defect
  // planted elsewhere must still be reported.
  it('still reports the same rule elsewhere, so the waiver is scoped not blanket', async () => {
    const doc = JSON.parse(readFileSync(API, 'utf-8')) as {
      components: { schemas: Record<string, unknown> };
    };
    doc.components.schemas.PlantedLooseArray = {
      type: 'object',
      additionalProperties: false,
      properties: { things: { type: 'array' } },
    };
    const dir = mkdtempSync(join(tmpdir(), 'spectral-'));
    const planted = join(dir, 'planted.json');
    writeFileSync(planted, JSON.stringify(doc));
    const { errors } = await lintDocument(planted);
    expect(errors.map((e) => e.code)).toContain('array-items');
  });

  // The waiver exists only because a tracked schema defect does. When that lands, this
  // fails and the waiver has to be removed rather than lingering as dead config.
  it('the waived path still has the defect the waiver is for', () => {
    const doc = JSON.parse(readFileSync(API, 'utf-8')) as {
      components: { schemas: Record<string, { properties?: Record<string, Record<string, unknown>> }> };
    };
    const allowedValues = doc.components.schemas.Input_Constraints?.properties?.allowedValues;
    expect(allowedValues, 'Input_Constraints.allowedValues is gone — remove the waiver').toBeDefined();
    expect(allowedValues!.type).toBe('array');
    expect(
      allowedValues!.items,
      'allowedValues now declares items, so the scoped waiver is dead config and must be removed',
    ).toBeUndefined();
  });
});
