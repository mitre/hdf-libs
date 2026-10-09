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

// ADR-0008 §3 requires a deprecated operation to carry both dates and notes that no
// built-in rule checks it — Spectral's oas-deprecated only checks the field is boolean.
// So the rule is custom, and these are the planted violations the card asks for.
describe('the custom deprecation rule', () => {
  const plant = (overrides: Record<string, unknown>): string => {
    const doc = JSON.parse(readFileSync(API, 'utf-8')) as {
      paths: Record<string, Record<string, Record<string, unknown>>>;
    };
    Object.assign(doc.paths['/documents/{id}']!.get!, overrides);
    const dir = mkdtempSync(join(tmpdir(), 'deprecation-'));
    const file = join(dir, 'planted.json');
    writeFileSync(file, JSON.stringify(doc));
    return file;
  };

  it('fails a deprecated operation with no x-hdf-sunset, and names the field', async () => {
    const { errors } = await lintDocument(
      plant({ deprecated: true, 'x-hdf-deprecation': '2026-01-01' }),
    );
    expect(errors.map((e) => e.code)).toContain('hdf-deprecation-dates');
    expect(errors.map((e) => e.message).join(' ')).toContain('x-hdf-sunset');
  });

  it('fails a deprecated operation with no x-hdf-deprecation', async () => {
    const { errors } = await lintDocument(plant({ deprecated: true, 'x-hdf-sunset': '2027-01-01' }));
    expect(errors.map((e) => e.message).join(' ')).toContain('x-hdf-deprecation');
  });

  it('fails a deprecation dated after its sunset, naming both values', async () => {
    const { errors } = await lintDocument(
      plant({ deprecated: true, 'x-hdf-deprecation': '2027-06-01', 'x-hdf-sunset': '2026-01-01' }),
    );
    const message = errors.map((e) => e.message).join(' ');
    expect(message).toContain('2027-06-01');
    expect(message).toContain('2026-01-01');
  });

  // The rule must not fire on a healthy deprecated operation, or it would force every
  // deprecation to be a lint failure and teach people to waive it.
  it('accepts a deprecated operation that carries both dates in order', async () => {
    const { errors } = await lintDocument(
      plant({ deprecated: true, 'x-hdf-deprecation': '2026-01-01', 'x-hdf-sunset': '2027-01-01' }),
    );
    expect(errors.filter((e) => e.code === 'hdf-deprecation-dates')).toEqual([]);
  });

  it('does not fire on the real document, where nothing is deprecated yet', async () => {
    const { errors } = await lintDocument(API);
    expect(errors.filter((e) => e.code === 'hdf-deprecation-dates')).toEqual([]);
  });
});
