import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import type { BaselineRequirement } from '@mitre/hdf-schema';
import { generateInSpecProfile } from '../src/profile-generator.js';
import { makeBaseline } from './helpers.js';

interface IdTypeCase {
  why: string;
  idType: string;
  requirements: BaselineRequirement[];
  controls?: Record<string, string>;
  error?: string;
  perFileOnly?: boolean;
}

// The Go peer (GenerateInSpecProfile) asserts against this same table.
const { cases } = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'id-type-cases.json'), 'utf-8'),
) as { cases: IdTypeCase[] };

describe('generateInSpecProfile idType', () => {
  it('reads a non-empty shared table', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  describe.each(cases)('$why', ({ idType, requirements, controls, error, perFileOnly }) => {
    it.each([false, true])('single file %s', (singleFile) => {
      const baseline = makeBaseline({ name: 'b', requirements });
      const run = () => generateInSpecProfile(baseline, { idType, singleFile });
      if (error && !(singleFile && perFileOnly)) {
        expect(run).toThrow(new Error(error));
        return;
      }
      const profile = run();
      if (error) return;
      if (singleFile) {
        for (const first of Object.values(controls ?? {})) {
          expect(profile.controls.get('controls/controls.rb')).toContain(`${first}\n`);
        }
        return;
      }
      const firstLines = Object.fromEntries([...profile.controls].map(([name, src]) => [name, src.split('\n')[0]]));
      expect(firstLines).toEqual(controls);
    });
  });
});
