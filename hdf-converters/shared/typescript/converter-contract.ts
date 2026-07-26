/**
 * Shared converter contract tests.
 *
 * Tests the universal contract that every converter must satisfy:
 * empty input fails, invalid input fails, minimal fixture converts.
 * Call alongside converter-specific tests.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const convertersDir = join(__dirname, '..', '..', 'converters');

export interface ConverterContractSpec {
  /** Converter directory name, e.g. 'gosec-to-hdf' */
  converterName: string;
  /** The convert function (may be sync or async) */
  convertFn: (input: string) => string | Promise<string>;
  /** Path relative to fixtures/input/, e.g. 'minimal.json' */
  minimalFixture: string;
  /**
   * Inverts the empty-input contract: when true, empty input must convert
   * successfully (a valid "zero findings" signal) rather than throw. Set this
   * for converters of exit-code-first tools that emit no report on a clean run
   * (e.g. TruffleHog). Defaults to false — every other converter must still
   * reject empty input.
   */
  acceptsEmptyInput?: boolean;
}

/**
 * Run universal converter contract tests.
 */
export function runConverterContractTests(spec: ConverterContractSpec): void {
  describe(`${spec.converterName} contract`, () => {
    if (spec.acceptsEmptyInput) {
      it('accepts empty input as zero findings', async () => {
        const output = await Promise.resolve(spec.convertFn(''));
        expect(output).toBeTruthy();
        expect(() => JSON.parse(output)).not.toThrow();
      });
    } else {
      it('rejects empty input', async () => {
        await expect(Promise.resolve(spec.convertFn(''))).rejects.toThrow();
      });
    }

    it('rejects invalid input', async () => {
      await expect(Promise.resolve(spec.convertFn('not valid json'))).rejects.toThrow();
    });

    it('converts minimal fixture without error', async () => {
      const fixturePath = join(convertersDir, spec.converterName, 'fixtures', 'input', spec.minimalFixture);
      const input = readFileSync(fixturePath, 'utf-8');
      const output = await Promise.resolve(spec.convertFn(input));
      expect(output).toBeTruthy();
      // Should produce valid JSON
      expect(() => JSON.parse(output)).not.toThrow();
    });
  });
}
