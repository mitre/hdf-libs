/**
 * Differential tests for legacyhdf converter.
 *
 * Tests TypeScript implementation against expected outputs.
 * Go implementation tested separately but uses same fixtures.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertV1ToV2 } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '../fixtures');
const INPUT_DIR = join(FIXTURES_DIR, 'input');
const EXPECTED_DIR = join(FIXTURES_DIR, 'expected');
const OUTPUT_DIR = join(__dirname, '../../../../test-output/differential/typescript/legacyhdf');

describe('legacyhdf Converter - Differential Tests', () => {
  // Get all test cases from input directory
  const testFiles = readdirSync(INPUT_DIR).filter(f => f.endsWith('.json'));

  // Ensure output directory exists
  mkdirSync(OUTPUT_DIR, { recursive: true });

  for (const testFile of testFiles) {
    it(`should convert ${testFile} correctly`, () => {
      // Read input (v1.0)
      const inputPath = join(INPUT_DIR, testFile);
      const v1Data = JSON.parse(readFileSync(inputPath, 'utf-8'));

      // Convert
      const v2Data = convertV1ToV2(v1Data);

      // Write output for comparison with Go implementation
      const outputPath = join(OUTPUT_DIR, testFile);
      writeFileSync(outputPath, JSON.stringify(v2Data, null, 2));

      // Read expected output
      const expectedPath = join(EXPECTED_DIR, testFile);
      const expected = JSON.parse(readFileSync(expectedPath, 'utf-8'));

      // Compare
      expect(v2Data).toEqual(expected);
    });
  }

  it('should have at least one test case', () => {
    expect(testFiles.length).toBeGreaterThan(0);
  });
});
