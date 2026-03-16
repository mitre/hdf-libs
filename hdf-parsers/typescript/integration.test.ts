import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { parseResults, parse } from './index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('Integration Tests - Real HDF Files', () => {
  it('should parse minimal HDF results fixture', () => {
    const fixturePath = join(__dirname, '../../hdf-converters/converters/hdf-to-xml/fixtures/input/minimal.json');
    const hdfJson = readFileSync(fixturePath, 'utf-8');

    const result = parseResults(hdfJson);

    expect(result.success).toBe(true);
    expect(result.data).toBeDefined();
    expect(result.data!.baselines).toBeDefined();

    if (!result.success) {
      console.log('Parse error:', result.error);
    }
  });

  it('should auto-detect HDF results type', () => {
    const fixturePath = join(__dirname, '../../hdf-converters/converters/hdf-to-xml/fixtures/input/minimal.json');
    const hdfJson = readFileSync(fixturePath, 'utf-8');

    const result = parse(hdfJson);

    expect(result.success).toBe(true);
    expect(result.type).toBe('results');
    expect(result.data).toBeDefined();
  });

  it('should provide clear error for malformed JSON', () => {
    const malformedJson = '{ "baselines": [';

    const result = parseResults(malformedJson);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/JSON|parse|unexpected/i);
  });

  it('should provide clear error for invalid HDF structure', () => {
    const invalidHdf = JSON.stringify({
      baselines: [{
        // Missing required fields
        name: 'Test'
      }],
      targets: [],
      statistics: {}
    });

    const result = parseResults(invalidHdf);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toContain('Schema validation failed');
  });
});
