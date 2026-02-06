import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { validateResults } from './index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('Integration Tests - Real HDF Files', () => {
  it('should validate minimal HDF results fixture', () => {
    const fixturePath = join(__dirname, '../../hdf-converters/converters/hdf-to-xml/fixtures/input/minimal.json');
    const hdfJson = readFileSync(fixturePath, 'utf-8');
    const hdfData = JSON.parse(hdfJson);

    const result = validateResults(hdfData);

    expect(result.valid).toBe(true);
    if (!result.valid) {
      console.log('Validation errors:', result.errors);
      console.log('Error message:', result.getErrorMessage());
    }
  });

  it('should provide detailed errors for invalid HDF', () => {
    const invalid = {
      baselines: [
        {
          // Missing name
          checksum: { algorithm: 'sha256', value: 'test' },
          requirements: 'not an array' // Invalid type
        }
      ]
    };

    const result = validateResults(invalid);

    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);

    const errorMsg = result.getErrorMessage();
    expect(errorMsg).toBeTruthy();
    expect(errorMsg).toContain('name');
  });
});
