import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { validateResults } from './index.js';

describe('Integration Tests - Real HDF Files', () => {
  it('should validate minimal HDF results fixture', () => {
    const hdfData = JSON.parse(results.minimal.read());

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
          integrity: { algorithm: 'sha256', checksum: 'test' },
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
