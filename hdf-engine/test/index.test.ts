import { describe, it, expect } from 'vitest';
import { engineVersion } from '../src/index.js';

describe('@mitre/hdf-engine scaffold', () => {
  it('exports a non-empty version string on the workspace lockstep', () => {
    expect(engineVersion).toBeTruthy();
    expect(engineVersion).toBe('3.5.0');
  });
});
