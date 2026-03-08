import { describe, it, expect } from 'vitest';
import {
  escapeQuotes,
  generateControlStub,
  generateInSpecYml,
  generateInSpecProfile,
} from '../src/index.js';

describe('barrel exports', () => {
  it('exports all public functions', () => {
    expect(typeof escapeQuotes).toBe('function');
    expect(typeof generateControlStub).toBe('function');
    expect(typeof generateInSpecYml).toBe('function');
    expect(typeof generateInSpecProfile).toBe('function');
  });
});
