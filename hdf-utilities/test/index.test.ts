import { describe, it, expect } from 'vitest';
import { parseJSON, stringifyJSON, isValidJSON } from '../src/index.js';

describe('hdf-utilities exports', () => {
  it('should export parseJSON function', () => {
    expect(typeof parseJSON).toBe('function');
  });

  it('should export stringifyJSON function', () => {
    expect(typeof stringifyJSON).toBe('function');
  });

  it('should export isValidJSON function', () => {
    expect(typeof isValidJSON).toBe('function');
  });

  it('should work with exported functions', () => {
    const obj = { test: 'value' };
    const json = stringifyJSON(obj);
    const parsed = parseJSON(json);
    expect(parsed).toEqual(obj);
    expect(isValidJSON(json)).toBe(true);
  });
});
