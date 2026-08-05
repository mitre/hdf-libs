import { describe, it, expect } from 'vitest';
import { validateInputSize, DEFAULT_MAX_INPUT_SIZE } from './index.js';

describe('validateInputSize — parity with go/size.go ValidateInputSize', () => {
  it('accepts input under the limit', () => {
    expect(() => validateInputSize('hello', 100)).not.toThrow();
  });
  it('accepts input at the limit', () => {
    expect(() => validateInputSize('hello', 5)).not.toThrow();
  });
  it('rejects input over the limit', () => {
    expect(() => validateInputSize('hello', 4)).toThrow(/exceeds maximum/);
  });
  it('empty input is always ok', () => {
    expect(() => validateInputSize('', 1)).not.toThrow();
  });
  it('maxSize <= 0 falls back to the default', () => {
    expect(() => validateInputSize('x', 0)).not.toThrow();
    expect(() => validateInputSize('x', -1)).not.toThrow();
  });
  it('measures UTF-8 byte length, not code units (parity with Go []byte)', () => {
    // "€" is 3 UTF-8 bytes but 1 JS code unit.
    expect(() => validateInputSize('€', 2)).toThrow(/exceeds maximum/);
    expect(() => validateInputSize('€', 3)).not.toThrow();
  });
  it('enforces the default limit', () => {
    expect(DEFAULT_MAX_INPUT_SIZE).toBe(50 * 1024 * 1024);
    const over = 'a'.repeat(DEFAULT_MAX_INPUT_SIZE + 1);
    expect(() => validateInputSize(over)).toThrow(/exceeds maximum/);
  });
});
