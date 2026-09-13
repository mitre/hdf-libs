import { describe, it, expect, vi } from 'vitest';
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

describe('validateInputSize — cheap-bound edges', () => {
  // The guard settles most inputs from the string length alone: UTF-8 is never
  // shorter than the code-unit count, never longer than three times it. These
  // pin the two bounds and the band between them.
  it('accepts outright when three bytes per code unit still fits', () => {
    expect(() => validateInputSize('abcdefghij', 30)).not.toThrow();
  });
  it('rejects outright when the code-unit count alone exceeds the limit', () => {
    expect(() => validateInputSize('abcdefghij', 9)).toThrow(/exceeds maximum/);
  });
  it('measures exactly inside the band', () => {
    expect(() => validateInputSize('abcdefghij', 29)).not.toThrow();
    expect(() => validateInputSize('€'.repeat(10), 30)).not.toThrow();
    expect(() => validateInputSize('€'.repeat(10), 29)).toThrow(/exceeds maximum/);
  });
  it('counts a surrogate pair as four bytes, not six', () => {
    expect(() => validateInputSize('𝄞'.repeat(10), 40)).not.toThrow();
    expect(() => validateInputSize('𝄞'.repeat(10), 39)).toThrow(/exceeds maximum/);
  });
  it('counts a lone surrogate as the three-byte replacement, as TextEncoder does', () => {
    expect(() => validateInputSize('\ud800', 3)).not.toThrow();
    expect(() => validateInputSize('\ud800', 2)).toThrow(/exceeds maximum/);
    expect(() => validateInputSize('\udc00x', 4)).not.toThrow();
    expect(() => validateInputSize('\udc00x', 3)).toThrow(/exceeds maximum/);
  });
  it('reports the measured byte count, not the code-unit count', () => {
    expect(() => validateInputSize('€€', 2)).toThrow(/\(6 bytes provided\)/);
  });
  it('measures a Uint8Array by its own length', () => {
    expect(() => validateInputSize(new Uint8Array(5), 4)).toThrow(/exceeds maximum/);
    expect(() => validateInputSize(new Uint8Array(5), 5)).not.toThrow();
  });
  it('never allocates a UTF-8 copy of the input to measure it', () => {
    // The guard exists to reject oversized input; encoding it first would double
    // peak memory at exactly the point it is meant to protect.
    const encode = vi.spyOn(TextEncoder.prototype, 'encode');
    try {
      expect(() => validateInputSize('abcdefghij', 30)).not.toThrow();
      expect(() => validateInputSize('abcdefghij', 9)).toThrow(/exceeds maximum/);
      expect(() => validateInputSize('€'.repeat(10), 30)).not.toThrow();
      expect(encode).not.toHaveBeenCalled();
    } finally {
      encode.mockRestore();
    }
  });
});
