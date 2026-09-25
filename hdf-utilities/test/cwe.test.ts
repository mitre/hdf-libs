import { describe, it, expect } from 'vitest';
import { extractCWEIDs, CWE_PATTERN } from '../src/cwe/index.js';

// Parity: TestExtractCWEIDs in go/cwe_test.go. The spellings recognised here are
// the ones the whole workspace accepts, so a filter written against this cannot
// be stricter than the converters that populate the field.
describe('extractCWEIDs', () => {
  it('recognises the three spellings, case-insensitively', () => {
    expect(extractCWEIDs('CWE-79')).toEqual(['79']);
    expect(extractCWEIDs('CWE 79')).toEqual(['79']);
    expect(extractCWEIDs('cwe79')).toEqual(['79']);
    expect(extractCWEIDs('Cwe-79')).toEqual(['79']);
  });

  it('deduplicates and sorts', () => {
    expect(extractCWEIDs('CWE-89 CWE-79 cwe 89')).toEqual(['79', '89']);
  });

  it('returns an empty array when the text names none', () => {
    expect(extractCWEIDs('')).toEqual([]);
    expect(extractCWEIDs('no weakness here')).toEqual([]);
    // A bare number is deliberately NOT a CWE id — the prefix is what makes it one.
    expect(extractCWEIDs('79')).toEqual([]);
  });

  it('is a global regex, so repeated use does not skip matches', () => {
    // A /g regex carries lastIndex; extractCWEIDs must not leak it between calls.
    expect(extractCWEIDs('CWE-1')).toEqual(['1']);
    expect(extractCWEIDs('CWE-1')).toEqual(['1']);
    expect(CWE_PATTERN.global).toBe(true);
  });
});
