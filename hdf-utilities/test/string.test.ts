import { describe, it, expect } from 'vitest';
import { stripHtml, parseTimestamp } from '../src/string/index.js';

describe('stripHtml', () => {
  it('should strip simple tags', () => {
    expect(stripHtml('<p>hello</p> <b>world</b>')).toBe('hello world');
  });

  it('should strip nested tags', () => {
    expect(stripHtml('<div><span>text</span></div>')).toBe('text');
  });

  it('should normalize whitespace', () => {
    expect(stripHtml('  a   b   c  ')).toBe('a b c');
  });

  it('should handle self-closing tags', () => {
    expect(stripHtml('before<br/>after')).toBe('before after');
  });

  it('should return empty string for empty input', () => {
    expect(stripHtml('')).toBe('');
  });

  it('should return plain text unchanged', () => {
    expect(stripHtml('no tags here')).toBe('no tags here');
  });

  it('should handle tags with attributes', () => {
    expect(stripHtml('<a href="http://example.com">link text</a>')).toBe(
      'link text',
    );
  });
});

describe('parseTimestamp', () => {
  it('should parse ISO 8601 / RFC 3339', () => {
    const result = parseTimestamp('2024-01-15T10:30:00Z');
    expect(result).not.toBeNull();
    expect(result!.getUTCFullYear()).toBe(2024);
    expect(result!.getUTCMonth()).toBe(0); // January
    expect(result!.getUTCDate()).toBe(15);
  });

  it('should parse RFC 3339 with nanoseconds', () => {
    const result = parseTimestamp('2024-01-15T10:30:00.123456789Z');
    expect(result).not.toBeNull();
    expect(result!.getUTCFullYear()).toBe(2024);
  });

  it('should parse RFC 3339 with timezone offset', () => {
    const result = parseTimestamp('2024-01-15T10:30:00+05:00');
    expect(result).not.toBeNull();
    expect(result!.getFullYear()).toBe(2024);
  });

  it('should parse RFC 2822 format', () => {
    const result = parseTimestamp('Mon, 15 Jan 2024 10:30:00 UTC');
    expect(result).not.toBeNull();
    expect(result!.getUTCFullYear()).toBe(2024);
  });

  it('should return null for empty string', () => {
    expect(parseTimestamp('')).toBeNull();
  });

  it('should return null for whitespace-only string', () => {
    expect(parseTimestamp('   ')).toBeNull();
  });

  it('should return null for unparseable string', () => {
    expect(parseTimestamp('not a timestamp')).toBeNull();
  });

  it('should parse ISO 8601 date-only', () => {
    const result = parseTimestamp('2024-01-15');
    expect(result).not.toBeNull();
    expect(result!.getFullYear()).toBe(2024);
  });
});
