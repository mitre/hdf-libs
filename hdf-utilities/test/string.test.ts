import { describe, it, expect } from 'vitest';
import {
  stripHtml,
  parseTimestamp,
  formatTimestamp,
  trimUtcFraction,
} from '../src/string/index.js';

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

  // A zone-less ISO datetime must be interpreted as UTC (matching Go's
  // time.Parse with a zone-less layout), NOT host-local. Otherwise output
  // shifts by the host's UTC offset and diverges from the Go converter.
  it('treats a zone-less datetime as UTC, not host-local', () => {
    const result = parseTimestamp('2012-12-10T13:47:29');
    expect(result).not.toBeNull();
    // The instant must be 13:47:29 UTC regardless of the host timezone.
    expect(result!.toISOString()).toBe('2012-12-10T13:47:29.000Z');
  });

  it('treats a zone-less space-separated datetime as UTC', () => {
    const result = parseTimestamp('2012-12-10 13:47:29');
    expect(result).not.toBeNull();
    expect(result!.toISOString()).toBe('2012-12-10T13:47:29.000Z');
  });

  it('respects an explicit timezone offset (converts to the same instant)', () => {
    const result = parseTimestamp('2026-02-22T15:57:06-05:00');
    expect(result).not.toBeNull();
    expect(result!.toISOString()).toBe('2026-02-22T20:57:06.000Z');
  });

  it('respects an explicit Z designator', () => {
    const result = parseTimestamp('2024-11-15T10:30:00Z');
    expect(result!.toISOString()).toBe('2024-11-15T10:30:00.000Z');
  });
});

describe('trimUtcFraction', () => {
  it('drops an all-zero fraction', () => {
    expect(trimUtcFraction('2024-11-15T10:30:00.000Z')).toBe('2024-11-15T10:30:00Z');
  });

  it('trims only trailing zeros from a fraction', () => {
    expect(trimUtcFraction('2024-01-01T00:00:00.120Z')).toBe('2024-01-01T00:00:00.12Z');
    expect(trimUtcFraction('2024-01-01T00:00:00.100Z')).toBe('2024-01-01T00:00:00.1Z');
  });

  it('leaves a fraction with no trailing zeros unchanged', () => {
    expect(trimUtcFraction('2024-01-01T00:00:00.123Z')).toBe('2024-01-01T00:00:00.123Z');
  });

  it('leaves a fraction-free timestamp unchanged', () => {
    expect(trimUtcFraction('2024-11-15T10:30:00Z')).toBe('2024-11-15T10:30:00Z');
  });
});

describe('formatTimestamp', () => {
  it('formats a Date as trimmed-UTC RFC3339 (whole second)', () => {
    expect(formatTimestamp(new Date('2024-11-15T10:30:00Z'))).toBe('2024-11-15T10:30:00Z');
  });

  it('formats a Date with milliseconds, trimming trailing zeros', () => {
    expect(formatTimestamp(new Date('2024-01-01T00:00:00.120Z'))).toBe('2024-01-01T00:00:00.12Z');
  });

  it('normalizes an offset-bearing instant to UTC', () => {
    expect(formatTimestamp(new Date('2026-02-22T15:57:06-05:00'))).toBe('2026-02-22T20:57:06Z');
  });
});
