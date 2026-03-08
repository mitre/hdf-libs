import { describe, it, expect } from 'vitest';
import { escapeQuotes } from '../src/ruby-escape.js';

describe('escapeQuotes', () => {
  it('wraps plain text in single quotes', () => {
    expect(escapeQuotes('hello world')).toBe("'hello world'");
  });

  it('wraps empty string in single quotes', () => {
    expect(escapeQuotes('')).toBe("''");
  });

  it('uses double quotes when string contains single quotes', () => {
    // In Ruby double-quoted strings, single quotes don't need escaping
    expect(escapeQuotes("it's a test")).toBe("\"it's a test\"");
  });

  it('uses single quotes when string contains double quotes', () => {
    // In Ruby single-quoted strings, double quotes don't need escaping
    expect(escapeQuotes('say "hello"')).toBe("'say \"hello\"'");
  });

  it('uses %q() when string contains both quote types', () => {
    expect(escapeQuotes(`it's a "test"`)).toBe(`%q(it's a "test")`);
  });

  it('escapes backslashes before closing parens in %q mode', () => {
    // \) → \\) so Ruby sees literal backslash, then ) closes %q() delimiter
    expect(escapeQuotes(`it's a "test" with \\)`)).toBe(`%q(it's a "test" with \\\\))`);
  });

  it('escapes backslashes in single-quoted strings', () => {
    expect(escapeQuotes('path\\to\\file')).toBe("'path\\\\to\\\\file'");
  });

  it('escapes backslashes in double-quoted strings', () => {
    // Double-quoted: backslashes escaped, single quotes pass through
    expect(escapeQuotes("it's a path\\to\\file")).toBe("\"it's a path\\\\to\\\\file\"");
  });

  it('handles multiline content', () => {
    const input = 'line one\nline two';
    const result = escapeQuotes(input);
    expect(result).toContain('line one');
    expect(result).toContain('line two');
  });

  it('handles strings with only backslashes', () => {
    expect(escapeQuotes('\\')).toBe("'\\\\'");
  });
});
