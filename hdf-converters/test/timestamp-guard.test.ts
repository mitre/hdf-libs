import { describe, it, expect } from 'vitest';
import { Linter } from 'eslint';
import tsparser from '@typescript-eslint/parser';
import config, { DATE_GUARD_RULES } from '../eslint.config.js';

// 7vsq: the timestamp guard once existed but silently never fired (a broken
// selector / narrowed file scope gives false security — worse than no guard).
// These tests lock both halves: the selectors actually match the footgun forms,
// and the rule is scoped to every source tree that parses tool timestamps.

const linter = new Linter();
function fires(code: string): boolean {
  const msgs = linter.verify(code, {
    languageOptions: { parser: tsparser as unknown as Linter.Parser },
    rules: { 'no-restricted-syntax': ['error', ...DATE_GUARD_RULES] },
  });
  return msgs.some((m) => m.ruleId === 'no-restricted-syntax');
}

describe('timestamp guard — new Date(value) footgun', () => {
  it('fires on every dynamic-value form a converter might use', () => {
    expect(fires('new Date(raw)')).toBe(true); // Identifier
    expect(fires('new Date(r.startTime)')).toBe(true); // MemberExpression
    expect(fires('new Date(raw as string)')).toBe(true); // TSAsExpression
    expect(fires('new Date(raw!)')).toBe(true); // TSNonNullExpression
    expect(fires('new Date(String(raw))')).toBe(true); // CallExpression
    expect(fires('new Date(`${raw}`)')).toBe(true); // TemplateLiteral
  });

  it('does not fire on the safe forms', () => {
    expect(fires('new Date()')).toBe(false); // now
    expect(fires('new Date(0)')).toBe(false); // epoch literal
    expect(fires("new Date('0001-01-01T00:00:00Z')")).toBe(false); // fixed sentinel literal
    expect(fires('new Date(t.getTime() + 1000)')).toBe(false); // arithmetic (number)
  });
});

describe('timestamp guard — file scope', () => {
  it('applies to both converters/ and shared/ source (not just converters/)', () => {
    const guardBlock = (config as Array<{ files?: string[]; rules?: Record<string, unknown> }>).find(
      (b) => b.rules && 'no-restricted-syntax' in b.rules
    );
    expect(guardBlock).toBeDefined();
    expect(guardBlock!.files).toContain('converters/**/*.ts');
    expect(guardBlock!.files).toContain('shared/**/*.ts');
  });
});
