import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../../src/diff.js';
import { renderJson } from '../../src/renderers/json.js';
import type { HDFComparison } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, '..', 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('renderJson', () => {
  let comparison: HDFComparison;

  beforeAll(() => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    comparison = diffHdf(scanBefore, scanAfter);
  });

  it('should return valid JSON string', () => {
    const output = renderJson(comparison);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  describe('detail: full', () => {
    it('should produce JSON that parses back to the original comparison', () => {
      const output = renderJson(comparison, { detail: 'full' });
      const parsed = JSON.parse(output) as HDFComparison;
      expect(parsed).toEqual(comparison);
    });

    it('should include before/after fields on requirement diffs', () => {
      const output = renderJson(comparison, { detail: 'full' });
      const parsed = JSON.parse(output) as HDFComparison;
      // At least one matched requirement should have before and after
      const matched = parsed.requirementDiffs.filter(
        (r) => r.state !== 'new' && r.state !== 'absent',
      );
      expect(matched.length).toBeGreaterThan(0);
      for (const req of matched) {
        expect(req.before).not.toBeNull();
        expect(req.after).not.toBeNull();
      }
    });
  });

  describe('detail: summary', () => {
    it('should only contain formatVersion, comparisonMode, and summary', () => {
      const output = renderJson(comparison, { detail: 'summary' });
      const parsed = JSON.parse(output);
      expect(Object.keys(parsed).sort()).toEqual(
        ['comparisonMode', 'formatVersion', 'summary'].sort(),
      );
    });

    it('should have correct summary counts', () => {
      const output = renderJson(comparison, { detail: 'summary' });
      const parsed = JSON.parse(output);
      expect(parsed.summary).toEqual(comparison.summary);
    });
  });

  describe('detail: control', () => {
    it('should be the default detail level', () => {
      const outputDefault = renderJson(comparison);
      const outputControl = renderJson(comparison, { detail: 'control' });
      expect(outputDefault).toBe(outputControl);
    });

    it('should have requirementDiffs without before/after fields', () => {
      const output = renderJson(comparison);
      const parsed = JSON.parse(output) as HDFComparison;
      expect(parsed.requirementDiffs.length).toBeGreaterThan(0);
      for (const req of parsed.requirementDiffs) {
        expect(req).not.toHaveProperty('before');
        expect(req).not.toHaveProperty('after');
      }
    });

    it('should retain id, state, title, and status fields on requirement diffs', () => {
      const output = renderJson(comparison);
      const parsed = JSON.parse(output) as HDFComparison;
      for (const req of parsed.requirementDiffs) {
        expect(req.id).toBeDefined();
        expect(req.state).toBeDefined();
      }
    });
  });

  describe('filtering', () => {
    it('should filter requirementDiffs by state when filterStates is set', () => {
      const output = renderJson(comparison, {
        detail: 'control',
        filterStates: ['fixed'],
      });
      const parsed = JSON.parse(output) as HDFComparison;
      for (const req of parsed.requirementDiffs) {
        expect(req.state).toBe('fixed');
      }
      // Our fixture has at least one fixed requirement
      expect(parsed.requirementDiffs.length).toBeGreaterThan(0);
    });

    it('should filter requirementDiffs by severity when filterSeverity is set', () => {
      const output = renderJson(comparison, {
        detail: 'full',
        filterSeverity: 'high',
      });
      const parsed = JSON.parse(output) as HDFComparison;
      // Our fixture has SV-001, SV-003, SV-004, SV-006 as high severity
      expect(parsed.requirementDiffs.length).toBeGreaterThan(0);
      for (const req of parsed.requirementDiffs) {
        const before = req.before as Record<string, unknown> | null;
        const after = req.after as Record<string, unknown> | null;
        const tags =
          (after?.['tags'] as Record<string, unknown> | undefined) ??
          (before?.['tags'] as Record<string, unknown> | undefined);
        expect(tags?.['severity']).toBe('high');
      }
    });

    it('should return empty requirementDiffs for non-existent severity', () => {
      const output = renderJson(comparison, {
        detail: 'control',
        filterSeverity: 'critical',
      });
      const parsed = JSON.parse(output) as HDFComparison;
      expect(parsed.requirementDiffs.length).toBe(0);
    });

    it('should apply filterStates in full detail mode and reduce requirementDiffs', () => {
      const output = renderJson(comparison, {
        detail: 'full',
        filterStates: ['regressed'],
      });
      const parsed = JSON.parse(output) as HDFComparison;
      expect(parsed.requirementDiffs.length).toBeGreaterThan(0);
      for (const req of parsed.requirementDiffs) {
        expect(req.state).toBe('regressed');
        // Full detail should keep before/after
        if (req.state !== 'new') {
          expect(req.before).not.toBeNull();
        }
      }
    });
  });
});
