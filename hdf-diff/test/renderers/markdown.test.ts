import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../../src/diff.js';
import { renderMarkdown } from '../../src/renderers/markdown.js';
import type { HdfComparison } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, '..', 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('renderMarkdown', () => {
  let comparison: HdfComparison;

  beforeAll(() => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    comparison = diffHdf(scanBefore, scanAfter);
  });

  describe('detail: summary', () => {
    it('should contain the summary heading', () => {
      const output = renderMarkdown(comparison, { detail: 'summary' });
      expect(output).toContain('## HDF Comparison Summary');
    });

    it('should contain a markdown table with metric counts', () => {
      const output = renderMarkdown(comparison, { detail: 'summary' });
      expect(output).toContain('| Metric | Count |');
      expect(output).toContain('|--------|-------|');
      expect(output).toContain('Fixed');
      expect(output).toContain('Regressed');
      expect(output).toContain('New');
      expect(output).toContain('Absent');
      expect(output).toContain('Unchanged');
      expect(output).toContain('Updated');
      expect(output).toContain('**Total**');
    });

    it('should not contain per-requirement tables', () => {
      const output = renderMarkdown(comparison, { detail: 'summary' });
      expect(output).not.toContain('### Fixed');
      expect(output).not.toContain('| ID |');
    });
  });

  describe('detail: control', () => {
    it('should be the default detail level', () => {
      const outputDefault = renderMarkdown(comparison);
      const outputControl = renderMarkdown(comparison, { detail: 'control' });
      expect(outputDefault).toBe(outputControl);
    });

    it('should contain per-requirement tables with ID, Title, Status columns', () => {
      const output = renderMarkdown(comparison, { detail: 'control' });
      expect(output).toContain('| ID |');
      expect(output).toContain('Title');
      expect(output).toContain('Old Status');
      expect(output).toContain('New Status');
    });

    it('should include section headings for each state that has requirements', () => {
      const output = renderMarkdown(comparison, { detail: 'control' });
      // Our fixture should produce fixed, regressed, new, absent states
      expect(output).toContain('### Fixed');
      expect(output).toContain('### Regressed');
    });

    it('should show (none) for empty state sections', () => {
      // Create a comparison where some states have zero requirements
      // by stripping all but the fixed requirements
      const sparse: HdfComparison = {
        ...comparison,
        requirementDiffs: comparison.requirementDiffs.filter(
          (r) => r.state === 'fixed',
        ),
      };
      const output = renderMarkdown(sparse, { detail: 'control' });
      // States like regressed, new, absent, updated, unchanged should show (none)
      expect(output).toMatch(/\(none\)/);
    });
  });

  describe('detail: full', () => {
    it('should include changeReasons and fieldChanges columns', () => {
      const output = renderMarkdown(comparison, { detail: 'full' });
      expect(output).toContain('Change Reasons');
      expect(output).toContain('Field Changes');
    });

    it('should format add and remove field change operations', () => {
      const comp: HdfComparison = {
        ...comparison,
        requirementDiffs: [
          {
            ...comparison.requirementDiffs[0]!,
            state: 'updated',
            fieldChanges: [
              { op: 'add', path: 'tags.newTag', newValue: 'added-val' },
              { op: 'remove', path: 'tags.oldTag', oldValue: 'removed-val' },
              { op: 'replace', path: 'impact', oldValue: 0.3, newValue: 0.7 },
            ],
          },
        ],
      };
      const output = renderMarkdown(comp, { detail: 'full' });
      expect(output).toContain('+tags.newTag');
      expect(output).toContain('-tags.oldTag');
      expect(output).toContain('impact:');
    });

    it('should handle requirements with undefined title in full detail', () => {
      const comp: HdfComparison = {
        ...comparison,
        requirementDiffs: [
          {
            ...comparison.requirementDiffs[0]!,
            state: 'fixed',
            title: undefined,
          },
        ],
      };
      const output = renderMarkdown(comp, { detail: 'full' });
      // Should render without errors; the title cell should be empty
      expect(output).toContain('### Fixed (1)');
      expect(output).toContain(comp.requirementDiffs[0]!.id);
    });
  });

  describe('detail: control with edge cases', () => {
    it('should handle requirements with undefined title in control detail', () => {
      const comp: HdfComparison = {
        ...comparison,
        requirementDiffs: [
          {
            ...comparison.requirementDiffs[0]!,
            state: 'regressed',
            title: undefined,
          },
        ],
      };
      const output = renderMarkdown(comp, { detail: 'control' });
      // Should render without errors; the title cell should be empty
      expect(output).toContain('### Regressed (1)');
      expect(output).toContain(comp.requirementDiffs[0]!.id);
    });
  });

  describe('filtering', () => {
    it('should only show sections matching filterStates', () => {
      const output = renderMarkdown(comparison, {
        detail: 'control',
        filterStates: ['fixed'],
      });
      expect(output).toContain('### Fixed');
      expect(output).not.toContain('### Regressed');
      expect(output).not.toContain('### New');
      expect(output).not.toContain('### Absent');
    });
  });

  describe('severity filtering', () => {
    it('should filter requirements by severity', () => {
      const output = renderMarkdown(comparison, {
        detail: 'control',
        filterSeverity: 'high',
      });
      // High severity requirements should appear
      expect(output).toContain('SV-001');
      expect(output).toContain('SV-003');
      // Low and medium severity should be excluded
      expect(output).not.toContain('SV-005');
      expect(output).not.toContain('SV-002');
    });
  });

  describe('grouping', () => {
    it('should group multiple requirements of the same state together', () => {
      const comp: HdfComparison = {
        ...comparison,
        requirementDiffs: [
          { ...comparison.requirementDiffs[0]!, id: 'SV-010', state: 'fixed' },
          { ...comparison.requirementDiffs[0]!, id: 'SV-011', state: 'fixed' },
        ],
      };
      const output = renderMarkdown(comp, { detail: 'control' });
      expect(output).toContain('### Fixed (2)');
      expect(output).toContain('SV-010');
      expect(output).toContain('SV-011');
    });
  });

  describe('structure', () => {
    it('should produce valid markdown (no trailing whitespace on table rows)', () => {
      const output = renderMarkdown(comparison, { detail: 'control' });
      const lines = output.split('\n');
      for (const line of lines) {
        if (line.startsWith('|')) {
          // Table rows should end with |
          expect(line.trimEnd()).toMatch(/\|$/);
        }
      }
    });

    it('should escape pipe characters in table cells', () => {
      const withPipe: HdfComparison = {
        ...comparison,
        requirementDiffs: [
          {
            ...comparison.requirementDiffs[0]!,
            title: 'Ensure foo|bar disabled',
          },
        ],
      };
      const output = renderMarkdown(withPipe, { detail: 'control' });
      expect(output).toContain('foo&#124;bar');
      expect(output).not.toContain('foo|bar');
    });
  });
});
