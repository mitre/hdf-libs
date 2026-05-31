import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../../src/diff.js';
import { renderCsv } from '../../src/renderers/csv.js';
import type { HDFComparison } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, '..', 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('renderCsv', () => {
  let comparison: HDFComparison;

  beforeAll(() => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    comparison = diffHdf(scanBefore, scanAfter);
  });

  it('should include a header row as the first line', () => {
    const output = renderCsv(comparison);
    const firstLine = output.split('\n')[0]!;
    expect(firstLine).toContain('ID');
    expect(firstLine).toContain('Title');
    expect(firstLine).toContain('State');
    expect(firstLine).toContain('Old Status');
    expect(firstLine).toContain('New Status');
  });

  it('should have correct number of data rows (one per requirement)', () => {
    const output = renderCsv(comparison);
    const lines = output.split('\n').filter((l) => l.trim() !== '');
    // Header + one row per requirement
    expect(lines.length).toBe(comparison.requirementDiffs.length + 1);
  });

  it('should properly quote fields containing commas', () => {
    // Create a comparison with a comma in a title
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    const comp = diffHdf(scanBefore, scanAfter);

    // Inject a title with a comma to verify quoting
    if (comp.requirementDiffs.length > 0) {
      comp.requirementDiffs[0]!.title = 'Ensure SSH, SFTP are disabled';
    }

    const output = renderCsv(comp);
    expect(output).toContain('"Ensure SSH, SFTP are disabled"');
  });

  it('should properly escape fields containing double quotes', () => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    const comp = diffHdf(scanBefore, scanAfter);

    if (comp.requirementDiffs.length > 0) {
      comp.requirementDiffs[0]!.title = 'Ensure "root" login disabled';
    }

    const output = renderCsv(comp);
    expect(output).toContain('"Ensure ""root"" login disabled"');
  });

  it('should properly escape fields containing newlines', () => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    const comp = diffHdf(scanBefore, scanAfter);

    if (comp.requirementDiffs.length > 0) {
      comp.requirementDiffs[0]!.title = 'Line one\nLine two';
    }

    const output = renderCsv(comp);
    expect(output).toContain('"Line one\nLine two"');
  });

  it('should include all requirement IDs in the output', () => {
    const output = renderCsv(comparison);
    for (const req of comparison.requirementDiffs) {
      expect(output).toContain(req.id);
    }
  });

  it('should include Change Reasons column', () => {
    const output = renderCsv(comparison);
    const firstLine = output.split('\n')[0]!;
    expect(firstLine).toContain('Change Reasons');
  });

  describe('detail levels', () => {
    it('should include field changes columns when detail is full', () => {
      const output = renderCsv(comparison, { detail: 'full' });
      const firstLine = output.split('\n')[0]!;
      expect(firstLine).toContain('Field Changes');
    });

    it('should not include field changes column when detail is control', () => {
      const output = renderCsv(comparison, { detail: 'control' });
      const firstLine = output.split('\n')[0]!;
      expect(firstLine).not.toContain('Field Changes');
    });

    it('should format add and remove field change operations in full mode', () => {
      const comp: HDFComparison = {
        ...comparison,
        requirementDiffs: [
          {
            ...comparison.requirementDiffs[0]!,
            title: 'Test req',
            fieldChanges: [
              { op: 'add', path: 'tags.newTag', newValue: 'added' },
              { op: 'remove', path: 'tags.oldTag', oldValue: 'removed' },
              { op: 'replace', path: 'impact', oldValue: 0.3, newValue: 0.7 },
            ],
          },
        ],
      };
      const output = renderCsv(comp, { detail: 'full' });
      expect(output).toContain('+tags.newTag');
      expect(output).toContain('-tags.oldTag');
      expect(output).toContain('impact:');
    });

    it('should handle requirements with no title', () => {
      const comp: HDFComparison = {
        ...comparison,
        requirementDiffs: [
          {
            ...comparison.requirementDiffs[0]!,
            title: undefined,
          },
        ],
      };
      const output = renderCsv(comp);
      // Should not throw, just have empty title field
      const lines = output.split('\n').filter((l) => l.trim() !== '');
      expect(lines.length).toBe(2); // header + 1 row
    });
  });

  describe('filtering', () => {
    it('should filter rows by state when filterStates is set', () => {
      const output = renderCsv(comparison, { filterStates: ['fixed'] });
      const lines = output.split('\n').filter((l) => l.trim() !== '');
      // Header + only fixed requirements
      const fixedCount = comparison.requirementDiffs.filter(
        (r) => r.state === 'fixed',
      ).length;
      expect(lines.length).toBe(fixedCount + 1);
    });

    it('should filter rows by severity when filterSeverity is set', () => {
      const output = renderCsv(comparison, { filterSeverity: 'high' });
      const lines = output.split('\n').filter((l) => l.trim() !== '');
      // Header + high severity requirements (SV-001, SV-003, SV-004, SV-006)
      expect(lines.length).toBeGreaterThan(1);
      // Should not include medium (SV-002) or low (SV-005) requirements
      expect(output).not.toContain('SV-002');
      expect(output).not.toContain('SV-005');
    });
  });
});
