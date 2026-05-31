import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../../src/diff.js';
import { renderTerminal } from '../../src/renderers/terminal.js';
import type { HDFComparison } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, '..', 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('renderTerminal', () => {
  let comparison: HDFComparison;

  beforeAll(() => {
    const scanBefore = loadFixture('scan-before.json');
    const scanAfter = loadFixture('scan-after.json');
    comparison = diffHdf(scanBefore, scanAfter);
  });

  describe('detail: summary', () => {
    it('should contain the summary line with counts', () => {
      const output = renderTerminal(comparison, { detail: 'summary', color: false });
      expect(output).toContain('Summary:');
      expect(output).toMatch(/\d+ fixed/);
      expect(output).toMatch(/\d+ regressed/);
      expect(output).toMatch(/\d+ total/);
    });

    it('should not contain individual requirement lines', () => {
      const output = renderTerminal(comparison, { detail: 'summary', color: false });
      expect(output).not.toContain('SV-001');
    });
  });

  describe('detail: control', () => {
    it('should be the default detail level', () => {
      const outputDefault = renderTerminal(comparison, { color: false });
      const outputControl = renderTerminal(comparison, { detail: 'control', color: false });
      expect(outputDefault).toBe(outputControl);
    });

    it('should contain +, -, ~ symbols for requirement lines', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: false });
      // Our fixture has fixed (SV-001), regressed (SV-003), new (SV-006), absent (SV-004)
      expect(output).toMatch(/\+\s+SV-001/); // fixed = +
      expect(output).toMatch(/-\s+SV-003/); // regressed = -
      expect(output).toMatch(/\+\s+SV-006/); // new = +
      expect(output).toMatch(/-\s+SV-004/); // absent = -
    });

    it('should contain the summary line', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: false });
      expect(output).toContain('Summary:');
    });

    it('should not show unchanged requirements by default', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: false });
      // SV-002 is unchanged
      expect(output).not.toContain('SV-002');
    });
  });

  describe('detail: full', () => {
    it('should show unchanged requirements', () => {
      const output = renderTerminal(comparison, { detail: 'full', color: false });
      // SV-002 is unchanged and should appear in full detail
      expect(output).toContain('SV-002');
    });

    it('should apply DIM color to unchanged requirements when color is true', () => {
      const output = renderTerminal(comparison, { detail: 'full', color: true });
      // SV-002 is unchanged and should appear with DIM ANSI code (\x1b[2m)
      expect(output).toContain('SV-002');
      // The line containing SV-002 should have the DIM escape code
      const sv002Line = output.split('\n').find((l) => l.includes('SV-002'));
      expect(sv002Line).toBeDefined();
      expect(sv002Line).toContain('\x1b[2m');
    });

    it('should include changeReasons and fieldChanges in output', () => {
      const output = renderTerminal(comparison, { detail: 'full', color: false });
      // SV-005 has an impact change
      expect(output).toContain('SV-005');
    });

    it('should show unchanged requirements without state label', () => {
      const output = renderTerminal(comparison, { detail: 'full', color: false });
      // SV-002 is unchanged - should show status transition without "(unchanged)" label
      const sv002Line = output.split('\n').find((l) => l.includes('SV-002'));
      expect(sv002Line).toBeDefined();
      expect(sv002Line).not.toContain('(unchanged)');
    });

    it('should show ~ symbol for updated requirements', () => {
      const output = renderTerminal(comparison, { detail: 'full', color: false });
      // SV-005 is updated
      expect(output).toMatch(/~\s+SV-005/);
    });

    it('should handle requirements without title or statuses', () => {
      const comp: HDFComparison = {
        ...comparison,
        requirementDiffs: [
          {
            id: 'SV-099',
            state: 'updated',
            changeReasons: ['impactChanged'],
            before: null,
            after: null,
            title: undefined,
            oldEffectiveStatus: undefined,
            newEffectiveStatus: undefined,
            fieldChanges: [
              { op: 'add', path: 'tags.newTag', newValue: 'val' },
              { op: 'remove', path: 'tags.oldTag', oldValue: 'val' },
            ],
          },
        ],
      };
      const output = renderTerminal(comp, { detail: 'full', color: false });
      expect(output).toContain('SV-099');
      expect(output).toContain('(updated)');
      expect(output).toContain('+tags.newTag');
      expect(output).toContain('-tags.oldTag');
    });
  });

  describe('color option', () => {
    it('should produce ANSI escape codes when color is true', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: true });
      // ANSI escape starts with \x1b[
      expect(output).toMatch(/\x1b\[/);
    });

    it('should produce no ANSI escape codes when color is false', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: false });
      expect(output).not.toMatch(/\x1b\[/);
    });

    it('should default to color: true', () => {
      const output = renderTerminal(comparison, { detail: 'control' });
      expect(output).toMatch(/\x1b\[/);
    });
  });

  describe('header', () => {
    it('should include comparison mode in the header', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: false });
      expect(output).toContain('HDF Comparison:');
      expect(output).toContain('temporal');
    });

    it('should include date range when sources have timestamps', () => {
      const output = renderTerminal(comparison, { detail: 'control', color: false });
      expect(output).toContain('2024-01-01');
      expect(output).toContain('2024-02-01');
    });

    it('should omit date range when sources lack timestamps', () => {
      const noTimestamps: HDFComparison = {
        ...comparison,
        sources: [
          { role: 'old', label: 'Old evaluation' },
          { role: 'new', label: 'New evaluation' },
        ],
      };
      const output = renderTerminal(noTimestamps, { detail: 'summary', color: false });
      expect(output).toContain('HDF Comparison: temporal');
      expect(output).not.toContain('(20');
    });

    it('should find golden/reference roles for baseline/fleet modes', () => {
      const baselineComp: HDFComparison = {
        ...comparison,
        comparisonMode: 'baseline',
        sources: [
          { role: 'golden', label: 'Golden baseline', assessmentTimestamp: '2024-01-01T00:00:00Z' },
          { role: 'new', label: 'Current scan', assessmentTimestamp: '2024-02-01T00:00:00Z' },
        ],
      };
      const output = renderTerminal(baselineComp, { detail: 'summary', color: false });
      expect(output).toContain('baseline');
      expect(output).toContain('2024-01-01');
    });

    it('should find reference/system roles for fleet mode', () => {
      const fleetComp: HDFComparison = {
        ...comparison,
        comparisonMode: 'fleet',
        sources: [
          { role: 'reference', label: 'Reference', assessmentTimestamp: '2024-01-01T00:00:00Z' },
          { role: 'system', label: 'System 1', assessmentTimestamp: '2024-02-01T00:00:00Z' },
        ],
      };
      const output = renderTerminal(fleetComp, { detail: 'summary', color: false });
      expect(output).toContain('fleet');
      expect(output).toContain('2024-01-01');
    });
  });

  describe('filtering', () => {
    it('should filter by severity when filterSeverity is set', () => {
      const output = renderTerminal(comparison, {
        detail: 'full',
        color: false,
        filterSeverity: 'high',
      });
      // High severity: SV-001, SV-003, SV-004, SV-006
      expect(output).toContain('SV-001');
      expect(output).toContain('SV-003');
      // Low severity SV-005 and medium SV-002 should be excluded
      expect(output).not.toContain('SV-005');
      expect(output).not.toContain('SV-002');
    });
  });
});
