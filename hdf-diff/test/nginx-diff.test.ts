import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../src/diff.js';
import { isV1Format } from '../src/normalize.js';
import type { HdfComparison } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('nginx diff (v1 format, real fixtures)', () => {
  let nginxClean: Record<string, unknown>;
  let nginxFailing: Record<string, unknown>;
  let diff: HdfComparison;

  beforeAll(() => {
    nginxClean = loadFixture('nginx-clean.json');
    nginxFailing = loadFixture('nginx-failing.json');
    diff = diffHdf(nginxFailing, nginxClean);
  });

  it('should detect v1 format for both fixtures', () => {
    expect(isV1Format(nginxClean)).toBe(true);
    expect(isV1Format(nginxFailing)).toBe(true);
  });

  it('should produce a non-empty diff', () => {
    expect(diff.requirementDiffs.length).toBeGreaterThan(0);
    expect(diff.summary.total).toBeGreaterThan(0);
  });

  it('should detect fixed requirements (failing → clean)', () => {
    // The clean scan should have more passing controls
    expect(diff.summary.fixed).toBeGreaterThan(0);
  });

  it('should match baselines by profile name', () => {
    expect(diff.baselineDiffs.length).toBeGreaterThan(0);
    // Both fixtures are from the same baseline
    const baseline = diff.baselineDiffs[0]!;
    expect(baseline.name).toBeDefined();
  });

  it('should have requirements matched by control id', () => {
    // All controls should be present in both (same baseline)
    const newOrAbsent = diff.requirementDiffs.filter(
      (r) => r.state === 'new' || r.state === 'absent',
    );
    // Same baseline, so nothing should be new or absent
    expect(newOrAbsent.length).toBe(0);
  });

  it('should report total matching the number of controls', () => {
    // nginx baseline has 41 controls
    expect(diff.summary.total).toBe(41);
  });

  it('should show fixed + regressed + unchanged + updated = total', () => {
    const { fixed, regressed, unchanged, updated, absent, total } = diff.summary;
    const newCount = diff.summary.new;
    expect(fixed + regressed + unchanged + updated + newCount + absent).toBe(total);
  });

  it('should have no regressions when diffing failing → clean', () => {
    // Going from failing to clean: nothing should regress
    expect(diff.summary.regressed).toBe(0);
  });

  it('should have resultChanged in changeReasons for fixed requirements', () => {
    const fixedReqs = diff.requirementDiffs.filter((r) => r.state === 'fixed');
    for (const req of fixedReqs) {
      expect(req.changeReasons).toContain('resultChanged');
    }
  });

  it('should have formatVersion and comparisonMode set', () => {
    expect(diff.formatVersion).toBe('1.0.0');
    expect(diff.comparisonMode).toBe('temporal');
  });

  it('should include before/after snapshots for all matched requirements', () => {
    const matched = diff.requirementDiffs.filter(
      (r) => r.state !== 'new' && r.state !== 'absent',
    );
    for (const req of matched) {
      expect(req.before).not.toBeNull();
      expect(req.after).not.toBeNull();
    }
  });
});
