import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../src/diff.js';
import { isV1Format } from '../src/normalize.js';
import type { HDFComparison } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('Ubuntu 22.04 STIG diff (v1 format, real fixtures)', () => {
  let vanilla: Record<string, unknown>;
  let hardened: Record<string, unknown>;
  let diff: HDFComparison;

  beforeAll(() => {
    vanilla = loadFixture('ubuntu-22-vanilla.json');
    hardened = loadFixture('ubuntu-22-hardened.json');
    // Diff direction: vanilla (before) -> hardened (after)
    // Hardening should produce fixes, not regressions.
    diff = diffHdf(vanilla, hardened);
  });

  it('should detect v1 format for both fixtures', () => {
    expect(isV1Format(vanilla)).toBe(true);
    expect(isV1Format(hardened)).toBe(true);
  });

  it('should produce a non-empty diff', () => {
    expect(diff.requirementDiffs.length).toBeGreaterThan(0);
    expect(diff.summary.total).toBeGreaterThan(0);
  });

  it('should have total of 192 (same controls in both scans)', () => {
    expect(diff.summary.total).toBe(192);
  });

  it('should detect fixed requirements (vanilla -> hardened = fixes applied)', () => {
    expect(diff.summary.fixed).toBeGreaterThan(0);
  });

  it('should have no added or removed requirements (same baseline)', () => {
    expect(diff.summary.new).toBe(0);
    expect(diff.summary.absent).toBe(0);
  });

  it('should satisfy fixed + regressed + unchanged + updated = total', () => {
    const { fixed, regressed, unchanged, updated, absent, total } = diff.summary;
    const newCount = diff.summary.new;
    expect(fixed + regressed + unchanged + updated + newCount + absent).toBe(total);
  });

  it('should have minimal regressions (hardening may cause side-effects)', () => {
    // Real-world hardening can cause a small number of regressions.
    // In this fixture, 2 controls regress (SV-260500, SV-260601) — they
    // passed on vanilla but fail after hardening, likely due to stricter
    // configuration breaking their own checks.
    expect(diff.summary.regressed).toBe(2);
  });

  it('should include before/after snapshots for all matched requirements', () => {
    const matched = diff.requirementDiffs.filter(
      (r) => r.state !== 'new' && r.state !== 'absent',
    );
    expect(matched.length).toBeGreaterThan(0);
    for (const req of matched) {
      expect(req.before).not.toBeNull();
      expect(req.after).not.toBeNull();
    }
  });

  it('should have formatVersion and comparisonMode set correctly', () => {
    expect(diff.formatVersion).toBe('1.0.0');
    expect(diff.comparisonMode).toBe('temporal');
  });

  it('should include resultChanged in changeReasons for fixed requirements', () => {
    const fixedReqs = diff.requirementDiffs.filter((r) => r.state === 'fixed');
    expect(fixedReqs.length).toBeGreaterThan(0);
    for (const req of fixedReqs) {
      expect(req.changeReasons).toContain('resultChanged');
    }
  });
});
