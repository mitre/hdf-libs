import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../src/diff.js';
import { validateComparison } from '../src/validate.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('validateComparison', () => {
  let scanBefore: Record<string, unknown>;
  let scanAfter: Record<string, unknown>;

  beforeAll(() => {
    scanBefore = loadFixture('scan-before.json');
    scanAfter = loadFixture('scan-after.json');
  });

  // ── Valid output validates ────────────────────────────────────────
  describe('valid output validates', () => {
    it('should validate output from diffHdf(scanBefore, scanAfter)', () => {
      const comparison = diffHdf(scanBefore, scanAfter);
      const result = validateComparison(comparison);
      if (!result.valid) {
        // Log errors for debugging
        console.error('Validation errors:', result.errors);
      }
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('should validate output from diffHdf(scanBefore, scanBefore) — identical', () => {
      const comparison = diffHdf(scanBefore, scanBefore);
      const result = validateComparison(comparison);
      if (!result.valid) {
        console.error('Validation errors:', result.errors);
      }
      expect(result.valid).toBe(true);
    });
  });

  // ── Fleet mode output validates ──────────────────────────────────
  describe('fleet mode output validates', () => {
    it('should validate fleet mode comparison output', () => {
      const comparison = diffHdf(scanBefore, [scanAfter, scanBefore], {
        comparisonMode: 'fleet',
      });
      const result = validateComparison(comparison);
      if (!result.valid) {
        console.error('Validation errors:', result.errors);
      }
      expect(result.valid).toBe(true);
    });
  });

  // ── Invalid documents rejected ───────────────────────────────────
  describe('invalid document rejection', () => {
    it('should reject a completely invalid document', () => {
      const result = validateComparison({ foo: 'bar' });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
    });

    it('should reject a document missing required fields', () => {
      const result = validateComparison({ formatVersion: '1.0.0' });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
    });

    it('should reject a document with wrong formatVersion', () => {
      const comparison = diffHdf(scanBefore, scanAfter) as Record<string, unknown>;
      const modified = { ...comparison, formatVersion: '2.0.0' };
      const result = validateComparison(modified);
      expect(result.valid).toBe(false);
    });
  });

  // ── Nginx v1 comparison validates ────────────────────────────────
  describe('nginx v1 fixture comparison validates', () => {
    it('should validate nginx (failing -> clean) comparison', () => {
      const nginxFailing = loadFixture('nginx-failing.json');
      const nginxClean = loadFixture('nginx-clean.json');
      const comparison = diffHdf(nginxFailing, nginxClean);
      const result = validateComparison(comparison);
      if (!result.valid) {
        console.error('Validation errors (first 5):', result.errors?.slice(0, 5));
      }
      expect(result.valid).toBe(true);
    });
  });

  // ── Ubuntu comparison validates ──────────────────────────────────
  describe('ubuntu fixture comparison validates', () => {
    it('should validate ubuntu (vanilla -> hardened) comparison', () => {
      const vanilla = loadFixture('ubuntu-22-vanilla.json');
      const hardened = loadFixture('ubuntu-22-hardened.json');
      const comparison = diffHdf(vanilla, hardened);
      const result = validateComparison(comparison);
      if (!result.valid) {
        console.error('Validation errors (first 5):', result.errors?.slice(0, 5));
      }
      expect(result.valid).toBe(true);
    });
  });

  // ── diffHdf with validateOutput option ───────────────────────────
  describe('diffHdf with validateOutput option', () => {
    it('should not throw when validateOutput is true and output is valid', () => {
      expect(() =>
        diffHdf(scanBefore, scanAfter, { validateOutput: true }),
      ).not.toThrow();
    });

    it('should return a valid HDFComparison when validateOutput is true', () => {
      const comparison = diffHdf(scanBefore, scanAfter, { validateOutput: true });
      expect(comparison.formatVersion).toBe('1.0.0');
      expect(comparison.requirementDiffs.length).toBeGreaterThan(0);
    });
  });
});
