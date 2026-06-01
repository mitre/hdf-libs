/**
 * Tests that the Identity type is consistent across all HDF document types.
 * Bug: quicktype generates independent Identity interfaces per-file with
 * different enum names for the `type` field (OperatorType vs Type).
 * Fix: combined generation produces ONE Identity with ONE type enum.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST_TS_DIR = join(__dirname, '..', 'dist', 'ts');

describe('Identity type deduplication', () => {
  it('combined hdf.ts exists with a single Identity interface', () => {
    const combinedPath = join(DIST_TS_DIR, 'hdf.ts');
    expect(existsSync(combinedPath), 'dist/ts/hdf.ts should exist').toBe(true);

    const code = readFileSync(combinedPath, 'utf-8');
    const identityMatches = code.match(/export interface Identity\b/g) ?? [];
    expect(identityMatches.length).toBe(1);
  });

  it('combined hdf.ts has exactly one type enum for Identity.type', () => {
    const combinedPath = join(DIST_TS_DIR, 'hdf.ts');
    const code = readFileSync(combinedPath, 'utf-8');

    // Find the Identity interface and its type field
    const identityBlock = code.slice(
      code.indexOf('export interface Identity'),
      code.indexOf('}', code.indexOf('export interface Identity')) + 1
    );

    // The type field should reference a single enum (not OperatorType AND Type)
    const typeFieldMatch = identityBlock.match(/type:\s*(\w+)/);
    expect(typeFieldMatch).not.toBeNull();

    const enumName = typeFieldMatch![1]!;
    // The enum for Identity.type should appear exactly once (no duplicates)
    const enumRegex = new RegExp(`export enum ${enumName}`, 'g');
    const enumCount = (code.match(enumRegex) ?? []).length;
    expect(enumCount).toBe(1);
  });

  it('root type names use HDFResults (acronym from schema title), not HdfResults', () => {
    const combinedPath = join(DIST_TS_DIR, 'hdf.ts');
    if (!existsSync(combinedPath)) return;

    const code = readFileSync(combinedPath, 'utf-8');

    // Schema titles are "HDF Results", "HDF Baseline", etc. — quicktype produces HDFResults
    expect(code).toContain('export interface HDFResults');
    expect(code).toContain('export interface HDFBaseline');
    expect(code).toContain('export interface HDFSystem');
    expect(code).toContain('export interface HDFPlan');
    expect(code).toContain('export interface HDFAmendments');

    // Must NOT contain the old incorrect PascalCase naming
    expect(code).not.toContain('export interface HdfResults');
    expect(code).not.toContain('export interface HdfBaseline');
  });

  it('per-file outputs removed (combined only)', () => {
    const resultsPath = join(DIST_TS_DIR, 'hdf-results.ts');
    // Per-file outputs no longer exist — combined hdf.ts is the only output
    expect(existsSync(resultsPath)).toBe(false);
  });

  it('barrel index.d.ts exports Identity with a single type enum', () => {
    const indexPath = join(__dirname, '..', 'dist', 'index.d.ts');
    if (!existsSync(indexPath)) return;

    const code = readFileSync(indexPath, 'utf-8');
    // The barrel should export from combined hdf.js (not per-file hdf-results.js)
    expect(code).toContain('./ts/hdf.js');
    // Identity should not appear in multiple conflicting re-export paths
    const identityExports = (code.match(/\bIdentity\b/g) ?? []).length;
    expect(identityExports).toBeLessThanOrEqual(2);
  });
});
