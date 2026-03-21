/**
 * SARIF confidence tier verification.
 *
 * Validates that tool-specific SARIF wrappers (e.g. MSDO) rank higher
 * than generic SARIF detection, and that plain SARIF without tool-specific
 * properties falls back to the generic SARIF match.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  registerFingerprint,
  _resetRegistry,
  type ConverterFingerprint,
} from './registry.js';
import { detectConverter, detectConverterAll } from './fingerprint.js';

/** Generic SARIF fingerprint at confidence 0.9 (matches the real one) */
const sarifFP: ConverterFingerprint = {
  id: 'sarif-to-hdf',
  label: 'SARIF',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (typeof obj.version === 'string' && Array.isArray(obj.runs)) return 0.9;
    return 0;
  },
};

/**
 * Mock MSDO (Microsoft Defender for DevOps) fingerprint at confidence 0.95.
 * MSDO outputs SARIF with a specific tool driver name.
 */
const msdoFP: ConverterFingerprint = {
  id: 'msdo-sarif-to-hdf',
  label: 'MSDO SARIF',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (typeof obj.version !== 'string' || !Array.isArray(obj.runs)) return 0;
    // Check for MSDO-specific tool driver
    const runs = obj.runs as Array<Record<string, unknown>>;
    for (const run of runs) {
      const tool = run.tool as Record<string, unknown> | undefined;
      if (!tool) continue;
      const driver = tool.driver as Record<string, unknown> | undefined;
      if (!driver) continue;
      if (typeof driver.name === 'string' && driver.name.includes('Microsoft')) {
        return 0.95;
      }
    }
    return 0;
  },
};

/** SARIF with MSDO-specific tool driver */
const MSDO_SARIF = JSON.stringify({
  version: '2.1.0',
  runs: [
    {
      tool: { driver: { name: 'Microsoft Security DevOps' } },
      results: [{ ruleId: 'SEC-001', message: { text: 'Finding' } }],
    },
  ],
});

/** Plain SARIF with a non-MSDO tool */
const PLAIN_SARIF = JSON.stringify({
  version: '2.1.0',
  runs: [
    {
      tool: { driver: { name: 'eslint' } },
      results: [{ ruleId: 'no-unused-vars', message: { text: 'Unused var' } }],
    },
  ],
});

/** Non-SARIF JSON */
const NON_SARIF = JSON.stringify({ GosecVersion: '2.18.2', Issues: [] });

describe('SARIF confidence tiers', () => {
  beforeEach(() => {
    _resetRegistry();
    registerFingerprint(sarifFP);
    registerFingerprint(msdoFP);
  });

  it('MSDO-specific SARIF ranks higher than generic SARIF', () => {
    const result = detectConverter(MSDO_SARIF);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msdo-sarif-to-hdf');
    expect(result!.confidence).toBe(0.95);
  });

  it('MSDO SARIF also matches generic SARIF at lower confidence', () => {
    const all = detectConverterAll(MSDO_SARIF);
    expect(all.length).toBe(2);
    // Sorted by confidence descending
    expect(all[0].fingerprint.id).toBe('msdo-sarif-to-hdf');
    expect(all[0].confidence).toBe(0.95);
    expect(all[1].fingerprint.id).toBe('sarif-to-hdf');
    expect(all[1].confidence).toBe(0.9);
  });

  it('plain SARIF (no MSDO properties) returns generic SARIF match', () => {
    const result = detectConverter(PLAIN_SARIF);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('plain SARIF does not match MSDO fingerprint', () => {
    const all = detectConverterAll(PLAIN_SARIF);
    expect(all.length).toBe(1);
    expect(all[0].fingerprint.id).toBe('sarif-to-hdf');
  });

  it('non-SARIF input matches neither', () => {
    const result = detectConverter(NON_SARIF);
    expect(result).toBeUndefined();
  });

  it('confidence ordering is deterministic across multiple calls', () => {
    // Run detection multiple times to ensure stable ordering
    for (let i = 0; i < 5; i++) {
      const all = detectConverterAll(MSDO_SARIF);
      expect(all[0].fingerprint.id).toBe('msdo-sarif-to-hdf');
      expect(all[1].fingerprint.id).toBe('sarif-to-hdf');
    }
  });
});
