import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register as registerMsdo, msftDefenderDevopsFingerprint } from './fingerprint.js';
import { register as registerSarif } from '../../sarif-to-hdf/typescript/fingerprint.js';

const MSDO_SARIF = JSON.stringify({
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'Microsoft Security DevOps',
          organization: 'Microsoft',
        },
      },
      results: [],
    },
  ],
});

const MSDO_SARIF_DEVOPS_NAME = JSON.stringify({
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'Azure DevOps Scanner',
        },
      },
      results: [],
    },
  ],
});

const GENERIC_SARIF = JSON.stringify({
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: { name: 'eslint' },
      },
      results: [],
    },
  ],
});

const RANDOM_JSON = JSON.stringify({ foo: 'bar' });

describe('msft-defender-devops-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    registerMsdo();
    registerSarif();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('msft-defender-devops-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Microsoft Defender for DevOps');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(msftDefenderDevopsFingerprint.id).toBe('msft-defender-devops-to-hdf');
    expect(msftDefenderDevopsFingerprint).not.toHaveProperty('convert');
  });

  it('detects MSDO SARIF at confidence 0.95', () => {
    const result = detectConverter(MSDO_SARIF);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-devops-to-hdf');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects SARIF with DevOps in driver name', () => {
    const result = detectConverter(MSDO_SARIF_DEVOPS_NAME);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-devops-to-hdf');
    expect(result!.confidence).toBe(0.95);
  });

  it('outranks generic SARIF fingerprint', () => {
    const result = detectConverter(MSDO_SARIF);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('msft-defender-devops-to-hdf');
    // Generic SARIF would return 0.9, MSDO returns 0.95
    expect(result!.confidence).toBeGreaterThan(0.9);
  });

  it('does not match generic SARIF (returns 0, falls through to sarif fingerprint)', () => {
    const result = detectConverter(GENERIC_SARIF);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('does not match random JSON', () => {
    const result = detectConverter(RANDOM_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match null input', () => {
    expect(msftDefenderDevopsFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    registerMsdo();
    expect(getFingerprint('msft-defender-devops-to-hdf')).toBeDefined();
  });
});
