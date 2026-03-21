import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, conveyorFingerprint } from './fingerprint.js';

// Known-good Conveyor fixture: api_response with results
const CONVEYOR_FULL = JSON.stringify({
  api_error_message: '',
  api_server_version: '4.0.0',
  api_response: {
    file_tree: {},
    results: {
      sha256abc: {
        sha256: 'sha256abc',
        response: { service_name: 'Clamav' },
        result: { score: 0, sections: [] },
      },
    },
    params: { description: 'test scan' },
  },
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

// Known-bad: AWS Config format
const AWS_CONFIG_JSON = JSON.stringify({ ConfigRules: [] });

describe('conveyor-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('conveyor-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Conveyor');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(conveyorFingerprint.id).toBe('conveyor-to-hdf');
    expect(conveyorFingerprint).not.toHaveProperty('convert');
  });

  it('detects full Conveyor export at confidence 1.0', () => {
    const result = detectConverter(CONVEYOR_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('conveyor-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match AWS Config JSON', () => {
    const result = detectConverter(AWS_CONFIG_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(conveyorFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(conveyorFingerprint.fingerprint('string')).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('conveyor-to-hdf')).toBeDefined();
  });
});
