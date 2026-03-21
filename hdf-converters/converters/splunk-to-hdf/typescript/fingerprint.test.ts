import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, splunkFingerprint } from './fingerprint.js';

const SPLUNK_GOOD = JSON.stringify([
  {
    meta: {
      guid: 'abc-123',
      subtype: 'header',
      hdf_splunk_schema: '1.0',
      filetype: 'evaluation',
      filename: 'scan.json',
    },
    profiles: [],
    platform: { name: 'ubuntu', release: '22.04' },
    statistics: {},
    version: '4.38.9',
  },
  {
    meta: {
      guid: 'abc-123',
      subtype: 'profile',
      hdf_splunk_schema: '1.0',
      filetype: 'evaluation',
      filename: 'scan.json',
      profile_sha256: 'sha256abc',
    },
    name: 'ssh-baseline',
    title: 'SSH Baseline',
    sha256: 'sha256abc',
    version: '1.0',
    supports: [],
    groups: [],
    attributes: [],
    controls: [],
  },
  {
    meta: {
      guid: 'abc-123',
      subtype: 'control',
      hdf_splunk_schema: '1.0',
      filetype: 'evaluation',
      filename: 'scan.json',
      profile_sha256: 'sha256abc',
    },
    id: 'ssh-001',
    title: 'SSH version',
    desc: 'Ensure SSH v2',
    descriptions: {},
    impact: 0.7,
    code: '',
    tags: {},
    results: [
      { status: 'passed', code_desc: 'SSHv2 is enabled', start_time: '2024-01-01T00:00:00Z' },
    ],
    refs: [],
  },
]);

const SPLUNK_MINIMAL = JSON.stringify([
  {
    meta: {
      guid: 'xyz-789',
      subtype: 'header',
      hdf_splunk_schema: '1.0',
      filetype: 'evaluation',
      filename: 'test.json',
    },
  },
]);

const RANDOM_ARRAY = JSON.stringify([{ foo: 'bar' }]);
const RANDOM_JSON = JSON.stringify({ foo: 'bar' });

describe('splunk-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('splunk-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Splunk');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(splunkFingerprint.id).toBe('splunk-to-hdf');
    expect(splunkFingerprint).not.toHaveProperty('convert');
  });

  it('detects Splunk HDF events at confidence 1.0', () => {
    const result = detectConverter(SPLUNK_GOOD);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('splunk-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects minimal Splunk event array at confidence 1.0', () => {
    const result = detectConverter(SPLUNK_MINIMAL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('splunk-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match random array', () => {
    const result = detectConverter(RANDOM_ARRAY);
    expect(result).toBeUndefined();
  });

  it('does not match object JSON', () => {
    const result = detectConverter(RANDOM_JSON);
    expect(result).toBeUndefined();
  });

  it('does not match empty array', () => {
    expect(detectConverter('[]')).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('does not match null input', () => {
    expect(splunkFingerprint.fingerprint(null)).toBe(0);
  });

  it('register is idempotent', () => {
    register();
    expect(getFingerprint('splunk-to-hdf')).toBeDefined();
  });
});
