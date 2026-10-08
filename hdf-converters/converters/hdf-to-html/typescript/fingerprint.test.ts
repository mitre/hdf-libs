import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { register, hdfToHtmlFingerprint } from './fingerprint.js';

describe('hdf-to-html fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('hdf-to-html');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('HDF to HTML');
    expect(fp!.direction).toBe('export');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('raw');
  });

  it('registers once', () => {
    register();
    expect(getFingerprint('hdf-to-html')?.id).toBe(hdfToHtmlFingerprint.id);
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(hdfToHtmlFingerprint.id).toBe('hdf-to-html');
    expect(hdfToHtmlFingerprint).not.toHaveProperty('convert');
  });

  it('detects an HDF results shape at confidence 0.5', () => {
    expect(hdfToHtmlFingerprint.fingerprint({ baselines: [{ name: 'test' }] })).toBe(0.5);
    expect(hdfToHtmlFingerprint.fingerprint({ baselines: [] })).toBe(0.5);
  });

  it('returns 0 for anything else', () => {
    expect(hdfToHtmlFingerprint.fingerprint({ baselines: 'not-an-array' })).toBe(0);
    expect(hdfToHtmlFingerprint.fingerprint({ version: '2.1.0', runs: [] })).toBe(0);
    expect(hdfToHtmlFingerprint.fingerprint('hello world')).toBe(0);
    expect(hdfToHtmlFingerprint.fingerprint(null)).toBe(0);
  });
});
