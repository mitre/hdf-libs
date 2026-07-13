import { describe, it, expect } from 'vitest';
import { asffFingerprint, register } from './fingerprint.js';
import { getFingerprint } from '../../../shared/typescript/registry.js';

const fp = asffFingerprint.fingerprint;

describe('asff fingerprint', () => {
  it('has the expected registry metadata', () => {
    expect(asffFingerprint.id).toBe('asff-to-hdf');
    expect(asffFingerprint.outputType).toBe('results');
    expect(asffFingerprint.inputFamily).toBe('json');
  });

  it('detects a Findings envelope with a ProductArn/GeneratorId finding', () => {
    expect(fp({ Findings: [{ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub', GeneratorId: 'r/1.1' }] })).toBe(0.95);
  });

  it('detects a bare array of findings', () => {
    expect(fp([{ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/guardduty', Types: ['TTPs'] }])).toBe(0.95);
  });

  it('detects a single finding object', () => {
    expect(fp({ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub', Resources: [] })).toBe(0.95);
  });

  it('scores ProductArn alone at lower confidence', () => {
    expect(fp({ ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub' })).toBe(0.8);
  });

  it('register() is idempotent and registers the fingerprint', () => {
    register();
    register();
    expect(getFingerprint('asff-to-hdf')).toBeDefined();
  });

  it('rejects non-ASFF and malformed inputs', () => {
    expect(fp({ Findings: [] })).toBe(0);
    expect(fp([])).toBe(0);
    expect(fp({ Id: 'x', Title: 'y' })).toBe(0);
    expect(fp('plain text')).toBe(0);
    expect(fp(null)).toBe(0);
    expect(fp({ Findings: ['not-an-object'] })).toBe(0);
    expect(fp(['not-an-object'])).toBe(0);
    expect(fp({ version: '2.1.0', runs: [] })).toBe(0);
  });
});
