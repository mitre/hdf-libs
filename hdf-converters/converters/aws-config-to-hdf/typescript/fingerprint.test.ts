import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter, detectConverterAll } from '../../../shared/typescript/fingerprint.js';
import { register, awsConfigFingerprint } from './fingerprint.js';

// Known-good AWS Config fixture: ConfigRules array
const AWS_CONFIG_FULL = JSON.stringify({
  ConfigRules: [
    {
      ConfigRuleId: 'config-rule-abc123',
      ConfigRuleName: 's3-bucket-versioning-enabled',
      ConfigRuleArn: 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc123',
      Description: 'Checks whether S3 bucket versioning is enabled.',
      Source: { Owner: 'AWS', SourceIdentifier: 'S3_BUCKET_VERSIONING_ENABLED' },
      InputParameters: '{}',
      EvaluationResults: [],
    },
  ],
});

// Individual config rule object (secondary shape)
const AWS_CONFIG_SINGLE_RULE = JSON.stringify({
  ConfigRuleName: 's3-bucket-versioning-enabled',
  ConfigRuleId: 'config-rule-abc123',
});

// Known-bad: SARIF format
const SARIF_JSON = JSON.stringify({ version: '2.1.0', runs: [] });

describe('aws-config-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('aws-config-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('AWS Config');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(awsConfigFingerprint.id).toBe('aws-config-to-hdf');
    expect(awsConfigFingerprint).not.toHaveProperty('convert');
  });

  it('detects full AWS Config export at confidence 1.0', () => {
    const result = detectConverter(AWS_CONFIG_FULL);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('aws-config-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects single config rule at confidence 0.7', () => {
    const result = detectConverterAll(AWS_CONFIG_SINGLE_RULE)[0];
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('aws-config-to-hdf');
    expect(result!.confidence).toBe(0.7);
  });

  it('does not match SARIF JSON', () => {
    const result = detectConverter(SARIF_JSON);
    expect(result).toBeUndefined();
  });

  it('returns 0 for empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });

  it('returns 0 for null input', () => {
    expect(awsConfigFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for non-object input', () => {
    expect(awsConfigFingerprint.fingerprint('string')).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('aws-config-to-hdf')).toBeDefined();
  });
});
