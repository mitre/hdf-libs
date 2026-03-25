import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, awsConfigFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'aws-config-to-hdf',
  label: 'AWS Config',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: awsConfigFingerprint,
  register,
  positive: [
    {
      name: 'detects full AWS Config export at confidence 1.0',
      input: JSON.stringify({
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
      }),
      confidence: 1.0,
    },
    {
      name: 'detects single config rule at confidence 0.7',
      input: JSON.stringify({
        ConfigRuleName: 's3-bucket-versioning-enabled',
        ConfigRuleId: 'config-rule-abc123',
      }),
      confidence: 0.7,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
  ],
});
