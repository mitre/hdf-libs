import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, checkovFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'checkov-to-hdf',
  label: 'Checkov',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: checkovFingerprint,
  register,
  positive: [
    {
      name: 'detects single-object Checkov with summary.checkov_version at 1.0',
      input: JSON.stringify({
        check_type: 'terraform',
        results: { passed_checks: [], failed_checks: [{ check_id: 'CKV_AWS_1' }] },
        summary: { checkov_version: '2.5.0', passed: 0, failed: 1 },
      }),
      confidence: 1.0,
    },
    {
      name: 'detects single-object Checkov without checkov_version at 0.8',
      input: JSON.stringify({
        check_type: 'terraform',
        results: { passed_checks: [{ check_id: 'CKV_AWS_2' }], failed_checks: [] },
      }),
      confidence: 0.8,
    },
    {
      name: 'detects array-form Checkov by inspecting first element',
      input: JSON.stringify([
        {
          check_type: 'kubernetes',
          results: { passed_checks: [], failed_checks: [] },
          summary: { checkov_version: '2.5.0' },
        },
      ]),
      confidence: 1.0,
    },
    {
      name: 'detects single-object with results.passed_checks only',
      input: JSON.stringify({
        check_type: 'terraform',
        results: { passed_checks: [{ check_id: 'CKV_X' }] },
      }),
      confidence: 0.8,
    },
  ],
  negative: [
    {
      name: 'does not match SARIF JSON',
      input: JSON.stringify({ version: '2.1.0', runs: [] }),
      confidence: 0,
    },
    {
      name: 'does not match object missing check_type',
      input: JSON.stringify({ results: { passed_checks: [], failed_checks: [] } }),
      confidence: 0,
    },
    {
      name: 'does not match when check_type is not a string',
      input: JSON.stringify({ check_type: 42, results: { passed_checks: [] } }),
      confidence: 0,
    },
    {
      name: 'does not match when results is missing',
      input: JSON.stringify({ check_type: 'terraform' }),
      confidence: 0,
    },
    {
      name: 'does not match when results lacks check arrays',
      input: JSON.stringify({ check_type: 'terraform', results: { other: 'stuff' } }),
      confidence: 0,
    },
    {
      name: 'does not match empty array',
      input: JSON.stringify([]),
      confidence: 0,
    },
    {
      name: 'does not match array whose first element is null',
      input: JSON.stringify([null]),
      confidence: 0,
    },
    {
      name: 'does not match top-level null',
      input: 'null',
      confidence: 0,
    },
  ],
});
