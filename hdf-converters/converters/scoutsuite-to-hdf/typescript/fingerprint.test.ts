import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, scoutsuiteFingerprint, scoutsuiteJsFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'scoutsuite-to-hdf-js',
  label: 'ScoutSuite',
  direction: 'ingest',
  inputFamily: 'text',
  outputType: 'results',
  fingerprint: scoutsuiteJsFingerprint,
  register,
  positive: [
    { name: 'detects scoutsuite_results = { prefix', input: 'scoutsuite_results = {"services":{}}', confidence: 1.0 },
    { name: 'tolerates leading whitespace', input: '  scoutsuite_results = {"services":{}}', confidence: 1.0 },
    { name: 'case-insensitive', input: 'SCOUTSUITE_RESULTS = {"services":{}}', confidence: 1.0 },
  ],
  negative: [
    { name: 'does not match arbitrary text', input: 'some other content', confidence: 0 },
    { name: 'does not match scoutsuite_results mid-document', input: '// comment about scoutsuite_results\n{}', confidence: 0 },
  ],
});

runFingerprintTests({
  id: 'scoutsuite-to-hdf',
  label: 'ScoutSuite',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: scoutsuiteFingerprint,
  register,
  positive: [
    {
      name: 'detects ScoutSuite JSON at confidence 1.0',
      input: JSON.stringify({
        account_id: '123456789012',
        last_run: {
          ruleset_name: 'default',
          time: '2024-01-01T00:00:00Z',
          version: '5.13.0',
        },
        provider_name: 'aws',
        services: {
          iam: {
            findings: {
              'iam-no-support-role': {
                checked_items: 1,
                flagged_items: 1,
                description: 'No support role',
                items: [],
                level: 'danger',
                rationale: 'Create a support role',
              },
            },
          },
        },
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match when services is an array', input: JSON.stringify({ services: ['iam'], last_run: { time: '2024-01-01' } }), confidence: 0 },
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
