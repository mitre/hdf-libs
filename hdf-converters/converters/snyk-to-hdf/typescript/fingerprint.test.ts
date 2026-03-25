import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, snykFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'snyk-to-hdf',
  label: 'Snyk',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: snykFingerprint,
  register,
  positive: [
    {
      name: 'detects Snyk JSON with packageManager at confidence 1.0',
      input: JSON.stringify({
        ok: false,
        vulnerabilities: [
          {
            id: 'SNYK-JS-LODASH-590103',
            title: 'Prototype Pollution',
            description: 'desc',
            severity: 'high',
            identifiers: { CVE: ['CVE-2020-8203'], CWE: ['CWE-400'] },
            from: ['app@1.0.0', 'lodash@4.17.15'],
          },
        ],
        packageManager: 'npm',
        projectName: 'my-app',
      }),
      confidence: 1.0,
    },
    {
      name: 'detects Snyk JSON with empty vulnerabilities and packageManager at confidence 1.0',
      input: JSON.stringify({ ok: true, vulnerabilities: [], packageManager: 'pip' }),
      confidence: 1.0,
    },
    {
      name: 'detects Snyk JSON without packageManager at confidence 0.5',
      input: JSON.stringify({
        ok: false,
        vulnerabilities: [
          { id: 'SNYK-001', title: 'test', description: '', severity: 'low', identifiers: {}, from: [] },
        ],
      }),
      confidence: 0.5,
    },
    {
      name: 'detects multi-project Snyk array at confidence 1.0',
      input: JSON.stringify([
        {
          ok: false,
          vulnerabilities: [
            { id: 'SNYK-001', title: 'test', description: '', severity: 'low', identifiers: {}, from: [] },
          ],
          packageManager: 'maven',
        },
      ]),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
