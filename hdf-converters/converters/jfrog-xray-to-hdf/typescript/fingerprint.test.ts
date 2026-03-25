import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, jfrogXrayFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'jfrog-xray-to-hdf',
  label: 'JFrog Xray',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: jfrogXrayFingerprint,
  register,
  positive: [
    {
      name: 'detects JFrog Xray JSON at confidence 1.0',
      input: JSON.stringify({
        total_count: 2,
        data: [
          { id: 'XRAY-001', severity: 'High', summary: 'CVE-2023-1234' },
          { id: 'XRAY-002', severity: 'Medium', summary: 'CVE-2023-5678' },
        ],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects empty data array at confidence 1.0',
      input: JSON.stringify({ total_count: 0, data: [] }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar', baz: 42 }), confidence: 0 },
  ],
});
