import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, grypeFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'grype-to-hdf',
  label: 'Grype',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: grypeFingerprint,
  register,
  positive: [
    {
      name: 'detects full Grype report at confidence 1.0',
      input: JSON.stringify({
        matches: [
          {
            vulnerability: { id: 'CVE-2021-44228', severity: 'Critical', description: 'Log4Shell' },
            matchDetails: [{ type: 'exact-direct-match', matcher: 'java-matcher' }],
            artifact: { name: 'log4j-core', version: '2.14.1', type: 'java-archive' },
          },
        ],
        source: { target: { userInput: 'docker:myimage:latest' } },
        descriptor: { name: 'grype', version: '0.62.0' },
      }),
      confidence: 1.0,
    },
    {
      name: 'detects Grype with descriptor.name at confidence 0.8',
      input: JSON.stringify({
        matches: [],
        descriptor: { name: 'grype', version: '0.60.0' },
      }),
      confidence: 0.8,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match GoSec JSON', input: JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } }), confidence: 0 },
  ],
});
