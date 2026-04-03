import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, cyclonedxFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'cyclonedx-to-hdf',
  label: 'CycloneDX',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: cyclonedxFingerprint,
  register,
  positive: [
    {
      name: 'detects CycloneDX BOM at confidence 1.0',
      input: JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        metadata: { timestamp: '2024-01-01T00:00:00Z' },
        components: [{ type: 'library', name: 'lodash', version: '4.17.21' }],
        vulnerabilities: [],
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match Grype JSON', input: JSON.stringify({ matches: [], source: { target: { userInput: 'alpine:3.14' } }, descriptor: { name: 'grype', version: '0.62.0' } }), confidence: 0 },
  ],
});
