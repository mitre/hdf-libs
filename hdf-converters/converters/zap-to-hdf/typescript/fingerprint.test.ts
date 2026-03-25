import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, zapFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'zap-to-hdf',
  label: 'OWASP ZAP',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: zapFingerprint,
  register,
  positive: [
    {
      name: 'detects full ZAP JSON at confidence 0.95',
      input: JSON.stringify({
        '@generated': '2024-01-01T00:00:00Z',
        '@version': '2.14.0',
        site: [{ '@host': 'example.com', alerts: [] }],
      }),
      confidence: 0.95,
    },
    {
      name: 'detects minimal ZAP JSON at confidence 0.85',
      input: JSON.stringify({ site: [{ '@host': 'example.com' }] }),
      confidence: 0.85,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><root><child/></root>', confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
    { name: 'does not match object with non-array site', input: JSON.stringify({ site: 'example.com' }), confidence: 0 },
  ],
});
