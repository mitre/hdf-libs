import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, hdfFingerprint, HDF_PASSTHROUGH_ID } from './fingerprint.js';

runFingerprintTests({
  id: HDF_PASSTHROUGH_ID,
  label: 'HDF',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: hdfFingerprint,
  register,
  positive: [
    {
      name: 'detects minimal HDF at confidence 0.8',
      input: JSON.stringify({ baselines: [{ name: 'test-baseline', requirements: [] }] }),
      confidence: 0.8,
    },
    {
      name: 'detects full HDF at confidence 0.8',
      input: JSON.stringify({
        baselines: [
          {
            name: 'my-scan',
            title: 'My Security Scan',
            requirements: [
              { id: 'V-12345', title: 'Test Control', impact: 0.7, results: [{ status: 'passed' }] },
            ],
          },
        ],
        generator: { name: 'hdf-converters', version: '1.0.0' },
        components: [{ name: 'test-host', type: 'host' }],
        timestamp: '2024-01-15T10:00:00Z',
      }),
      confidence: 0.8,
    },
  ],
  negative: [
    { name: 'does not match HDF v1 (profiles[], not baselines[])', input: JSON.stringify({ version: '1.0.0', platform: { name: 'ubuntu', release: '20.04' }, profiles: [{ name: 'test', controls: [] }], statistics: {} }), confidence: 0 },
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match array input', input: '[]', confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><root/>', confidence: 0 },
    { name: 'does not match when baselines is not an array', input: JSON.stringify({ baselines: 'invalid' }), confidence: 0 },
  ],
});
