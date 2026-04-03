import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, legacyHdfFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'legacyhdf-to-hdf',
  label: 'HDF v1 (Legacy)',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: legacyHdfFingerprint,
  register,
  positive: [
    {
      name: 'detects full HDF v1 at confidence 1.0',
      input: JSON.stringify({
        version: '1.0.0',
        platform: { name: 'ubuntu', release: '20.04', target_id: '' },
        profiles: [
          {
            name: 'inspec-profile',
            version: '1.2.3',
            title: 'My Profile',
            controls: [
              { id: 'V-12345', title: 'Test Control', impact: 0.7, results: [{ status: 'passed', code_desc: 'test' }] },
            ],
          },
        ],
        statistics: { duration: 5.2 },
      }),
      confidence: 1.0,
    },
    {
      name: 'detects minimal HDF v1 at confidence 1.0',
      input: JSON.stringify({
        version: '0.1.0',
        platform: { name: 'unknown' },
        profiles: [],
        statistics: {},
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match HDF v2 (has baselines[], not profiles[])', input: JSON.stringify({ baselines: [{ name: 'test-baseline', requirements: [] }], generator: { name: 'hdf-converters', version: '1.0.0' } }), confidence: 0 },
    { name: 'does not match SARIF JSON (has version but no profiles)', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match when platform is null', input: JSON.stringify({ version: '1.0', profiles: [], platform: null }), confidence: 0 },
    { name: 'does not match when profiles is not array', input: JSON.stringify({ version: '1.0', profiles: {}, platform: { name: 'x' } }), confidence: 0 },
    { name: 'does not match when version is not string', input: JSON.stringify({ version: 1, profiles: [], platform: { name: 'x' } }), confidence: 0 },
    { name: 'does not match object with both baselines and profiles', input: JSON.stringify({ version: '1.0', platform: { name: 'test' }, profiles: [], baselines: [] }), confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><root/>', confidence: 0 },
  ],
});
