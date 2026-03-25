import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, conveyorFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'conveyor-to-hdf',
  label: 'Conveyor',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: conveyorFingerprint,
  register,
  positive: [
    {
      name: 'detects full Conveyor export at confidence 1.0',
      input: JSON.stringify({
        api_error_message: '',
        api_server_version: '4.0.0',
        api_response: {
          file_tree: {},
          results: {
            sha256abc: {
              sha256: 'sha256abc',
              response: { service_name: 'Clamav' },
              result: { score: 0, sections: [] },
            },
          },
          params: { description: 'test scan' },
        },
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match AWS Config JSON', input: JSON.stringify({ ConfigRules: [] }), confidence: 0 },
  ],
});
