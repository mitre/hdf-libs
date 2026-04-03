import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register as registerMsdo, msftDefenderDevopsFingerprint } from './fingerprint.js';
import { register as registerSarif } from '../../sarif-to-hdf/typescript/fingerprint.js';

// Register both MSDO and SARIF fingerprints so cross-fingerprint ranking tests work
function register(): void {
  registerMsdo();
  registerSarif();
}

runFingerprintTests({
  id: 'msft-defender-devops-to-hdf',
  label: 'Microsoft Defender for DevOps',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: msftDefenderDevopsFingerprint,
  register,
  positive: [
    {
      name: 'detects MSDO SARIF at confidence 0.95',
      input: JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'Microsoft Security DevOps',
                organization: 'Microsoft',
              },
            },
            results: [],
          },
        ],
      }),
      confidence: 0.95,
    },
    {
      name: 'detects SARIF with DevOps in driver name',
      input: JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'Azure DevOps Scanner',
              },
            },
            results: [],
          },
        ],
      }),
      confidence: 0.95,
    },
  ],
  negative: [
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
