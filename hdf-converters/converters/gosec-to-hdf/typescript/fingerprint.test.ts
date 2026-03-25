import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, gosecFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'gosec-to-hdf',
  label: 'GoSec',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: gosecFingerprint,
  register,
  positive: [
    {
      name: 'detects full GoSec report at confidence 1.0',
      input: JSON.stringify({ GosecVersion: '2.18.2', Issues: [{ severity: 'HIGH', rule_id: 'G101' }], Stats: { files: 10 } }),
      confidence: 1.0,
    },
    {
      name: 'detects GoSec without version at confidence 0.6',
      input: JSON.stringify({ Issues: [{ severity: 'MEDIUM', rule_id: 'G201' }], Stats: { files: 5 } }),
      confidence: 0.6,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match CycloneDX JSON', input: JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5' }), confidence: 0 },
  ],
});
