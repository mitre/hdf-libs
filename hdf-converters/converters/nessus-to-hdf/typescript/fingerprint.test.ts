import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, nessusFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'nessus-to-hdf',
  label: 'Nessus',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: nessusFingerprint,
  register,
  positive: [
    {
      name: 'detects Nessus XML at confidence 1.0',
      input: '<?xml version="1.0"?><NessusClientData_v2><Policy><policyName>test</policyName></Policy></NessusClientData_v2>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
