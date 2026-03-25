import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, niktoFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'nikto-to-hdf',
  label: 'Nikto',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: niktoFingerprint,
  register,
  positive: [
    {
      name: 'detects full Nikto JSON at confidence 0.95',
      input: JSON.stringify({
        host: '10.0.0.1',
        port: '80',
        banner: 'Apache/2.4',
        vulnerabilities: [{ id: '1', msg: 'test vuln' }],
      }),
      confidence: 0.95,
    },
    {
      name: 'detects minimal Nikto JSON at confidence 0.85',
      input: JSON.stringify({
        vulnerabilities: [{ id: '1', msg: 'test vuln' }],
      }),
      confidence: 0.85,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><root><child/></root>', confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
    { name: 'does not match object without vulnerabilities array', input: JSON.stringify({ host: '10.0.0.1', findings: [] }), confidence: 0 },
  ],
});
