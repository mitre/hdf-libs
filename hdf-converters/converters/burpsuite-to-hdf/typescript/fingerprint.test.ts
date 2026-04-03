import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, burpsuiteFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'burpsuite-to-hdf',
  label: 'Burp Suite',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: burpsuiteFingerprint,
  register,
  positive: [
    {
      name: 'detects Burp Suite XML with burpVersion at confidence 1.0',
      input: '<?xml version="1.0"?><issues burpVersion="2024.1" exportTime="2024-01-01"><issue><serialNumber>1</serialNumber></issue></issues>',
      confidence: 1.0,
    },
    {
      name: 'detects minimal Burp Suite XML (no burpVersion) at confidence 0.7',
      input: '<?xml version="1.0"?><issues><issue/></issues>',
      confidence: 0.7,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
