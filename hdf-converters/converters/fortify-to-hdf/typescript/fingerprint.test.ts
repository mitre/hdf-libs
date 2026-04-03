import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, fortifyFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'fortify-to-hdf',
  label: 'Fortify',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: fortifyFingerprint,
  register,
  positive: [
    {
      name: 'detects Fortify FVDL with namespace at confidence 1.0',
      input: '<?xml version="1.0"?><FVDL xmlns="xmlns.fortify.com/schema/fvdl"><CreatedTS date="2024-01-01"/></FVDL>',
      confidence: 1.0,
    },
    {
      name: 'detects Fortify FVDL without namespace at confidence 0.95',
      input: '<?xml version="1.0"?><FVDL><Vulnerabilities/></FVDL>',
      confidence: 0.95,
    },
    {
      name: 'detects Fortify FVDL with namespace prefix',
      input: '<?xml version="1.0"?><f:FVDL xmlns:f="xmlns.fortify.com/schema/fvdl"><f:CreatedTS/></f:FVDL>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
