import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, netsparkerFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'netsparker-to-hdf',
  label: 'Netsparker',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: netsparkerFingerprint,
  register,
  positive: [
    {
      name: 'detects netsparker-enterprise XML at confidence 1.0',
      input: '<?xml version="1.0"?><netsparker-enterprise><generated>2024-01-01</generated></netsparker-enterprise>',
      confidence: 1.0,
    },
    {
      name: 'detects invicti-enterprise XML at confidence 1.0',
      input: '<?xml version="1.0"?><invicti-enterprise><generated>2024-01-01</generated></invicti-enterprise>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
