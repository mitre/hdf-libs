import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, cklFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'ckl-to-hdf',
  label: 'CKL (DISA STIG Viewer checklist)',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: cklFingerprint,
  register,
  positive: [
    {
      name: 'detects bare CHECKLIST root element',
      input: '<?xml version="1.0"?><CHECKLIST><ASSET/></CHECKLIST>',
      confidence: 1.0,
    },
  ],
  negative: [
    {
      name: 'does not match unrelated XML root',
      input: '<?xml version="1.0"?><Benchmark/>',
      confidence: 0,
    },
    {
      name: 'does not match JSON',
      input: '{"Findings": []}',
      confidence: 0,
    },
    {
      name: 'does not match empty string',
      input: '',
      confidence: 0,
    },
  ],
});
