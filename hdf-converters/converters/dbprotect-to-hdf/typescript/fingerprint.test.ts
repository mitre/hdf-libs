import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, dbprotectFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'dbprotect-to-hdf',
  label: 'DBProtect',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: dbprotectFingerprint,
  register,
  positive: [
    {
      name: 'detects DBProtect XML with metadata/data at confidence 1.0',
      input: '<?xml version="1.0"?><dataset><metadata><item><name>col1</name><type>string</type></item></metadata><data><row><value>v1</value></row></data></dataset>',
      confidence: 1.0,
    },
    {
      name: 'detects minimal dataset XML at confidence 0.8',
      input: '<?xml version="1.0"?><dataset><other/></dataset>',
      confidence: 0.8,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
