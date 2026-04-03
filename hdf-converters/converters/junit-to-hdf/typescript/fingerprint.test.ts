import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, junitFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'junit-to-hdf',
  label: 'JUnit',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: junitFingerprint,
  register,
  positive: [
    {
      name: 'detects testsuites root at confidence 1.0',
      input: '<?xml version="1.0"?><testsuites><testsuite name="suite1"><testcase name="test1"/></testsuite></testsuites>',
      confidence: 1.0,
    },
    {
      name: 'detects testsuite root at confidence 1.0',
      input: '<?xml version="1.0"?><testsuite name="suite1"><testcase name="test1"/></testsuite>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><Benchmark id="test"><title>Test</title></Benchmark>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
