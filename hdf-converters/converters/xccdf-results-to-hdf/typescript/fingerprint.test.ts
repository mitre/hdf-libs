import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, xccdfFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'xccdf-results-to-hdf',
  label: 'XCCDF/ARF',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: xccdfFingerprint,
  register,
  positive: [
    {
      name: 'detects XCCDF Benchmark XML at confidence 1.0',
      input: '<?xml version="1.0"?><Benchmark id="xccdf_test"><title>Test Benchmark</title></Benchmark>',
      confidence: 1.0,
    },
    {
      name: 'detects ARF asset-report-collection XML at confidence 1.0',
      input: '<?xml version="1.0"?><asset-report-collection><report-requests/></asset-report-collection>',
      confidence: 1.0,
    },
    {
      name: 'detects XCCDF with namespace prefix (xccdf:Benchmark)',
      input: '<?xml version="1.0"?><xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="test"><xccdf:title>Test</xccdf:title></xccdf:Benchmark>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});
