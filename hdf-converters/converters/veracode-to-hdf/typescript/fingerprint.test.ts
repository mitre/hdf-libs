import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, veracodeFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'veracode-to-hdf',
  label: 'Veracode',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: veracodeFingerprint,
  register,
  positive: [
    {
      name: 'detects Veracode DetailedReport at confidence 1.0',
      input: '<?xml version="1.0" encoding="UTF-8"?><detailedreport report_format_version="1.5" app_name="TestApp" build_id="12345"><severity level="5"><category categoryid="18" categoryname="CRLF Injection"/></severity></detailedreport>',
      confidence: 1.0,
    },
    {
      name: 'detects namespaced detailedreport',
      input: '<?xml version="1.0"?><ns:detailedreport xmlns:ns="https://www.veracode.com/schema/reports/export/1.0" app_name="TestApp"/>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match Veracode summaryreport', input: '<?xml version="1.0"?><summaryreport app_name="TestApp"><severity level="5"/></summaryreport>', confidence: 0 },
    { name: 'does not match JUnit XML', input: '<?xml version="1.0"?><testsuites><testsuite name="s1"><testcase name="t1"/></testsuite></testsuites>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty string', input: '', confidence: 0 },
    { name: 'does not match plain text', input: 'just some plain text', confidence: 0 },
  ],
});
