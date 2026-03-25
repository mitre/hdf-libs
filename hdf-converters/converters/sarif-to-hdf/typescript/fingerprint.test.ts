import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, sarifFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'sarif-to-hdf',
  label: 'SARIF',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: sarifFingerprint,
  register,
  positive: [
    {
      name: 'detects minimal SARIF at confidence 0.9',
      input: JSON.stringify({ version: '2.1.0', runs: [] }),
      confidence: 0.9,
    },
    {
      name: 'detects SARIF with $schema field',
      input: JSON.stringify({
        $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'eslint' } }, results: [] }],
      }),
      confidence: 0.9,
    },
  ],
  negative: [
    { name: 'does not match GoSec JSON', input: JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } }), confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><testsuites><testsuite/></testsuites>', confidence: 0 },
    { name: 'does not match when version is number', input: JSON.stringify({ version: 2, runs: [] }), confidence: 0 },
    { name: 'does not match when runs is object', input: JSON.stringify({ version: '2.1.0', runs: {} }), confidence: 0 },
  ],
});
