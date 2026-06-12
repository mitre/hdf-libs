import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, cklbFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'cklb-to-hdf',
  label: 'CKLB (DISA STIG Viewer 3.x JSON)',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: cklbFingerprint,
  register,
  positive: [
    {
      name: 'detects CKLB with cklb_version + stigs array at 1.0',
      input: JSON.stringify({
        cklb_version: '1.0',
        stigs: [{ stig_name: 'sample' }],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects CKLB with empty stigs array at 1.0',
      input: JSON.stringify({
        cklb_version: '1.0',
        stigs: [],
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    {
      name: 'does not match missing cklb_version',
      input: JSON.stringify({ stigs: [] }),
      confidence: 0,
    },
    {
      name: 'does not match cklb_version present but stigs missing',
      input: JSON.stringify({ cklb_version: '1.0' }),
      confidence: 0,
    },
    {
      name: 'does not match cklb_version present but stigs not an array',
      input: JSON.stringify({ cklb_version: '1.0', stigs: 'not-array' }),
      confidence: 0,
    },
    {
      name: 'does not match top-level array',
      input: JSON.stringify([{ cklb_version: '1.0', stigs: [] }]),
      confidence: 0,
    },
    {
      name: 'does not match top-level null',
      input: 'null',
      confidence: 0,
    },
    {
      name: 'does not match SARIF JSON',
      input: JSON.stringify({ version: '2.1.0', runs: [] }),
      confidence: 0,
    },
  ],
});
