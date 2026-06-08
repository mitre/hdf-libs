import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { ionchannelFingerprint, register } from './fingerprint.js';

runFingerprintTests({
  id: 'ionchannel-to-hdf',
  label: 'Ion Channel',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: ionchannelFingerprint,
  register,
  positive: [
    {
      name: 'detects Ion Channel analysis JSON at confidence 1.0 (4 keys + scan_summaries)',
      input: JSON.stringify({
        analysis_id: 'a1',
        team_id: 't1',
        source: 's1',
        trigger_hash: 'h1',
        scan_summaries: [],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects Ion Channel at confidence 0.5 (3 keys + scan_summaries)',
      input: JSON.stringify({
        analysis_id: 'a1',
        team_id: 't1',
        source: 's1',
        scan_summaries: [],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects partial Ion Channel at lower confidence (2 keys + scan_summaries)',
      input: JSON.stringify({
        analysis_id: 'a1',
        team_id: 't1',
        scan_summaries: [],
      }),
      confidence: 0.5,
    },
  ],
  negative: [
    { name: 'rejects JSON with Ion Channel keys but no scan_summaries', input: JSON.stringify({ analysis_id: 'a1', team_id: 't1', source: 's1', trigger_hash: 'h1' }), confidence: 0 },
    { name: 'rejects JSON with zero matching keys', input: JSON.stringify({ scan_summaries: [], foo: 'bar' }), confidence: 0 },
    { name: 'rejects arrays', input: JSON.stringify([{ analysis_id: 'a' }]), confidence: 0 },
    { name: 'rejects unrelated JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
