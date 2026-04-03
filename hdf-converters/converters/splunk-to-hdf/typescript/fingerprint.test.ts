import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, splunkFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'splunk-to-hdf',
  label: 'Splunk',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: splunkFingerprint,
  register,
  positive: [
    {
      name: 'detects Splunk HDF events at confidence 1.0',
      input: JSON.stringify([
        {
          meta: {
            guid: 'abc-123',
            subtype: 'header',
            hdf_splunk_schema: '1.0',
            filetype: 'evaluation',
            filename: 'scan.json',
          },
          profiles: [],
          platform: { name: 'ubuntu', release: '22.04' },
          statistics: {},
          version: '4.38.9',
        },
        {
          meta: {
            guid: 'abc-123',
            subtype: 'profile',
            hdf_splunk_schema: '1.0',
            filetype: 'evaluation',
            filename: 'scan.json',
            profile_sha256: 'sha256abc',
          },
          name: 'ssh-baseline',
          title: 'SSH Baseline',
          sha256: 'sha256abc',
          version: '1.0',
          supports: [],
          groups: [],
          attributes: [],
          controls: [],
        },
        {
          meta: {
            guid: 'abc-123',
            subtype: 'control',
            hdf_splunk_schema: '1.0',
            filetype: 'evaluation',
            filename: 'scan.json',
            profile_sha256: 'sha256abc',
          },
          id: 'ssh-001',
          title: 'SSH version',
          desc: 'Ensure SSH v2',
          descriptions: {},
          impact: 0.7,
          code: '',
          tags: {},
          results: [
            { status: 'passed', code_desc: 'SSHv2 is enabled', start_time: '2024-01-01T00:00:00Z' },
          ],
          refs: [],
        },
      ]),
      confidence: 1.0,
    },
    {
      name: 'detects minimal Splunk event array at confidence 1.0',
      input: JSON.stringify([
        {
          meta: {
            guid: 'xyz-789',
            subtype: 'header',
            hdf_splunk_schema: '1.0',
            filetype: 'evaluation',
            filename: 'test.json',
          },
        },
      ]),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match random array', input: JSON.stringify([{ foo: 'bar' }]), confidence: 0 },
    { name: 'does not match object JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
    { name: 'does not match empty array', input: '[]', confidence: 0 },
  ],
});
