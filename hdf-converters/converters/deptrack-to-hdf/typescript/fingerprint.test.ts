import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, deptrackFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'deptrack-to-hdf',
  label: 'Dependency-Track',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: deptrackFingerprint,
  register,
  positive: [
    {
      name: 'detects full Dependency-Track FPF at confidence 1.0',
      input: JSON.stringify({
        version: '1.0',
        meta: {
          application: 'Dependency-Track',
          version: '4.8.0',
          timestamp: '2024-01-01T00:00:00Z',
        },
        project: {
          uuid: 'proj-uuid-123',
          name: 'test-project',
          version: '1.0.0',
        },
        findings: [
          {
            component: { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
            vulnerability: {
              vulnId: 'CVE-2021-23337',
              source: 'NVD',
              severity: 'HIGH',
            },
            matrix: 'proj-uuid:comp-uuid:vuln-uuid',
          },
        ],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects findings with vulnId at confidence 0.9',
      input: JSON.stringify({
        findings: [
          {
            vulnerability: { vulnId: 'CVE-2021-12345', severity: 'MEDIUM' },
            component: { name: 'foo' },
          },
        ],
      }),
      confidence: 0.9,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match CycloneDX JSON', input: JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5' }), confidence: 0 },
  ],
});
