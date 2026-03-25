import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, gitlabFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'gitlab-to-hdf',
  label: 'GitLab',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: gitlabFingerprint,
  register,
  positive: [
    {
      name: 'detects full GitLab report with scan.type at confidence 0.9',
      input: JSON.stringify({
        version: '14.0.0',
        scan: {
          analyzer: { id: 'gemnasium', name: 'Gemnasium', version: '3.0' },
          scanner: { id: 'gemnasium', name: 'Gemnasium' },
          type: 'dependency_scanning',
          start_time: '2024-01-01T00:00:00',
          end_time: '2024-01-01T00:01:00',
          status: 'success',
        },
        vulnerabilities: [
          {
            id: 'vuln-001',
            name: 'Test Vulnerability',
            severity: 'High',
            description: 'A test vulnerability',
          },
        ],
      }),
      confidence: 0.9,
    },
    {
      name: 'detects minimal GitLab report (vulnerabilities only) at confidence 0.5',
      input: JSON.stringify({
        vulnerabilities: [
          { id: 'vuln-002', severity: 'Medium' },
        ],
      }),
      confidence: 0.5,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match GoSec JSON', input: JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } }), confidence: 0 },
  ],
});
