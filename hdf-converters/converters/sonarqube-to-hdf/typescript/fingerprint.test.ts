import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, sonarqubeFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'sonarqube-to-hdf',
  label: 'SonarQube',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: sonarqubeFingerprint,
  register,
  positive: [
    {
      name: 'detects SonarQube JSON at confidence 1.0',
      input: JSON.stringify({
        total: 1,
        p: 1,
        ps: 100,
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [
          {
            key: 'issue-001',
            rule: 'java:S1135',
            severity: 'MAJOR',
            component: 'com.example:app:src/Main.java',
            project: 'com.example:app',
            status: 'OPEN',
            message: 'Complete the task associated to this TODO comment.',
            creationDate: '2024-01-01T00:00:00+0000',
            updateDate: '2024-01-01T00:00:00+0000',
            type: 'CODE_SMELL',
          },
        ],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects SonarQube with empty issues at confidence 0.5',
      input: JSON.stringify({ total: 0, issues: [] }),
      confidence: 0.5,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
