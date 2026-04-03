import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, msftDefenderCloudFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'msft-defender-cloud-to-hdf',
  label: 'Microsoft Defender for Cloud',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: msftDefenderCloudFingerprint,
  register,
  positive: [
    {
      name: 'detects Defender for Cloud JSON at confidence 1.0',
      input: JSON.stringify({
        value: [
          {
            id: '/subscriptions/abc/providers/Microsoft.Security/assessments/001',
            name: '001',
            type: 'Microsoft.Security/assessments',
            properties: {
              displayName: 'Enable MFA',
              resourceDetails: { source: 'Azure', id: '/subscriptions/abc' },
              status: { code: 'Unhealthy', cause: '', description: '' },
              metadata: {
                displayName: 'Enable MFA',
                assessmentType: 'BuiltIn',
                policyDefinitionId: '',
                description: 'desc',
                remediationDescription: '',
                categories: [],
                severity: 'High',
                userImpact: 'Moderate',
                implementationEffort: 'Low',
                threats: [],
                tactics: [],
                techniques: [],
              },
            },
          },
        ],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects empty value array at confidence 0.5',
      input: JSON.stringify({ value: [] }),
      confidence: 0.5,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
