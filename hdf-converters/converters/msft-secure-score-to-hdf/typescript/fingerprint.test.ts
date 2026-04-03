import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, msftSecureScoreFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'msft-secure-score-to-hdf',
  label: 'Microsoft Secure Score',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: msftSecureScoreFingerprint,
  register,
  positive: [
    {
      name: 'detects Secure Score JSON at confidence 1.0',
      input: JSON.stringify({
        secureScore: {
          value: [
            {
              id: 'score-001',
              azureTenantId: 'tenant-abc',
              createdDateTime: '2024-01-01T00:00:00Z',
              controlScores: [
                {
                  controlCategory: 'Identity',
                  controlName: 'MFARegistrationV2',
                  description: 'Register MFA',
                  score: 9,
                  implementationStatus: 'Implemented',
                  scoreInPercentage: 100,
                },
              ],
            },
          ],
        },
        profiles: {
          value: [
            { id: 'MFARegistrationV2', title: 'MFA Registration' },
          ],
        },
      }),
      confidence: 1.0,
    },
    {
      name: 'detects empty secureScore/profiles at confidence 0.8',
      input: JSON.stringify({ secureScore: { value: [] }, profiles: { value: [] } }),
      confidence: 0.8,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
