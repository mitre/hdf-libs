import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, msftDefenderEndpointFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'msft-defender-endpoint-to-hdf',
  label: 'Microsoft Defender for Endpoint',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: msftDefenderEndpointFingerprint,
  register,
  positive: [
    {
      name: 'detects MDE alert JSON at confidence 1.0',
      input: JSON.stringify({
        '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2',
        value: [
          {
            id: 'alert-001',
            severity: 'high',
            category: 'Malware',
            title: 'Suspicious process',
            description: 'A suspicious process was detected',
            status: 'new',
            evidence: [
              { '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'host1' },
            ],
          },
        ],
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match MDE-like JSON without evidence array', input: JSON.stringify({ value: [{ id: 'alert-002', severity: 'medium', category: 'Lateral Movement', title: 'test', description: 'desc', status: 'new' }] }), confidence: 0 },
    { name: 'does not match Defender for Cloud JSON', input: JSON.stringify({ value: [{ id: '/subscriptions/abc', name: '001', properties: { displayName: 'Enable MFA' } }] }), confidence: 0 },
    { name: 'does not match random JSON', input: JSON.stringify({ foo: 'bar' }), confidence: 0 },
  ],
});
