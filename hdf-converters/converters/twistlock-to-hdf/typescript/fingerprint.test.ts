import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, twistlockFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'twistlock-to-hdf',
  label: 'Twistlock',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: twistlockFingerprint,
  register,
  positive: [
    {
      name: 'detects container scan with complianceDistribution at confidence 1.0',
      input: JSON.stringify({
        results: [
          {
            id: 'sha256:abc123',
            name: 'my-image:latest',
            complianceDistribution: { critical: 0, high: 2, medium: 5, low: 3, total: 10 },
            vulnerabilityDistribution: { critical: 1, high: 3, medium: 7, low: 2, total: 13 },
            vulnerabilities: [{ id: 'CVE-2024-1234', severity: 'high', description: 'test vuln' }],
          },
        ],
        consoleURL: 'https://prisma.example.com',
      }),
      confidence: 1.0,
    },
    {
      name: 'detects scan with vulnerabilityDistribution only at confidence 0.9',
      input: JSON.stringify({
        results: [
          {
            id: 'sha256:def456',
            vulnerabilityDistribution: { critical: 0, high: 1, medium: 2, low: 0, total: 3 },
          },
        ],
      }),
      confidence: 0.9,
    },
    {
      name: 'detects code repo scan (single result, no wrapper) at confidence 1.0',
      input: JSON.stringify({
        complianceDistribution: { critical: 0, high: 0, medium: 1, low: 2, total: 3 },
        vulnerabilities: [],
      }),
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match TruffleHog JSON', input: JSON.stringify({ DetectorName: 'AWS', SourceMetadata: {}, Raw: 'key', Verified: true, Redacted: '***' }), confidence: 0 },
    { name: 'does not match object with empty results array', input: JSON.stringify({ results: [] }), confidence: 0 },
    { name: 'does not match array input', input: JSON.stringify([{ complianceDistribution: {} }]), confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><results/>', confidence: 0 },
  ],
});
