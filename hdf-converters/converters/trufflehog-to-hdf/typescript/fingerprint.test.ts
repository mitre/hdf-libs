import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, trufflehogFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'trufflehog-to-hdf',
  label: 'TruffleHog',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: trufflehogFingerprint,
  register,
  positive: [
    {
      name: 'detects full TruffleHog finding at confidence 1.0',
      input: JSON.stringify({
        SourceMetadata: { Data: { Git: { commit: 'abc123', file: 'config.yml', email: 'dev@example.com', repository: 'https://github.com/org/repo', timestamp: '2024-01-15T10:00:00Z', line: 42 } } },
        SourceID: 1,
        SourceType: 16,
        SourceName: 'trufflehog - git',
        DetectorType: 1,
        DetectorName: 'AWS',
        DecoderName: 'PLAIN',
        Verified: true,
        Raw: 'AKIAIOSFODNN7EXAMPLE',
        Redacted: 'AKIA***EXAMPLE',
      }),
      confidence: 1.0,
    },
    {
      name: 'detects minimal TruffleHog finding (Raw + Verified, no SourceMetadata) at confidence 0.7',
      input: JSON.stringify({
        Raw: 'some-secret-value',
        Verified: false,
        DetectorName: 'Generic',
        DecoderName: 'PLAIN',
        Redacted: '***',
      }),
      confidence: 0.7,
    },
    {
      name: 'detects TruffleHog array input',
      input: JSON.stringify([
        { SourceMetadata: { Data: {} }, DetectorName: 'AWS', DecoderName: 'PLAIN', Verified: true, Raw: 'key1', Redacted: '***' },
        { SourceMetadata: { Data: {} }, DetectorName: 'GitHub', DecoderName: 'PLAIN', Verified: false, Raw: 'key2', Redacted: '***' },
      ]),
      confidence: 1.0,
    },
    {
      name: 'detects Raw + Verified (no SourceMetadata) at confidence 0.7',
      input: JSON.stringify({ Raw: 'secret-token-123', Verified: true }),
      confidence: 0.7,
    },
  ],
  negative: [
    { name: 'does not match SARIF JSON', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match GoSec JSON', input: JSON.stringify({ GosecVersion: '2.18.2', Issues: [], Stats: { files: 1 } }), confidence: 0 },
    { name: 'does not match empty array', input: '[]', confidence: 0 },
    { name: 'does not match XML input', input: '<?xml version="1.0"?><root/>', confidence: 0 },
    { name: 'does not match when Raw is present but Verified is not boolean', input: JSON.stringify({ Raw: 'secret', Verified: 'yes' }), confidence: 0 },
  ],
});
