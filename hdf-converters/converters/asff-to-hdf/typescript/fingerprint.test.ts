import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, asffFingerprint } from './fingerprint.js';

runFingerprintTests({
  id: 'asff-to-hdf',
  label: 'ASFF (AWS Security Finding Format)',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: asffFingerprint,
  register,
  positive: [
    {
      name: 'detects canonical ASFF with SchemaVersion + ProductArn at 1.0',
      input: JSON.stringify({
        Findings: [
          {
            SchemaVersion: '2018-10-08',
            ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
            GeneratorId: 'g',
            Title: 't',
          },
        ],
      }),
      confidence: 1.0,
    },
    {
      name: 'detects ASFF with ProductArn but no SchemaVersion at 0.7',
      input: JSON.stringify({
        Findings: [
          { ProductArn: 'arn:aws:securityhub:us-east-1::product/companyx/scannery' },
        ],
      }),
      confidence: 0.7,
    },
  ],
  negative: [
    {
      name: 'does not match SARIF JSON',
      input: JSON.stringify({ version: '2.1.0', runs: [] }),
      confidence: 0,
    },
    {
      name: 'does not match Dependency-Track JSON',
      input: JSON.stringify({ findings: [{ vulnerability: { vulnId: 'x' } }] }),
      confidence: 0,
    },
    {
      name: 'does not match envelope with empty Findings array',
      input: JSON.stringify({ Findings: [] }),
      confidence: 0,
    },
    {
      name: 'does not match envelope with non-object Findings element',
      input: JSON.stringify({ Findings: ['string-not-object'] }),
      confidence: 0,
    },
    {
      name: 'does not match envelope with first finding lacking ProductArn',
      input: JSON.stringify({ Findings: [{ SchemaVersion: '2018-10-08' }] }),
      confidence: 0,
    },
    {
      name: 'does not match top-level array',
      input: JSON.stringify(['anything']),
      confidence: 0,
    },
    {
      name: 'does not match top-level null',
      input: 'null',
      confidence: 0,
    },
  ],
});
