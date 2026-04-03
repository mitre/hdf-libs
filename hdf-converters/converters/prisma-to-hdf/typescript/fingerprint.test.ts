import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, prismaFingerprint } from './fingerprint.js';

const PRISMA_CSV_HEADER = 'Hostname,Distro,CVE ID,Compliance ID,Type,Severity,Packages,Description,Cause,Fix Status,Published,Vulnerability Link';
const PRISMA_CSV_FULL = `${PRISMA_CSV_HEADER}
host1,Ubuntu 22.04,CVE-2024-1234,CID-001,image,high,openssl,Vulnerable package found,outdated,Fix available,2024-01-01,https://example.com`;

runFingerprintTests({
  id: 'prisma-to-hdf',
  label: 'Prisma Cloud CSV',
  direction: 'ingest',
  inputFamily: 'text',
  outputType: 'results',
  fingerprint: prismaFingerprint,
  register,
  positive: [
    {
      name: 'detects Prisma CSV header at confidence 0.85',
      input: PRISMA_CSV_HEADER,
      confidence: 0.85,
    },
    {
      name: 'detects full Prisma CSV at confidence 0.85',
      input: PRISMA_CSV_FULL,
      confidence: 0.85,
    },
    {
      name: 'returns partial confidence 0.4 for CSV with 3 of 5 columns',
      input: 'Hostname,Severity,Type,Other,Column\nhost1,high,image,foo,bar',
      confidence: 0.4,
    },
  ],
  negative: [
    { name: 'returns 0 for unrelated CSV', input: 'Name,Email,Phone\nJohn,john@test.com,555-1234', confidence: 0 },
    { name: 'returns 0 for JSON input string', input: '{"version": "2.1.0", "runs": []}', confidence: 0 },
    { name: 'returns 0 for XML input string', input: '<?xml version="1.0"?><root/>', confidence: 0 },
  ],
});
