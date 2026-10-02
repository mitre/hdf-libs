import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, gitlabVulnerabilitiesFingerprint } from './fingerprint.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');

runFingerprintTests({
  id: 'gitlab-vulnerabilities-to-hdf',
  label: 'GitLab Vulnerability Report',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: gitlabVulnerabilitiesFingerprint,
  register,
  positive: [
    { name: 'triaged envelope at confidence 1.0', input: fixture('triaged.json'), confidence: 1.0 },
    { name: 'clean envelope (no nodes to inspect) at confidence 0.9', input: fixture('clean.json'), confidence: 0.9 },
    { name: 'report-error envelope at confidence 0.9', input: fixture('report-error.json'), confidence: 0.9 },
    { name: 'empty envelope at confidence 0.9', input: fixture('empty.json'), confidence: 0.9 },
  ],
  negative: [
    // The sibling CI-artifact report also has a vulnerabilities array.
    { name: 'gitlab CI artifact report', input: readFileSync(join(__dirname, '..', '..', 'gitlab-to-hdf', 'fixtures', 'input', 'multi-vuln.json'), 'utf-8') },
    { name: 'empty object', input: '{}' },
    { name: 'vulnerabilities without a project block', input: JSON.stringify({ vulnerabilities: [{ uuid: 'x', state: 'DETECTED' }] }) },
    { name: 'project without fullPath', input: JSON.stringify({ project: { id: '1' }, vulnerabilities: [] }) },
    { name: 'nodes without state', input: JSON.stringify({ project: { fullPath: 'g/p' }, vulnerabilities: [{ uuid: 'x' }] }) },
    { name: 'vulnerabilities not an array', input: JSON.stringify({ project: { fullPath: 'g/p' }, vulnerabilities: {} }) },
  ],
});
