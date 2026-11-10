import cases from './cases.json' with { type: 'json' };
import test from 'node:test';
import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function requireEvidence(condition, message) {
  if (!condition) throw new Error(message);
}

export function validateReport(report, target, commit) {
  if (report?.mode !== 'integration') throw new Error('Missing integration evidence');
  if (!report.targets?.[target]) throw new Error('Missing requested target');
  requireEvidence(['elasticsearch', 'splunk'].includes(target), 'Unsupported target');
  requireEvidence(typeof commit === 'string' && /^[a-f0-9]{40}$/.test(commit), 'Expected commit is required');
  requireEvidence(report.status === 'PASS' && report.cleanup === 'PASS', 'Run and cleanup must pass');
  requireEvidence(report.source?.commit === commit, 'Report must match the expected commit');
  requireEvidence(report.source.trackedDiffSha256 === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    && Array.isArray(report.source.untracked) && report.source.untracked.length === 0, 'Hosted evidence requires a clean source tree');
  const service = report.targets[target];
  requireEvidence(typeof service.version === 'string' && service.version.length > 0
    && service.authenticated === true && /@sha256:[a-f0-9]{64}$/.test(service.image), 'Missing service identity or authentication');
  const rows = service.verification?.cases;
  requireEvidence(Array.isArray(rows) && rows.length === cases.length * 2, 'Incomplete integration matrix');
  for (const entry of cases) {
    let inputHash;
    for (const producer of ['cli', 'typescript']) {
      const matches = rows.filter(row => row?.name === entry.name && row.producer === producer);
      requireEvidence(matches.length === 1, 'Missing or duplicate fixture/producer result');
      const row = matches[0];
      requireEvidence(typeof row.sourceSha256 === 'string' && /^[a-f0-9]{64}$/.test(row.sourceSha256), 'Missing input fingerprint');
      requireEvidence(!inputHash || inputHash === row.sourceSha256, 'Producers must consume identical input');
      inputHash = row.sourceSha256;
      requireEvidence(row.kind === entry.kind, 'Incorrect fixture provenance');
      requireEvidence(Number.isSafeInteger(row.events) && (entry.name === 'empty' ? row.events === 0 : row.events > 0)
        && row.checksums === 3, 'Missing event or integrity verification');
      for (const name of ['source.json', 'manifest.json', 'evidence-package.json', 'archive']) {
        requireEvidence(Number.isSafeInteger(row.sizes?.[name]) && row.sizes[name] > 0, 'Missing delivered bundle member');
      }
      requireEvidence(Number.isSafeInteger(row.sizes['events.ndjson']) && row.sizes['events.ndjson'] >= 0, 'Missing events artifact');
      if (entry.name === 'override') {
        requireEvidence(Array.isArray(row.negatives) && row.negatives.length === 10 && new Set(row.negatives).size === 10,
          'Incomplete rejection verification');
      }
    }
  }
  return rows;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const target = process.env.HDF_SIEM_REPORT_TARGET;
  const label = ['elasticsearch', 'splunk'].includes(target) ? target : 'unknown target';
  test(`${label} source-preserving integration`, async () => {
    let report;
    try {
      const directory = process.env.HDF_SIEM_REPORT_DIR;
      const runs = (await readdir(directory, { withFileTypes: true })).filter(entry => entry.isDirectory());
      requireEvidence(runs.length === 1, 'Expected exactly one run');
      report = JSON.parse(await readFile(join(directory, runs[0].name, 'report.json'), 'utf8'));
    } catch {
      // Native file/JSON errors can include paths or credential-bearing input.
      throw new Error('Missing, ambiguous or malformed SIEM report');
    }
    validateReport(report, target, process.env.HDF_SIEM_REPORT_COMMIT);
  });
}
