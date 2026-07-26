#!/usr/bin/env node
// Regenerates the Hipcheck analysis -> NIST 800-53 Rev 5 mapping
// (hipcheck-nist-mappings.json) and writes it byte-identically to both the Go
// and TS copies, deterministically sorted so future diffs stay clean.
//
//   node scripts/generate-hipcheck-mappings.mjs [--check]
//
//     (no flag)  rewrite both mapping files and print a row-count summary
//     --check    report drift only; exit 1 if regenerating would change EITHER copy (CI gate)
//
// Provenance: unlike aws-config, Hipcheck publishes NO analysis-to-controls
// crosswalk, so there is no authoritative source to scrape. The mapping below IS
// the source of truth: a hand-curated, NIST-RMF-reviewed table. Each row carries
// a Rationale. Editing the mapping means editing the CURATED array here, then
// running this script to propagate to both copies. This keeps the same
// "single source + repeatable refresh + CI drift gate" ergonomics as the other
// mapping generators even though the input is curated rather than scraped.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..');
const OUT_FILES = [
  join(REPO, 'hdf-mappings', 'go', 'hipcheck', 'hipcheck-nist-mappings.json'),
  join(REPO, 'hdf-mappings', 'src', 'data', 'hipcheck-nist-mappings.json'),
];

// Curated source of truth. NIST-ID is a '|'-delimited control list (matching the
// aws-config mapping convention). Rev 5 throughout.
const CURATED = [
  { Analysis: 'activity', 'NIST-ID': 'SR-3|SR-4', Rationale: 'Project maintenance/staleness is a supply-chain risk factor (SR-3) bearing on component provenance and continued viability (SR-4).' },
  { Analysis: 'affiliation', 'NIST-ID': 'SR-6', Rationale: 'Contributor org/nation-of-concern affiliation is a supplier assessment and review concern.' },
  { Analysis: 'binary', 'NIST-ID': 'SI-7|SR-4', Rationale: 'Unreviewable committed binaries are a software-integrity risk (SI-7) of unknown provenance (SR-4).' },
  { Analysis: 'churn', 'NIST-ID': 'SI-7|SR-4', Rationale: 'Anomalous code-change volume is a tamper/injection integrity signal (SI-7); alteration detection relates to provenance (SR-4).' },
  { Analysis: 'entropy', 'NIST-ID': 'SI-7|SR-4', Rationale: 'Obfuscated/high-entropy commit content is an integrity-of-content signal (SI-7); alteration relates to provenance (SR-4).' },
  { Analysis: 'fuzz', 'NIST-ID': 'SA-11', Rationale: 'Fuzz testing is a developer security testing and evaluation practice.' },
  { Analysis: 'identity', 'NIST-ID': 'AC-5', Rationale: 'A pull request whose author is also its merger is a separation-of-duties gap in the change-approval path.' },
  { Analysis: 'review', 'NIST-ID': 'SA-15', Rationale: 'Peer-review-before-merge discipline is a development-process and standards practice.' },
  { Analysis: 'typo', 'NIST-ID': 'SR-11|SR-4', Rationale: 'Typosquatted dependencies are a component-authenticity failure (SR-11) delivering a component of false provenance (SR-4).' },
];

const REV = 5;

// Emit rows with a fixed key order (Analysis, NIST-ID, Rev, Rationale), sorted by Analysis.
const rows = [...CURATED]
  .sort((a, b) => (a.Analysis < b.Analysis ? -1 : a.Analysis > b.Analysis ? 1 : 0))
  .map((r) => ({ Analysis: r.Analysis, 'NIST-ID': r['NIST-ID'], Rev: REV, Rationale: r.Rationale }));

const rendered = JSON.stringify(rows, null, 2) + '\n';

const check = process.argv.includes('--check');
let drift = false;

for (const file of OUT_FILES) {
  let current = '';
  try {
    current = readFileSync(file, 'utf8');
  } catch {
    current = '';
  }
  if (current === rendered) continue;
  drift = true;
  if (!check) {
    writeFileSync(file, rendered);
  }
}

if (check) {
  if (drift) {
    console.error('hipcheck mapping drift: regenerating would change a copy. Run: node scripts/generate-hipcheck-mappings.mjs');
    process.exit(1);
  }
  console.log(`hipcheck mapping in sync (${rows.length} analyses, both copies).`);
} else {
  console.log(`hipcheck mapping written: ${rows.length} analyses -> ${OUT_FILES.length} copies.`);
}
