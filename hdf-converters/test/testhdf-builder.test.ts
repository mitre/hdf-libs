import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { expectValidResults } from './helpers/expectValidHdf.js';
import {
  validateBaseline,
  validateAmendments,
  validateSystem,
  validatePlan,
  validateEvidencePackage,
  validateRequirementChangeEvent,
  validateComparison,
} from '@mitre/hdf-validators';

const clone = (x: unknown): unknown => JSON.parse(JSON.stringify(x));
const expectValid = (v: { valid: boolean; getErrorMessage: () => string }): void => {
  expect(v.valid, v.getErrorMessage()).toBe(true);
};

const OVERRIDE_TYPES = [
  'waiver',
  'attestation',
  'poam',
  'inherited',
  'falsePositive',
  'riskAdjustment',
  'operationalRequirement',
];

describe('@mitre/hdf-schema/testhdf builder', () => {
  it('defaults produce schema-valid HDF', () => {
    expectValidResults(testhdf.results(testhdf.req('X')));
  });

  it('options produce schema-valid HDF', () => {
    expectValidResults(
      testhdf.results(
        testhdf.req('AC-1', {
          severity: 'high',
          impact: 0.7,
          status: 'failed',
          tags: { nist: ['AC-1'] },
          cwe: ['CWE-79'],
        }),
        testhdf.req('AC-2', { status: 'passed', addDesc: [['check', 'the check text']] }),
      ),
    );
  });

  it('multi-baseline doc is schema-valid', () => {
    expectValidResults(testhdf.doc(testhdf.baseline('b1', testhdf.req('X')), testhdf.baseline('b2', testhdf.req('Y'))));
  });
});

describe('@mitre/hdf-schema/testhdf doc-type builders are schema-valid', () => {
  it('baseline', () => {
    expectValid(validateBaseline(clone(testhdf.baselineDoc('b', testhdf.baselineReq('AC-1')))));
  });
  it('baseline with options', () => {
    expectValid(validateBaseline(clone(testhdf.baselineDoc('b', testhdf.baselineReq('AC-1', { impact: 0.5 })))));
  });
  it('amendments with an explicit status', () => {
    expectValid(validateAmendments(clone(testhdf.amendments('a',
      testhdf.override('waiver', 'AC-1', { status: 'passed', reason: 'accepted risk' })))));
  });
  // The schema's status/impact rule is type-dependent, so no single default can
  // satisfy operationalRequirement (which forbids both) and the rest at once.
  it.each(OVERRIDE_TYPES)('amendments with a bare %s override', (type) => {
    expectValid(validateAmendments(clone(testhdf.amendments('a', testhdf.override(type, 'CVE-2021-44228')))));
  });
  it('system', () => {
    expectValid(validateSystem(clone(testhdf.system('s', testhdf.component('WebTier', 'application')))));
  });
  it('plan', () => {
    expectValid(validatePlan(clone(testhdf.plan('p', testhdf.assessment('baseline-1')))));
  });
  it('evidence-package', () => {
    expectValid(validateEvidencePackage(clone(testhdf.evidencePackage('e', testhdf.content('results.json', 'hdf-results')))));
  });
  it('change-event', () => {
    expectValid(validateRequirementChangeEvent(clone(testhdf.changeEvent('AC-1'))));
  });
  it('comparison', () => {
    expectValid(validateComparison(clone(testhdf.comparison('temporal'))));
  });
});

const goModuleDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'hdf-schema',
  'testhdf',
  'go',
);

function hasGo(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function goBuilderDocs(): unknown {
  const dumpPath = path.join(mkdtempSync(path.join(tmpdir(), 'testhdf-parity-')), 'go.json');
  execFileSync('go', ['test', './...', '-run', 'TestDocs_ParityDump', '-count=1'], {
    cwd: goModuleDir,
    env: { ...process.env, TESTHDF_PARITY_DUMP: dumpPath },
    stdio: 'ignore',
  });
  return JSON.parse(readFileSync(dumpPath, 'utf-8'));
}

function tsBuilderDocs(): Record<string, unknown> {
  const docs: Record<string, unknown> = {
    results: testhdf.results(testhdf.req('X')),
    baseline: testhdf.baselineDoc('b', testhdf.baselineReq('AC-1')),
    system: testhdf.system('s', testhdf.component('WebTier', 'application')),
    plan: testhdf.plan('p', testhdf.assessment('baseline-1')),
    'evidence-package': testhdf.evidencePackage('e', testhdf.content('results.json', 'hdf-results')),
    'change-event': testhdf.changeEvent('AC-1'),
    comparison: testhdf.comparison('temporal'),
  };
  for (const type of OVERRIDE_TYPES) {
    docs[`amendments-${type}`] = testhdf.amendments('a', testhdf.override(type, 'CVE-2021-44228'));
  }
  return docs;
}

// Skipped without a Go toolchain so a TS-only dev environment still runs; CI has Go.
describe.skipIf(!hasGo())('@mitre/hdf-schema/testhdf builders agree across Go and TypeScript', () => {
  it('builds identical documents from identical calls', { timeout: 120_000 }, () => {
    expect(clone(tsBuilderDocs())).toEqual(goBuilderDocs());
  });
});
