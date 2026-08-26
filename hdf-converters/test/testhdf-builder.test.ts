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
    expectValid(validateBaseline(clone(testhdf.baselineDoc('b', testhdf.baselineReq('AC-1', { impact: 0.5 })))));
  });
  it('amendments', () => {
    expectValid(validateAmendments(clone(testhdf.amendments('a',
      testhdf.override('waiver', 'AC-1', { status: 'passed', reason: 'accepted risk' })))));
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
