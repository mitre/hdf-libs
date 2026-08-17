/**
 * Type definitions for the test-only HDF builders (index.js).
 */
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
} from '../dist/ts/hdf.js';

export interface ReqOptions {
  severity?: string;
  impact?: number;
  status?: string;
  tags?: Record<string, unknown>;
  code?: string;
  cwe?: string[];
  title?: string;
  /** codeDesc of the (default) result. */
  codeDesc?: string;
  /** startTime (ISO string) of the (default) result. */
  startTime?: string;
  /** Data for the default description. */
  desc?: string;
  /** Extra [label, data] descriptions appended after the default. */
  addDesc?: Array<[string, string]>;
  /** Replace the requirement's results wholesale. */
  results?: RequirementResult[];
}

export function req(id: string, opts?: ReqOptions): EvaluatedRequirement;
export function baseline(name: string, ...reqs: EvaluatedRequirement[]): EvaluatedBaseline;
export function doc(...baselines: EvaluatedBaseline[]): HDFResults;
export function results(...reqs: EvaluatedRequirement[]): HDFResults;

import type {
  HDFBaseline,
  BaselineRequirement,
  HDFAmendments,
  StandaloneOverride,
  HDFSystem,
  Component,
  HDFPlan,
  Assessment,
  HDFEvidencePackage,
  ContentReference,
  HDFRequirementChangeEvent,
  HDFComparison,
} from '../dist/ts/hdf.js';

export interface BaselineReqOptions {
  impact?: number;
  tags?: Record<string, unknown>;
  desc?: string;
}
export function baselineReq(id: string, opts?: BaselineReqOptions): BaselineRequirement;
export function baselineDoc(name: string, ...reqs: BaselineRequirement[]): HDFBaseline;

export interface OverrideOptions {
  status?: string;
  reason?: string;
  appliedBy?: { type: string; identifier: string };
  milestones?: unknown[];
}
export function override(type: string, reqId: string, opts?: OverrideOptions): StandaloneOverride;
export function amendments(name: string, ...overrides: StandaloneOverride[]): HDFAmendments;

export function component(name: string, type: string, opts?: Record<string, unknown>): Component;
export function system(name: string, ...components: Component[]): HDFSystem;

export function assessment(baselineRef: string): Assessment;
export function plan(name: string, ...assessments: Assessment[]): HDFPlan;

export function content(uri: string, type: string): ContentReference;
export function evidencePackage(name: string, ...contents: ContentReference[]): HDFEvidencePackage;

export interface ChangeEventOptions {
  state?: string;
  before?: unknown;
  after?: unknown;
  priorChecksum?: unknown;
}
export function changeEvent(reqId: string, opts?: ChangeEventOptions): HDFRequirementChangeEvent;

export function comparison(mode: string): HDFComparison;
