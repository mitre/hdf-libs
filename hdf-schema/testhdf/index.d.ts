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
