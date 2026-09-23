// Threshold rules — the TypeScript peer of hdf-engine/go/rules.go. A rule is a
// filter predicate plus a bound on how many requirements may match it, for the
// policies the fixed status × severity grid cannot express. Kept at behavioural
// parity with the Go implementation by the shared case table both suites read
// (testdata/threshold-rule-cases.json).

import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';
import { filter, type FilterOptions } from './query.js';
import {
  validateGrid,
  type ThresholdConfig,
  type StatusCounts,
  type ControlIDMapping,
} from './compliance.js';

/**
 * The predicate surface, in one place. Go maps these onto the filter explicitly
 * while TypeScript spreads them, so a field known to one language and not the
 * other is silently inert on one side; the shared case table pins this list, and
 * the assertion below stops the interface drifting away from it.
 */
export const PREDICATE_FIELDS = [
  'status',
  'severity',
  'impact',
  'cci',
  'nist',
  'id',
  'tag',
  'search',
  'baseline',
  'disposition',
  'poams',
] as const;

/**
 * The vocabulary a rule may name. It is deliberately the filter engine's own
 * vocabulary rather than a second one: a rule and an `hdf query` invocation then
 * mean the same thing. Values within a field OR; fields AND.
 */
export interface RulePredicate {
  status?: string[];
  severity?: string[];
  impact?: string;
  cci?: string[];
  nist?: string[];
  id?: string;
  tag?: string[];
  search?: string;
  baseline?: string;
  disposition?: string[];
  poams?: string;
}

/**
 * A policy the grid cannot express. Two decisions, recorded because a policy
 * author will otherwise assume one of them: a rule bounds a COUNT and not a
 * percentage — the grid's compliance min/max remains the only percentage bound,
 * and extending rules to percentages is deferred rather than excluded — and a
 * rule evaluates over the WHOLE document, not per baseline. A policy that wants
 * one baseline says so with the baseline predicate.
 *
 * `name` is optional and exists for the
 * violation message; a rule without one is identified by its predicate, which is
 * the only other handle a reader has.
 */
export interface ThresholdRule {
  name?: string;
  where: RulePredicate;
  min?: number;
  max?: number;
}

/**
 * What rule evaluation needs beyond the document: the reference clock for
 * expiry, and the status resolver. statusOf is injected rather than assumed so a
 * rule and the grid's counts cannot disagree about what 'failed' means on the
 * same document.
 */
export interface RuleOptions {
  now?: string;
  statusOf?: (control: EvaluatedRequirement) => string;
}

/**
 * Maps a predicate onto the engine filter. Every field is a pass-through: the
 * point of reusing the vocabulary is that there is nothing to translate, and a
 * new filter field becomes a rule field by adding it here.
 */
function filterOptions(where: RulePredicate, options: RuleOptions): FilterOptions {
  return {
    ...where,
    now: options.now,
    // count so a limit can never truncate the population a bound is judged
    // against — a rule counts matches, it does not list them.
    count: true,
    statusOf: options.statusOf,
  };
}

/**
 * Renders a predicate for a violation message, fields sorted so the same rule
 * always reads the same way. Values within a field join with '|', which is what
 * they mean. Parity: describe() in go/rules.go.
 */
function describe(where: RulePredicate): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(where)) {
    if (Array.isArray(value)) {
      if (value.length > 0) parts.push(`${key}: ${value.join('|')}`);
    } else if (value) {
      parts.push(`${key}: ${String(value)}`);
    }
  }
  parts.sort();
  return `{${parts.join(', ')}}`;
}

function label(rule: ThresholdRule): string {
  return rule.name && rule.name !== '' ? rule.name : `rule ${describe(rule.where)}`;
}

/**
 * Applies every rule to the document and returns one violation per breached
 * bound. Evaluation is filter → count → compare, calling the engine's own filter
 * rather than a second matcher.
 */
export function evaluateRules(
  config: ThresholdConfig,
  results: HDFResults,
  options: RuleOptions = {}
): string[] {
  const violations: string[] = [];
  for (const rule of config.rules ?? []) {
    const matched = filter(results, filterOptions(rule.where, options)).length;
    if (rule.max !== undefined && matched > rule.max) {
      violations.push(`${label(rule)}: ${matched} matched, maximum ${rule.max}`);
    }
    if (rule.min !== undefined && matched < rule.min) {
      violations.push(`${label(rule)}: ${matched} matched, minimum ${rule.min}`);
    }
  }
  return violations;
}

/**
 * Everything an evaluation needs. A shape rather than a parameter list because
 * rules made the list long enough that a caller could transpose two arguments of
 * the same type without the compiler noticing. Parity: ThresholdInput in
 * go/rules.go.
 */
export interface ThresholdInput {
  results: HDFResults;
  counts: StatusCounts;
  compliance: number;
  controlMap: ControlIDMapping[];
  now?: string;
  statusOf?: (control: EvaluatedRequirement) => string;
}

/**
 * Applies a whole policy — the grid and the rules — and returns every violation.
 * This is the entry point a surface should call: validateThresholds evaluates the
 * grid alone and refuses a config carrying rules, so a caller cannot
 * half-implement a policy without being told. Parity: Evaluate in go/rules.go.
 */
export function evaluate(config: ThresholdConfig, input: ThresholdInput): string[] {
  const violations = validateGrid(config, input.counts, input.compliance, input.controlMap);
  return violations.concat(
    evaluateRules(config, input.results, { now: input.now, statusOf: input.statusOf })
  );
}

// Compile-time guard: a field added to RulePredicate and not to PREDICATE_FIELDS
// would reach the TypeScript filter through the spread and never reach Go, which
// is the drift the shared field list exists to prevent. This fails the build
// rather than waiting for a test nobody wrote.
type UnlistedPredicateField = Exclude<keyof RulePredicate, (typeof PREDICATE_FIELDS)[number]>;
const _everyPredicateFieldIsListed: UnlistedPredicateField extends never ? true : never = true;
void _everyPredicateFieldIsListed;
