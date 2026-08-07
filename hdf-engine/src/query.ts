// Requirements query engine — the TypeScript peer of hdf-engine/go/filter.go.
// A pure filter(results, options) with no shared mutable state, kept at
// behavioural parity with the Go implementation (see test/query.test.ts, which
// runs both over the same fixture).

import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';
import { impactToSeverity } from '@mitre/hdf-utilities';
import { safeGlobMatch } from './safematch.js';

/**
 * FilterOptions configures a requirements query. Every filter input arrives here;
 * distinct filters combine with AND, repeated values within a filter with OR.
 * statusOf resolves a requirement's display status, injected so the engine stays
 * agnostic to the caller's status-string convention (undefined → empty status).
 */
export interface FilterOptions {
  status?: string[];
  severity?: string[];
  impact?: string;
  cci?: string[];
  nist?: string[];
  id?: string;
  tag?: string[];
  search?: string;
  baseline?: string;
  limit?: number;
  count?: boolean;
  statusOf?: (control: EvaluatedRequirement) => string;
}

/** A single query result row. */
export interface Match {
  id: string;
  title: string;
  status: string;
  impact: number;
  severity: string;
  baseline: string;
}

type FilterFunc = (control: EvaluatedRequirement, status: string, severity: string) => boolean;

/**
 * filter returns the requirements across the result set's baselines that satisfy
 * options. Applies to requirement collections (results/baseline documents); the
 * calling adapter rejects document types that carry no requirements.
 */
export function filter(results: HDFResults, options: FilterOptions): Match[] {
  const filters = buildFilters(options);
  const matches: Match[] = [];

  for (const baseline of results.baselines ?? []) {
    if (options.baseline && !matchesGlob(baseline.name, options.baseline)) {
      continue;
    }
    for (const control of baseline.requirements ?? []) {
      if (options.limit && options.limit > 0 && matches.length >= options.limit && !options.count) {
        return matches;
      }

      const status = options.statusOf ? options.statusOf(control) : '';
      const severity = impactToSeverity(control.impact);

      if (!applyFilters(control, status, severity, filters)) {
        continue;
      }

      matches.push({
        id: control.id,
        title: control.title ?? '',
        status,
        impact: control.impact,
        severity,
        baseline: baseline.name,
      });
    }
  }
  return matches;
}

function buildFilters(options: FilterOptions): FilterFunc[] {
  const filters: FilterFunc[] = [];

  if (options.status && options.status.length > 0) {
    const statuses = options.status.map((s) => s.toLowerCase());
    filters.push((_c, s) => statuses.includes(s.toLowerCase()));
  }

  if (options.severity && options.severity.length > 0) {
    const severities = options.severity.map((s) => s.toLowerCase());
    filters.push((_c, _s, severity) => severities.includes(severity));
  }

  if (options.impact) {
    const [op, val] = parseImpactFilter(options.impact);
    filters.push((c) => compareImpact(c.impact, op, val));
  }

  if (options.cci && options.cci.length > 0) {
    const ccis = options.cci.map((c) => c.toUpperCase());
    filters.push((c) => ccis.some((cci) => tagContains(c.tags, 'cci', cci)));
  }

  if (options.nist && options.nist.length > 0) {
    const nist = options.nist;
    filters.push((c) => nist.some((n) => tagMatchesGlob(c.tags, 'nist', n)));
  }

  if (options.id) {
    const id = options.id;
    filters.push(
      (c) =>
        tagContains(c.tags, 'stig_id', id) ||
        tagContains(c.tags, 'gid', id) ||
        tagContains(c.tags, 'gtitle', id) ||
        c.id === id,
    );
  }

  if (options.tag && options.tag.length > 0) {
    const tagFilters: { key: string; value: string }[] = [];
    for (const t of options.tag) {
      const idx = t.indexOf(':');
      if (idx >= 0) {
        tagFilters.push({ key: t.slice(0, idx), value: t.slice(idx + 1) });
      }
    }
    if (tagFilters.length > 0) {
      filters.push((c) => tagFilters.some((tf) => tagMatchesGlob(c.tags, tf.key, tf.value)));
    }
  }

  if (options.search) {
    const search = options.search.toLowerCase();
    filters.push((c) => {
      if (c.id.toLowerCase().includes(search)) return true;
      if (c.title && c.title.toLowerCase().includes(search)) return true;
      for (const desc of c.descriptions ?? []) {
        if (desc.data.toLowerCase().includes(search)) return true;
      }
      return false;
    });
  }

  return filters;
}

function applyFilters(
  control: EvaluatedRequirement,
  status: string,
  severity: string,
  filters: FilterFunc[],
): boolean {
  return filters.every((f) => f(control, status, severity));
}

export function parseImpactFilter(f: string): [string, number] {
  const trimmed = f.trim();
  for (const op of ['>=', '<=', '>', '<', '=']) {
    if (trimmed.startsWith(op)) {
      const rest = trimmed.slice(op.length).trim();
      const v = rest === '' ? NaN : Number(rest);
      return Number.isNaN(v) ? ['=', 0] : [op, v];
    }
  }
  const v = trimmed === '' ? NaN : Number(trimmed);
  return Number.isNaN(v) ? ['=', 0] : ['=', v];
}

export function compareImpact(impact: number, op: string, val: number): boolean {
  switch (op) {
    case '>':
      return impact > val;
    case '>=':
      return impact >= val;
    case '<':
      return impact < val;
    case '<=':
      return impact <= val;
    case '=':
      return impact === val;
    default:
      return false;
  }
}

export function tagContains(tags: Record<string, unknown>, key: string, value: string): boolean {
  const tagVal = tags?.[key];
  if (tagVal === undefined) {
    return false;
  }
  const want = value.toLowerCase();
  if (typeof tagVal === 'string') {
    return tagVal.toLowerCase() === want;
  }
  if (Array.isArray(tagVal)) {
    return tagVal.some((item) => typeof item === 'string' && item.toLowerCase() === want);
  }
  return false;
}

export function tagMatchesGlob(tags: Record<string, unknown>, key: string, pattern: string): boolean {
  const tagVal = tags?.[key];
  if (tagVal === undefined) {
    return false;
  }
  if (typeof tagVal === 'string') {
    return safeGlobMatch(tagVal, pattern);
  }
  if (Array.isArray(tagVal)) {
    return tagVal.some((item) => typeof item === 'string' && safeGlobMatch(item, pattern));
  }
  return false;
}

/** matchesGlob reports whether s matches the glob pattern (case-insensitive). */
export function matchesGlob(s: string, pattern: string): boolean {
  return safeGlobMatch(s, pattern);
}
