import { computeEffectiveStatus as canonicalEffectiveStatus, parseTimestamp } from '@mitre/hdf-utilities';
import type { ChangeReason, RequirementState } from './types.js';

/** Statuses that count as "passing" for fixed/regressed classification */
const PASSING_STATUSES = new Set(['passed']);

/** Statuses that count as "failing" for fixed/regressed classification */
const FAILING_STATUSES = new Set(['failed', 'error', 'notReviewed']);

interface ResultLike {
  status: string;
}

interface OverrideLike {
  status?: string;
  appliedAt?: string;
  expiresAt: string;
}

/**
 * Determine the effective status of a requirement from its results and
 * overrides, delegating to the canonical shared implementation in
 * `@mitre/hdf-utilities` (see status-determination.md):
 *
 * 1. impact === 0 → notApplicable (regardless of results)
 * 2. the governing (most recent non-expired) status override's status
 * 3. effectiveStatus field set (and no statusOverrides) → use it
 * 4. Aggregate results using worst-wins
 * 5. Empty results → notReviewed
 */
export function computeEffectiveStatus(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): string {
  const results = (requirement['results'] as ResultLike[] | undefined) ?? [];
  const overrides = (requirement['statusOverrides'] as OverrideLike[] | undefined) ?? [];
  return canonicalEffectiveStatus(
    {
      // A missing impact must not read as 0 (which would force notApplicable).
      impact: (requirement['impact'] as number | undefined) ?? Number.NaN,
      effectiveStatus: requirement['effectiveStatus'] as string | undefined,
      resultStatuses: results.map((r) => r.status),
      overrides: overrides.map((o) => ({
        status: o.status,
        appliedAt: o.appliedAt,
        expiresAt: o.expiresAt,
      })),
    },
    referenceTimestamp,
  );
}

/**
 * Classify why the status changed between two requirements.
 * Returns an array of change reasons (a status change can have multiple causes).
 */
export function classifyChangeReasons(
  oldReq: Record<string, unknown>,
  newReq: Record<string, unknown>,
  oldTimestamp?: string,
  newTimestamp?: string,
): ChangeReason[] {
  const reasons: ChangeReason[] = [];

  // Check result status changes
  const oldResults = (oldReq['results'] as ResultLike[] | undefined) ?? [];
  const newResults = (newReq['results'] as ResultLike[] | undefined) ?? [];
  const oldResultStatuses = oldResults.map((r) => r.status).sort();
  const newResultStatuses = newResults.map((r) => r.status).sort();
  if (JSON.stringify(oldResultStatuses) !== JSON.stringify(newResultStatuses)) {
    reasons.push('resultChanged');
  }

  // Check override changes
  const oldOverrides = (oldReq['statusOverrides'] as OverrideLike[] | undefined) ?? [];
  const newOverrides = (newReq['statusOverrides'] as OverrideLike[] | undefined) ?? [];

  if (newOverrides.length > oldOverrides.length) {
    reasons.push('overrideAdded');
  } else if (newOverrides.length < oldOverrides.length) {
    reasons.push('overrideRemoved');
  }

  // Check for override expiration between scans. parseTimestamp keeps
  // zone-less scan timestamps host-independent (repo timestamp convention);
  // null means unparseable, so the check is skipped.
  if (oldTimestamp && newTimestamp && oldOverrides.length > 0) {
    const oldTime = parseTimestamp(oldTimestamp)?.getTime();
    const newTime = parseTimestamp(newTimestamp)?.getTime();
    if (oldTime !== undefined && newTime !== undefined) {
      for (const override of oldOverrides) {
        const expiresAt = parseTimestamp(override.expiresAt)?.getTime();
        if (expiresAt !== undefined && expiresAt > oldTime && expiresAt <= newTime) {
          reasons.push('overrideExpired');
          break; // Only report once
        }
      }
    }
  }

  // Check impact changes
  const oldImpact = oldReq['impact'] as number | undefined;
  const newImpact = newReq['impact'] as number | undefined;
  if (oldImpact !== newImpact) {
    reasons.push('impactChanged');
  }

  // Check disposition changes
  const oldDisposition = oldReq['disposition'] as string | undefined;
  const newDisposition = newReq['disposition'] as string | undefined;
  if (oldDisposition !== newDisposition) {
    reasons.push('dispositionChanged');
  }

  // Check effectiveImpact changes
  const oldEffectiveImpact = oldReq['effectiveImpact'] as number | undefined;
  const newEffectiveImpact = newReq['effectiveImpact'] as number | undefined;
  if (oldEffectiveImpact !== newEffectiveImpact) {
    reasons.push('effectiveImpactChanged');
  }

  // Check baseline metadata changes (tags, descriptions, title)
  const oldTags = JSON.stringify(oldReq['tags'] ?? {});
  const newTags = JSON.stringify(newReq['tags'] ?? {});
  const oldDescs = JSON.stringify(oldReq['descriptions'] ?? []);
  const newDescs = JSON.stringify(newReq['descriptions'] ?? []);
  const oldTitle = oldReq['title'] as string | undefined;
  const newTitle = newReq['title'] as string | undefined;

  if (oldTags !== newTags || oldDescs !== newDescs || oldTitle !== newTitle) {
    reasons.push('metadataChanged');
  }

  return reasons;
}

/**
 * Classify the overall diff status based on old and new effective statuses.
 *
 * - If old is failing and new is passing → 'fixed'
 * - If old is passing and new is failing → 'regressed'
 * - If statuses are equal → 'unchanged'
 * - Otherwise → 'updated'
 */
export function classifyDiffStatus(
  oldEffectiveStatus: string,
  newEffectiveStatus: string,
): RequirementState {
  if (oldEffectiveStatus === newEffectiveStatus) {
    return 'unchanged';
  }

  const oldIsFailing = FAILING_STATUSES.has(oldEffectiveStatus);
  const newIsPassing = PASSING_STATUSES.has(newEffectiveStatus);
  const oldIsPassing = PASSING_STATUSES.has(oldEffectiveStatus);
  const newIsFailing = FAILING_STATUSES.has(newEffectiveStatus);

  if (oldIsFailing && newIsPassing) {
    return 'fixed';
  }
  if (oldIsPassing && newIsFailing) {
    return 'regressed';
  }

  return 'updated';
}
