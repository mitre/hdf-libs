import type { ChangeReason, RequirementState } from './types.js';

/** Status severity ranking — higher index = worse */
const STATUS_SEVERITY: readonly string[] = [
  'notApplicable',
  'notReviewed',
  'passed',
  'failed',
  'error',
];

/** Statuses that count as "passing" for fixed/regressed classification */
const PASSING_STATUSES = new Set(['passed']);

/** Statuses that count as "failing" for fixed/regressed classification */
const FAILING_STATUSES = new Set(['failed', 'error', 'notReviewed']);

interface ResultLike {
  status: string;
}

interface OverrideLike {
  status?: string;
  expiresAt: string;
}

/**
 * Determine the effective status of a requirement from its results and overrides.
 *
 * Priority:
 * 1. impact === 0 → notApplicable (regardless of results)
 * 2. effectiveStatus field set (and no statusOverrides) → use it
 * 3. Non-expired statusOverrides → use first non-expired
 * 4. Aggregate results using worst-wins
 * 5. Empty results → notReviewed
 */
export function computeEffectiveStatus(
  requirement: Record<string, unknown>,
  referenceTimestamp?: string,
): string {
  const impact = requirement['impact'] as number | undefined;
  if (impact === 0) {
    return 'notApplicable';
  }

  const overrides = requirement['statusOverrides'] as OverrideLike[] | undefined;
  if (overrides && overrides.length > 0) {
    const refTime = referenceTimestamp ? new Date(referenceTimestamp).getTime() : Date.now();
    for (const override of overrides) {
      const expiresAt = new Date(override.expiresAt).getTime();
      if (expiresAt > refTime && override.status) {
        return override.status;
      }
    }
    // All overrides expired — fall through to results
  }

  // If effectiveStatus is set and there are no overrides, use it
  const effectiveStatus = requirement['effectiveStatus'] as string | undefined;
  if (effectiveStatus && (!overrides || overrides.length === 0)) {
    return effectiveStatus;
  }

  const results = requirement['results'] as ResultLike[] | undefined;
  if (!results || results.length === 0) {
    return 'notReviewed';
  }

  // Worst-wins: find the status with the highest severity index
  let worstIndex = -1;
  let worstStatus = 'notReviewed';
  for (const result of results) {
    const idx = STATUS_SEVERITY.indexOf(result.status);
    if (idx > worstIndex) {
      worstIndex = idx;
      worstStatus = result.status;
    }
  }

  return worstStatus;
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

  // Check for override expiration between scans
  if (oldTimestamp && newTimestamp && oldOverrides.length > 0) {
    const oldTime = new Date(oldTimestamp).getTime();
    const newTime = new Date(newTimestamp).getTime();
    for (const override of oldOverrides) {
      const expiresAt = new Date(override.expiresAt).getTime();
      if (expiresAt > oldTime && expiresAt <= newTime) {
        reasons.push('overrideExpired');
        break; // Only report once
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
