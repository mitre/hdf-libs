import {
  computeEffectiveChecksum,
  computeEffectiveImpact,
  type EffectiveChecksum,
} from './effective-checksum.js';
import { computeEffectiveStatus, classifyChangeReasons, classifyDiffStatus } from './status.js';
import type { ChangeReason } from './types.js';

/**
 * The reconciler's per-key last-value state (ADR-0005 §1): the minimal
 * posture a producer compares against to decide whether a requirement moved.
 * Go parity: KeyState in hdf-diff/go/change_event.go.
 */
export interface KeyState {
  effectiveStatus: string;
  effectiveImpact: number;
  checksum: EffectiveChecksum;
}

/**
 * Caller-injected envelope identity for an emitted event. Everything is
 * supplied by the caller — the kernel touches no wall clock and no RNG, so
 * identical inputs always produce identical events. referenceTimestamp
 * anchors override expiry (pass the new document's timestamp); timestamp is
 * the event's occurrence time (RFC 3339, trimmed UTC).
 */
export interface EventInputs {
  eventId: string;
  source: string;
  sequence: number;
  systemRef: string;
  componentId: string;
  requirementId: string;
  timestamp: string;
  referenceTimestamp: string;
  /** Prior observation's timestamp — enables overrideExpired detection across the window. */
  prevReferenceTimestamp?: string;
  schemaRef?: string;
}

/** Batch ChangeReason → event-vocabulary mapping; unmapped reasons are batch-only. */
const EVENT_REASON_FOR: Partial<Record<ChangeReason, string>> = {
  resultChanged: 'resultChanged',
  overrideAdded: 'overrideAdded',
  overrideExpired: 'overrideExpired',
  overrideRemoved: 'overrideRemoved',
  impactChanged: 'impactChanged',
  effectiveImpactChanged: 'impactChanged',
};

function classifyEventReasons(
  prev: KeyState,
  newReq: Record<string, unknown>,
  prevReq: Record<string, unknown> | null,
  inputs: EventInputs,
): string[] {
  const reasons: string[] = [];
  const add = (r: string | undefined): void => {
    if (r && !reasons.includes(r)) reasons.push(r);
  };

  if (prevReq) {
    const prevRef = inputs.prevReferenceTimestamp ?? inputs.referenceTimestamp;
    for (const r of classifyChangeReasons(prevReq, newReq, prevRef, inputs.referenceTimestamp)) {
      add(EVENT_REASON_FOR[r]);
    }
    return reasons;
  }

  if (computeEffectiveImpact(newReq, inputs.referenceTimestamp) !== prev.effectiveImpact) {
    add('impactChanged');
  }
  return reasons;
}

/**
 * The pure detection kernel (ADR-0005): compare a requirement's resolved
 * posture against the stored last-value state and emit a
 * Requirement_Change_Event when it moved, or null when it did not.
 *
 * - prev null      → state "new" (chain start: null before/priorChecksum)
 * - newReq null    → state "absent" (after null, thin before preserved)
 * - checksum match → null (no event; the steady-state majority)
 * - otherwise      → fixed/regressed/updated per the effective-status
 *   transition, with the full after requirement as payload
 *
 * prevReq (optional) is the full prior requirement when the caller's
 * materialized state has it; it enables complete changeReasons
 * classification via the batch classifier, filtered to the event
 * vocabulary. Without it, only reasons provable from the thin state
 * (impactChanged) are emitted. Byte-parity with the Go kernel
 * (ChangeEventFromPrevious) is pinned by shared test vectors.
 */
export async function changeEventFromPrevious(
  prev: KeyState | null,
  newReq: Record<string, unknown> | null,
  prevReq: Record<string, unknown> | null,
  inputs: EventInputs,
): Promise<Record<string, unknown> | null> {
  if (!prev && !newReq) {
    return null;
  }

  const envelope: Record<string, unknown> = {
    eventId: inputs.eventId,
    source: inputs.source,
    sequence: inputs.sequence,
    systemRef: inputs.systemRef,
    componentId: inputs.componentId,
    requirementId: inputs.requirementId,
    timestamp: inputs.timestamp,
    ...(inputs.schemaRef !== undefined ? { schemaRef: inputs.schemaRef } : {}),
  };

  if (!prev) {
    return { ...envelope, priorChecksum: null, state: 'new', before: null, after: newReq };
  }

  const before = {
    effectiveStatus: prev.effectiveStatus,
    effectiveImpact: prev.effectiveImpact,
  };

  if (!newReq) {
    return {
      ...envelope,
      priorChecksum: { ...prev.checksum },
      state: 'absent',
      before,
      after: null,
    };
  }

  const newChecksum = await computeEffectiveChecksum(newReq, inputs.referenceTimestamp);
  if (newChecksum.value === prev.checksum.value) {
    return null;
  }

  const newStatus = computeEffectiveStatus(newReq, inputs.referenceTimestamp);
  const transition = classifyDiffStatus(prev.effectiveStatus, newStatus);
  // Status unchanged but the checksum moved: impact or disposition shifted.
  const state = transition === 'fixed' || transition === 'regressed' ? transition : 'updated';

  const changeReasons = classifyEventReasons(prev, newReq, prevReq, inputs);
  return {
    ...envelope,
    priorChecksum: { ...prev.checksum },
    state,
    ...(changeReasons.length > 0 ? { changeReasons } : {}),
    before,
    after: newReq,
  };
}
