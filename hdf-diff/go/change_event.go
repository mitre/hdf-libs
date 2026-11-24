package diff

import (
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// KeyState is the reconciler's per-key last-value state (ADR-0005 §1):
// the minimal posture a producer compares against to decide whether a
// requirement moved.
type KeyState struct {
	EffectiveStatus string
	EffectiveImpact float64
	Checksum        hdf.Checksum
}

// EventInputs carries the caller-injected envelope identity for an emitted
// event. Everything is supplied by the caller — the kernel touches no wall
// clock and no RNG, so identical inputs always produce identical events.
// ReferenceTimestamp anchors override expiry (pass the new document's
// timestamp); PrevReferenceTimestamp is the prior observation's timestamp
// (enables overrideExpired detection across the observation window; falls
// back to ReferenceTimestamp when empty); Timestamp is the event's
// occurrence time.
type EventInputs struct {
	EventID                string
	Source                 string
	Sequence               int64
	SystemRef              string
	ComponentID            string
	RequirementID          string
	Timestamp              time.Time
	ReferenceTimestamp     string
	PrevReferenceTimestamp string
	SchemaRef              string
}

// eventReasonFor maps a batch ChangeReason onto the event vocabulary's
// producer-computable subset. Reasons with no event equivalent (metadata,
// baseline, scanner, target — cross-corpus context — and disposition) return "",
// as do overrideModified and configChanged, which the event vocabulary carries
// but this mapping does not yet emit.
func eventReasonFor(reason ChangeReason) hdf.EventChangeReason {
	switch reason {
	case ReasonResultChanged:
		return hdf.EventChangeReasonResultChanged
	case ReasonOverrideAdded:
		return hdf.EventChangeReasonOverrideAdded
	case ReasonOverrideExpired:
		return hdf.EventChangeReasonOverrideExpired
	case ReasonOverrideRemoved:
		return hdf.EventChangeReasonOverrideRemoved
	case ReasonImpactChanged, ReasonEffectiveImpactChanged:
		return hdf.EventChangeReasonImpactChanged
	case ReasonOverrideModified, ReasonConfigChanged, ReasonDispositionChanged,
		ReasonBaselineUpgraded, ReasonControlMapped, ReasonScannerChanged,
		ReasonTargetChanged, ReasonMetadataChanged:
	}
	return ""
}

// checksumMap renders a Checksum as the map shape the generated event type's
// interface{} field marshals to the wire format.
func checksumMap(cs hdf.Checksum) map[string]interface{} {
	return map[string]interface{}{
		"algorithm": string(cs.Algorithm),
		"value":     cs.Value,
	}
}

// ChangeEventFromPrevious is the pure detection kernel (ADR-0005): compare a
// requirement's resolved posture against the stored last-value state and emit a
// Requirement_Change_Event when it moved, or nil when it did not.
//
//   - prev == nil      → state "new" (chain start: null before/priorChecksum)
//   - no newReqs       → state "absent" (after null, thin before preserved)
//   - checksums match  → nil (no event; the steady-state majority)
//   - otherwise        → fixed/regressed/updated per the effective-status
//     transition, carrying every entry of the id as payload
//
// newReqs and prevReqs are EVERY entry the id carries on each side, because an id
// names the requirement rather than the finding. Their posture is folded by
// FoldEffectiveState, and after[] carries them all, which is what lets a replay
// reconstruct the document.
//
// prevReqs (optional) is the full prior state when the caller's materialized state
// has it; it enables complete changeReasons classification via the batch classifier,
// filtered to the event vocabulary. Without it, only reasons provable from the thin
// state are emitted.
func ChangeEventFromPrevious(
	prev *KeyState,
	newReqs []hdf.EvaluatedRequirement,
	prevReqs []hdf.EvaluatedRequirement,
	in EventInputs,
) *hdf.HDFRequirementChangeEvent {
	if prev == nil && len(newReqs) == 0 {
		return nil
	}

	ev := &hdf.HDFRequirementChangeEvent{
		EventID:       in.EventID,
		Source:        in.Source,
		Sequence:      in.Sequence,
		SystemRef:     in.SystemRef,
		ComponentID:   in.ComponentID,
		RequirementID: in.RequirementID,
		Timestamp:     in.Timestamp,
	}
	if in.SchemaRef != "" {
		ev.SchemaRef = &in.SchemaRef
	}

	if prev == nil {
		ev.State = hdf.EventRequirementStateNew
		ev.After = newReqs
		return ev
	}

	ev.PriorChecksum = checksumMap(prev.Checksum)
	before := map[string]interface{}{
		"effectiveStatus": prev.EffectiveStatus,
		"effectiveImpact": prev.EffectiveImpact,
	}

	if len(newReqs) == 0 {
		ev.State = hdf.EventRequirementStateAbsent
		ev.Before = before
		return ev
	}

	newState := FoldEffectiveState(newReqs, in.ReferenceTimestamp)
	if newState == nil || newState.Checksum.Value == prev.Checksum.Value {
		return nil
	}

	switch ClassifyDiffStatus(prev.EffectiveStatus, newState.EffectiveStatus) {
	case StateFixed:
		ev.State = hdf.EventRequirementStateFixed
	case StateRegressed:
		ev.State = hdf.EventRequirementStateRegressed
	case StateUnchanged, StateUpdated, StateNew, StateAbsent,
		StateMoved, StateSplit, StateMerged:
		// ClassifyDiffStatus only yields unchanged/fixed/regressed/updated, and the
		// checksum already moved, so "unchanged" here means impact or disposition did.
		ev.State = hdf.EventRequirementStateUpdated
	}

	ev.Before = before
	ev.After = newReqs
	ev.ChangeReasons = foldEventReasons(prev, newReqs, prevReqs, in)
	return ev
}

// foldEventReasons unions the reasons over the id's entries, paired by position. The
// event is about the requirement, so a reason any entry shows is a reason the
// requirement moved. For the single-entry case — every document without a repeated id —
// this is exactly classifyEventReasons on that one pair.
func foldEventReasons(
	prev *KeyState,
	newReqs []hdf.EvaluatedRequirement,
	prevReqs []hdf.EvaluatedRequirement,
	in EventInputs,
) []hdf.EventChangeReason {
	var reasons []hdf.EventChangeReason
	seen := map[hdf.EventChangeReason]bool{}
	for i := range newReqs {
		var prevReq *hdf.EvaluatedRequirement
		if i < len(prevReqs) {
			prevReq = &prevReqs[i]
		}
		for _, r := range classifyEventReasons(prev, &newReqs[i], prevReq, in) {
			if !seen[r] {
				seen[r] = true
				reasons = append(reasons, r)
			}
		}
	}
	return reasons
}

// classifyEventReasons produces the event-vocabulary changeReasons. With the
// full prior requirement it delegates to the batch classifier and filters;
// with only thin state it emits what the thin comparison can prove.
func classifyEventReasons(
	prev *KeyState,
	newReq *hdf.EvaluatedRequirement,
	prevReq *hdf.EvaluatedRequirement,
	in EventInputs,
) []hdf.EventChangeReason {
	var reasons []hdf.EventChangeReason
	seen := map[hdf.EventChangeReason]bool{}
	add := func(r hdf.EventChangeReason) {
		if r != "" && !seen[r] {
			seen[r] = true
			reasons = append(reasons, r)
		}
	}

	if prevReq != nil {
		prevRef := in.PrevReferenceTimestamp
		if prevRef == "" {
			prevRef = in.ReferenceTimestamp
		}
		for _, r := range ClassifyChangeReasons(*prevReq, *newReq, prevRef, in.ReferenceTimestamp) {
			add(eventReasonFor(r))
		}
		return reasons
	}

	if ComputeEffectiveImpact(*newReq, in.ReferenceTimestamp) != prev.EffectiveImpact {
		add(hdf.EventChangeReasonImpactChanged)
	}
	return reasons
}
