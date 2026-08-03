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
// baseline, scanner, target — cross-corpus context) return "".
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
	default:
		return ""
	}
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
// requirement's resolved posture against the stored last-value state and emit
// a Requirement_Change_Event when it moved, or nil when it did not.
//
//   - prev == nil        → state "new" (chain start: null before/priorChecksum)
//   - newReq == nil      → state "absent" (after null, thin before preserved)
//   - checksums match    → nil (no event; the steady-state majority)
//   - otherwise          → fixed/regressed/updated per the effective-status
//     transition, with the full after requirement as payload
//
// prevReq (optional) is the full prior requirement when the caller's
// materialized state has it; it enables complete changeReasons classification
// via the batch classifier, filtered to the event vocabulary. Without it,
// only reasons provable from the thin state (impactChanged) are emitted.
func ChangeEventFromPrevious(
	prev *KeyState,
	newReq *hdf.EvaluatedRequirement,
	prevReq *hdf.EvaluatedRequirement,
	in EventInputs,
) *hdf.HDFRequirementChangeEvent {
	if prev == nil && newReq == nil {
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
		ev.After = newReq
		return ev
	}

	ev.PriorChecksum = checksumMap(prev.Checksum)
	before := map[string]interface{}{
		"effectiveStatus": prev.EffectiveStatus,
		"effectiveImpact": prev.EffectiveImpact,
	}

	if newReq == nil {
		ev.State = hdf.EventRequirementStateAbsent
		ev.Before = before
		return ev
	}

	newChecksum := ComputeEffectiveChecksum(*newReq, in.ReferenceTimestamp)
	if newChecksum == nil || newChecksum.Value == prev.Checksum.Value {
		return nil
	}

	newStatus := ComputeEffectiveStatus(*newReq, in.ReferenceTimestamp)
	switch ClassifyDiffStatus(prev.EffectiveStatus, newStatus) {
	case StateFixed:
		ev.State = hdf.EventRequirementStateFixed
	case StateRegressed:
		ev.State = hdf.EventRequirementStateRegressed
	default:
		// Status unchanged but the checksum moved: impact or disposition shifted.
		ev.State = hdf.EventRequirementStateUpdated
	}

	ev.Before = before
	ev.After = newReq
	ev.ChangeReasons = classifyEventReasons(prev, newReq, prevReq, in)
	return ev
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
