package push

import (
	"fmt"
	"reflect"
)

// Reconcile diffs a package against a target's current state and returns the
// plan. It issues no writes: the plan is inspectable before anything is sent,
// which is what makes a dry run truthful and this layer testable without a
// server.
//
// Conflict detection runs in the layers ADR-0025 Decision 3 defines, each
// independent and none required. Where no layer can decide, the plan writes and
// the step is marked ambiguous — the operator asked for the push, and refusing
// every undecidable record would make the command useless on a populated system.
func Reconcile(desired Desired, remote []Entity, policy Policy) (Plan, error) {
	byKey := make(map[entityID]Entity, len(remote))
	for _, r := range remote {
		byKey[entityID{r.Kind, r.Key}] = r
	}

	// A duplicate (kind, key) cannot be audited: both entities would write, but
	// the receipt keys on that pair, so the second outcome would overwrite the
	// first and one real write would be left looking unattempted. Refusing here
	// is the pre-write check ADR-0025 Decision 6 asks for.
	seen := make(map[entityID]bool, len(desired.Entities))
	for _, want := range desired.Entities {
		id := entityID{want.Kind, want.Key}
		if seen[id] {
			return Plan{}, fmt.Errorf("two %s entities share the natural key %q; a push cannot record an outcome for either", want.Kind, want.Key)
		}
		seen[id] = true
	}

	plan := Plan{Steps: make([]Step, 0, len(desired.Entities))}
	for _, want := range desired.Entities {
		current, found := byKey[entityID{want.Kind, want.Key}]
		if !found {
			plan.Steps = append(plan.Steps, Step{
				Entity: want,
				Action: ActionCreate,
				Reason: "no record with this natural key on the target",
			})
			continue
		}

		step, err := decide(desired, want, current, policy)
		if err != nil {
			return Plan{}, err
		}
		plan.Steps = append(plan.Steps, step)
	}
	return plan, nil
}

// entityID is a natural key scoped to its kind, since two kinds may legitimately
// use the same key.
type entityID struct {
	Kind EntityKind
	Key  string
}

// decide applies the conflict layers to one entity that exists on both sides.
func decide(desired Desired, want, current Entity, policy Policy) (Step, error) {
	// Layer 1, content equality. Always available, and the only layer that can
	// report "unchanged" rather than merely "not in conflict".
	if current.Content != nil && contentEqual(want.Content, current.Content) {
		return Step{
			Entity:   want,
			Action:   ActionSkipUnchanged,
			Reason:   "the target already carries this content",
			RemoteID: current.ID,
		}, nil
	}

	// Layer 3 runs before layer 2 by decision, and the two can disagree: a
	// receipt is direct evidence of what we left, while a creation time only
	// infers authorship — wrongly, for a record our own earlier push created
	// after the package was prepared. So a receipt that matches the remote
	// CLEARS what layer 2 would flag. Direct evidence wins in both directions.
	if prior := desired.Prior.stateOf(want.Kind, want.Key); prior != nil && current.Content != nil {
		if !contentEqual(prior, current.Content) {
			return conflicted(want, current, policy,
				"edited on the target since the last push: it no longer carries what that push left")
		}
		// The remote still carries what we left, so nobody else touched it and
		// our newer content goes without ambiguity.
		return Step{
			Entity:   want,
			Action:   ActionUpdate,
			Reason:   "the target still carries what the last push left, so this update is ours to make",
			RemoteID: current.ID,
		}, nil
	}

	// Layer 2, remote creation time against the package's preparedAt. A record
	// created after the package was prepared cannot be one the package knows
	// about, so someone else created it and the remote wins.
	if !current.CreatedAt.IsZero() && !desired.PreparedAt.IsZero() && current.CreatedAt.After(desired.PreparedAt) {
		return conflicted(want, current, policy,
			fmt.Sprintf("created on the target at %s, after the package was prepared at %s",
				current.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
				desired.PreparedAt.UTC().Format("2006-01-02T15:04:05Z")))
	}

	// No layer decided. The permissive default writes, and says so.
	return Step{
		Entity:    want,
		Action:    ActionUpdate,
		Reason:    "content differs and no conflict layer could determine which side is newer",
		RemoteID:  current.ID,
		Ambiguous: true,
	}, nil
}

// conflicted turns a flagged entity into the step the policy asks for.
func conflicted(want, current Entity, policy Policy, reason string) (Step, error) {
	switch policy.OnConflict {
	case ConflictOverwrite:
		return Step{
			Entity:   want,
			Action:   ActionUpdate,
			Reason:   reason + "; overwriting because --on-conflict=overwrite",
			RemoteID: current.ID,
		}, nil
	case ConflictFail:
		return Step{}, &ConflictError{Kind: want.Kind, Key: want.Key, Reason: reason}
	// The empty string is the zero value, which means a caller who configured
	// nothing gets the remote-wins default; "skip" is the same policy spelled out.
	case ConflictSkip, "":
		return Step{
			Entity:   want,
			Action:   ActionSkipConflicted,
			Reason:   reason,
			RemoteID: current.ID,
		}, nil
	default:
		return Step{}, fmt.Errorf("unknown conflict policy %q", policy.OnConflict)
	}
}

// ConflictError aborts a plan under --on-conflict=fail, before any write.
type ConflictError struct {
	Kind   EntityKind
	Key    string
	Reason string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s %q conflicts with the target: %s", e.Kind, e.Key, e.Reason)
}

// contentEqual compares two adapter payloads. A field the adapter omits and one
// it sets to nil are the same absence, so they compare equal; anything else is a
// difference the adapter meant.
func contentEqual(want, current map[string]any) bool {
	return reflect.DeepEqual(withoutNils(want), withoutNils(current))
}

func withoutNils(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if v != nil {
			out[k] = v
		}
	}
	return out
}
