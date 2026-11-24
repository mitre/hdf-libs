// Package push holds the target-agnostic half of pushing an evidence package to
// a GRC system of record: it reads a target's current state, diffs the package
// against it, decides create, update or skip per entity, and records a receipt.
//
// No identifier, field name or endpoint of any particular system appears here. A
// second target is an adapter, not a rewrite.
package push

import "time"

// EntityKind names a class of record a target holds. The kinds are the ones an
// evidence package can speak to, not any one system's schema names.
type EntityKind string

const (
	KindTestResult EntityKind = "test-result"
	KindPOAM       EntityKind = "poam"
	KindMilestone  EntityKind = "milestone"
	KindArtifact   EntityKind = "artifact"
)

// Entity is one record, in the shape the adapter chose. Content is compared for
// equality and is otherwise opaque: the reconciler never interprets its keys, so
// a target's field names stay inside its adapter.
type Entity struct {
	Kind EntityKind
	// Key is the natural key the adapter derives, unique within a Kind.
	Key string
	// Source is the HDF location this came from, carried into the receipt so a
	// reader can trace a remote record back to the document that produced it.
	Source string
	// Content is the adapter-shaped payload. Nil on a remote entity the adapter
	// could not read back in comparable form, which makes the entity
	// indeterminate rather than unchanged.
	Content map[string]any

	// ID and CreatedAt are set on remote entities only. CreatedAt drives
	// conflict layer 2 and is zero when the target does not report one.
	ID        string
	CreatedAt time.Time
}

// Desired is the package side of the diff.
type Desired struct {
	// PreparedAt is when the evidence package was prepared. A remote record
	// created after it cannot be one this package knows about.
	PreparedAt time.Time
	Entities   []Entity
	// Prior is the receipt from the last push, when the caller kept one. It is
	// conflict layer 3 and is always optional: nil loses that layer and nothing
	// else.
	Prior *Receipt
}

// Action is what the plan decided for one entity.
type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	// ActionSkipUnchanged means the target already carries what we would write.
	ActionSkipUnchanged Action = "skip-unchanged"
	// ActionSkipConflicted means a layer found the remote record newer than the
	// package, and the policy chose to leave it alone.
	ActionSkipConflicted Action = "skip-conflicted"
)

// Step is one entity's decision, with the reason a reader needs to audit it.
type Step struct {
	Entity Entity
	Action Action
	Reason string
	// RemoteID is the id of the record this step would update, when there is one.
	RemoteID string
	// Ambiguous records that no conflict layer could decide this entity, so the
	// permissive default applied and the step writes. Reported, never hidden.
	Ambiguous bool
}

// Writes reports whether a step sends anything to the target.
func (s Step) Writes() bool { return s.Action == ActionCreate || s.Action == ActionUpdate }

// Plan is the whole decision, inspectable before anything is sent.
type Plan struct {
	Steps []Step
}

// Writes returns only the steps that would send something.
func (p Plan) Writes() []Step {
	var out []Step
	for _, step := range p.Steps {
		if step.Writes() {
			out = append(out, step)
		}
	}
	return out
}

// NothingToDo reports a plan that would send nothing, which the CLI surfaces as
// its own exit code rather than as success with no output.
func (p Plan) NothingToDo() bool { return len(p.Writes()) == 0 }

// Ambiguous returns the steps that wrote because no layer could decide.
func (p Plan) Ambiguous() []Step {
	var out []Step
	for _, step := range p.Steps {
		if step.Ambiguous {
			out = append(out, step)
		}
	}
	return out
}

// Policy selects what to do with an entity a conflict layer flagged.
type Policy struct {
	OnConflict ConflictPolicy
}

// ConflictPolicy is the --on-conflict vocabulary. The zero value is skip, so a
// caller who configures nothing gets the remote-wins default.
type ConflictPolicy string

const (
	ConflictSkip      ConflictPolicy = "skip"
	ConflictOverwrite ConflictPolicy = "overwrite"
	ConflictFail      ConflictPolicy = "fail"
)
