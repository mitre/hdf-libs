package push

import "time"

// ReceiptVersion is the receipt schema's version. A receipt is a durable
// artifact other tools parse and the next push reads back as conflict layer 3,
// so it carries a version from its first release rather than acquiring one once
// the format has already changed under someone.
const ReceiptVersion = 1

// Outcome is what actually happened to one entity, as distinct from what the
// plan intended.
type Outcome string

const (
	OutcomeCreated          Outcome = "created"
	OutcomeUpdated          Outcome = "updated"
	OutcomeSkippedUnchanged Outcome = "skipped-unchanged"
	// OutcomeSkippedConflicted is a conflict layer's decision that the remote wins.
	OutcomeSkippedConflicted Outcome = "skipped-conflicted"
	// OutcomeSkippedUnverifiable is a requirement whose posture the package
	// cannot assert, so nothing is written and the staleness is reported.
	OutcomeSkippedUnverifiable Outcome = "skipped-unverifiable"
	OutcomeFailed              Outcome = "failed"
	// OutcomePlanned is an entity the plan intended to write that no execution
	// has reached yet. A receipt emitted after an abort still names it.
	OutcomePlanned Outcome = "planned"
)

// PackageRef identifies the evidence package a push came from.
type PackageRef struct {
	Name      string `json:"name"`
	Integrity string `json:"integrity,omitempty"`
}

// Entry is one entity's audit row.
type Entry struct {
	Kind     EntityKind `json:"kind"`
	Key      string     `json:"key"`
	Source   string     `json:"source,omitempty"`
	Outcome  Outcome    `json:"outcome"`
	RemoteID string     `json:"remoteId,omitempty"`
	// RemoteState is what the target was observed to hold after this push, and
	// is empty where nothing was observed. The next push reads it as conflict
	// layer 3, the only way to notice an in-place edit of a record that already
	// existed when the package was prepared.
	RemoteState map[string]any `json:"remoteState,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	Error       string         `json:"error,omitempty"`
	Ambiguous   bool           `json:"ambiguous,omitempty"`
}

// Receipt is the one audit row per push that ADR-0013 requires, written on
// failure as well as success because a partial push's receipt is the only
// recovery record.
type Receipt struct {
	Version   int        `json:"version"`
	Package   PackageRef `json:"package"`
	Target    string     `json:"target"`
	SystemID  string     `json:"systemId"`
	StartedAt time.Time  `json:"startedAt,omitempty"`
	Entries   []Entry    `json:"entries"`
}

// NewReceipt seeds a receipt from a plan, so an abort before the first write
// still produces a record naming everything the plan intended.
func NewReceipt(pkg PackageRef, target, systemID string, plan Plan) *Receipt {
	r := &Receipt{
		Version:  ReceiptVersion,
		Package:  pkg,
		Target:   target,
		SystemID: systemID,
		Entries:  make([]Entry, 0, len(plan.Steps)),
	}
	for _, step := range plan.Steps {
		entry := Entry{
			Kind:      step.Entity.Kind,
			Key:       step.Entity.Key,
			Source:    step.Entity.Source,
			Outcome:   plannedOutcome(step.Action),
			RemoteID:  step.RemoteID,
			Reason:    step.Reason,
			Ambiguous: step.Ambiguous,
		}
		// RemoteState is only ever what the target was observed to hold. A
		// skip-unchanged observed it, by definition: content equality is how the
		// step was decided. Everything else waits for a write to report it, so a
		// receipt from a failed push never claims the target holds what was
		// never sent.
		if step.Action == ActionSkipUnchanged {
			entry.RemoteState = step.Entity.Content
		}
		r.Entries = append(r.Entries, entry)
	}
	return r
}

// plannedOutcome is the outcome a step has before anything is sent. A skip is
// already final; a write is only planned.
func plannedOutcome(a Action) Outcome {
	switch a {
	case ActionSkipUnchanged:
		return OutcomeSkippedUnchanged
	case ActionSkipConflicted:
		return OutcomeSkippedConflicted
	case ActionCreate, ActionUpdate:
		return OutcomePlanned
	default:
		return OutcomePlanned
	}
}

// Record sets what actually happened to one entity, identified by kind and key
// because two kinds may share a natural key. RemoteState is what the target was
// observed to hold afterwards and must be left nil when nothing was observed;
// err is recorded rather than returned, because a failure must appear in the
// receipt instead of discarding it.
func (r *Receipt) Record(kind EntityKind, key string, outcome Outcome, remoteID string, remoteState map[string]any, err error) {
	for i := range r.Entries {
		if r.Entries[i].Kind != kind || r.Entries[i].Key != key {
			continue
		}
		r.Entries[i].Outcome = outcome
		if remoteID != "" {
			r.Entries[i].RemoteID = remoteID
		}
		if remoteState != nil {
			r.Entries[i].RemoteState = remoteState
		}
		if err != nil {
			r.Entries[i].Error = err.Error()
		}
		return
	}
}

// Lookup finds an entry by kind and key. Two kinds may share a key, so both are
// needed to identify one.
func (r *Receipt) Lookup(kind EntityKind, key string) *Entry {
	for i := range r.Entries {
		if r.Entries[i].Kind == kind && r.Entries[i].Key == key {
			return &r.Entries[i]
		}
	}
	return nil
}

// Partial reports a push where something wrote and something failed, which the
// CLI distinguishes from total failure because the caller's recovery differs.
func (r *Receipt) Partial() bool {
	var wrote, failed bool
	for _, e := range r.Entries {
		switch e.Outcome {
		case OutcomeCreated, OutcomeUpdated:
			wrote = true
		case OutcomeFailed:
			failed = true
		case OutcomeSkippedUnchanged, OutcomeSkippedConflicted, OutcomeSkippedUnverifiable, OutcomePlanned:
			// Neither written nor failed, so this is not a partial push.
		}
	}
	return wrote && failed
}

// stateOf returns what the last push observed on the target for one entity, or
// nil when there is no receipt, no entry, or an outcome under which nothing was
// observed. A nil receiver is the no-receipt case, so callers need no guard.
//
// Only an observed outcome is evidence for conflict layer 3. A failed or
// unattempted write saw nothing, and a conflicted skip recorded our content
// rather than the target's, so treating either as a baseline would make the next
// push blame a phantom edit.
func (r *Receipt) stateOf(kind EntityKind, key string) map[string]any {
	if r == nil {
		return nil
	}
	entry := r.Lookup(kind, key)
	if entry == nil {
		return nil
	}
	switch entry.Outcome {
	case OutcomeCreated, OutcomeUpdated, OutcomeSkippedUnchanged:
		return entry.RemoteState
	case OutcomeFailed, OutcomePlanned, OutcomeSkippedConflicted, OutcomeSkippedUnverifiable:
		return nil
	default:
		return nil
	}
}
