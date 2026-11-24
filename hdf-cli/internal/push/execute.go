package push

import (
	"context"
	"fmt"
	"time"
)

// Target is what a GRC adapter implements, and the minimum one: an adapter that
// implements this alone works. A target whose endpoints accept several records
// per request also implements BatchWriter, which Execute prefers when present.
// A second system is a new Target, not a change here.
//
// Read is called by whoever assembles the reconcile inputs, not by this package.
type Target interface {
	// Name identifies the target in the receipt and in output.
	Name() string
	// Read returns the target's current entities for one system. Reads are
	// expected to be unprivileged, which is what lets a dry run work for a
	// caller with no write approval.
	Read(ctx context.Context, systemID string) ([]Entity, error)
	// Write sends one step. The adapter translates the step's opaque content
	// into whatever its system requires.
	Write(ctx context.Context, step Step) (WriteResult, error)
}

// WriteResult is what the target reports back about one write.
type WriteResult struct {
	// RemoteID is the identifier the target assigned, carried into the receipt
	// so a later push can address the record.
	RemoteID string
	// RemoteState is what the target holds afterwards. The next push reads it as
	// conflict layer 3.
	RemoteState map[string]any
}

// Exit codes, the CLI's documented vocabulary. A push classifies its own outcome
// here so the number is decided in one place and tested against the receipt
// rather than assembled at the command layer.
const (
	ExitSuccess     = 0
	ExitFailure     = 1
	ExitUsage       = 2
	ExitPartial     = 3
	ExitNothingToDo = 4
)

// Execute sends a plan's writes to the target and returns the receipt.
//
// The receipt comes back populated whether or not the push succeeded: on a
// failure it is the only record of what was already written.
//
// A failure stops the per-step path immediately, since each write is its own
// request. On the batch path a per-object rejection does not stop the remaining
// kinds, because the request itself succeeded and reported each entity
// separately; only a failed request stops the run. Neither path is atomic.
func Execute(ctx context.Context, target Target, systemID string, pkg PackageRef, plan Plan) (*Receipt, error) {
	receipt := NewReceipt(pkg, target.Name(), systemID, plan)
	receipt.StartedAt = time.Now().UTC()

	if batcher, ok := target.(BatchWriter); ok {
		return receipt, writeBatched(ctx, batcher, plan, receipt)
	}
	return receipt, writeOneByOne(ctx, target, plan, receipt)
}

// writeOneByOne sends a step at a time, stopping at the first failure: no target
// of this kind offers a transaction, so continuing past a failure would widen
// the damage the receipt has to describe.
func writeOneByOne(ctx context.Context, target Target, plan Plan, receipt *Receipt) error {
	for _, step := range plan.Steps {
		if !step.Writes() {
			continue // already final in the receipt, and never sent
		}

		result, err := target.Write(ctx, step)
		if err != nil {
			receipt.Record(step.Entity.Kind, step.Entity.Key, OutcomeFailed, "", nil, err)
			return fmt.Errorf("writing %s %q: %w", step.Entity.Kind, step.Entity.Key, err)
		}
		receipt.Record(step.Entity.Kind, step.Entity.Key, outcomeFor(step.Action), result.RemoteID, result.RemoteState, nil)
	}
	return nil
}

// writeBatched sends one request per kind. A batch reports per object, so a
// rejected entity is recorded as its own failure and the entities that
// succeeded in the same request keep their outcomes.
func writeBatched(ctx context.Context, target BatchWriter, plan Plan, receipt *Receipt) error {
	var failures int
	for _, kind := range writeKinds(plan) {
		steps := stepsOfKind(plan, kind)

		outcomes, err := target.WriteBatch(ctx, kind, steps)
		if err != nil {
			// The request itself failed, so no entity in it was written.
			for _, step := range steps {
				receipt.Record(step.Entity.Kind, step.Entity.Key, OutcomeFailed, "", nil, err)
			}
			return fmt.Errorf("writing a batch of %s: %w", kind, err)
		}

		byKey := make(map[string]BatchOutcome, len(outcomes))
		for _, outcome := range outcomes {
			byKey[outcome.Key] = outcome
		}
		for _, step := range steps {
			outcome, reported := byKey[step.Entity.Key]
			switch {
			case !reported:
				failures++
				receipt.Record(step.Entity.Kind, step.Entity.Key, OutcomeFailed, "", nil,
					fmt.Errorf("the target reported no outcome for this entity"))
			case outcome.Err != nil:
				failures++
				receipt.Record(step.Entity.Kind, step.Entity.Key, OutcomeFailed, "", nil, outcome.Err)
			default:
				receipt.Record(step.Entity.Kind, step.Entity.Key, outcomeFor(step.Action),
					outcome.Result.RemoteID, outcome.Result.RemoteState, nil)
			}
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d writes failed; the receipt records which", failures, len(plan.Writes()))
	}
	return nil
}

// writeKinds lists the kinds the plan writes, in the order they first appear, so
// a plan's ordering is preserved across the grouping.
func writeKinds(plan Plan) []EntityKind {
	var kinds []EntityKind
	seen := make(map[EntityKind]bool)
	for _, step := range plan.Steps {
		if step.Writes() && !seen[step.Entity.Kind] {
			seen[step.Entity.Kind] = true
			kinds = append(kinds, step.Entity.Kind)
		}
	}
	return kinds
}

func stepsOfKind(plan Plan, kind EntityKind) []Step {
	var steps []Step
	for _, step := range plan.Steps {
		if step.Writes() && step.Entity.Kind == kind {
			steps = append(steps, step)
		}
	}
	return steps
}

func outcomeFor(a Action) Outcome {
	if a == ActionCreate {
		return OutcomeCreated
	}
	return OutcomeUpdated
}

// ExitCode classifies a receipt into the CLI's exit vocabulary.
//
// A push that wrote nothing because everything was already current, or because
// every difference was a conflict the remote won, is "nothing to do" rather than
// success: the caller asked for a change and none was needed, and a script
// should be able to tell that from a push that actually moved something.
func ExitCode(r *Receipt) int {
	if r == nil {
		return ExitFailure
	}

	var wrote, failed bool
	for _, e := range r.Entries {
		switch e.Outcome {
		case OutcomeCreated, OutcomeUpdated:
			wrote = true
		case OutcomeFailed:
			failed = true
		case OutcomeSkippedUnchanged, OutcomeSkippedConflicted, OutcomeSkippedUnverifiable, OutcomePlanned:
			// Nothing was written and nothing failed; neither flag moves.
		}
	}

	switch {
	case wrote && failed:
		return ExitPartial
	case failed:
		return ExitFailure
	case wrote:
		return ExitSuccess
	default:
		return ExitNothingToDo
	}
}

// BatchWriter is an optional capability a Target may implement. Where a target
// accepts several entities of one kind in one request and reports an outcome per
// object, Execute prefers this over one Write per step — ADR-0025 Decision 4
// requires using a batch endpoint where the target offers one.
//
// It is deliberately optional: a target without batch support implements Target
// alone and Execute falls back to per-step writes, so neither kind of adapter
// carries machinery it cannot use.
type BatchWriter interface {
	// WriteBatch sends every step of one kind. The returned outcomes are matched
	// to steps by key, and a batch may partially succeed: an outcome carrying an
	// error is that entity's failure, not the batch's.
	WriteBatch(ctx context.Context, kind EntityKind, steps []Step) ([]BatchOutcome, error)
}

// BatchOutcome is one entity's result within a batch.
type BatchOutcome struct {
	Key    string
	Result WriteResult
	Err    error
}
