package push_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// "skip" must work as a literal value, not only as the zero value. The command
// layer passes the word through from --on-conflict, so a policy that only
// understands "" would abort every push that spelled its default out.
func TestConflictPolicy_SkipWorksAsALiteralAndAsTheZeroValue(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "theirs"},
		CreatedAt: preparedAt.Add(time.Hour),
	}}
	pkg := push.Desired{PreparedAt: preparedAt, Entities: desired}

	for _, policy := range []push.ConflictPolicy{push.ConflictSkip, "skip", ""} {
		plan, err := push.Reconcile(pkg, remote, push.Policy{OnConflict: policy})
		require.NoErrorf(t, err, "policy %q must be accepted", policy)
		require.Len(t, plan.Steps, 1)
		assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action, "policy %q", policy)
	}
}

func TestConflictPolicy_UnknownValueIsRejectedByName(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "theirs"},
		CreatedAt: preparedAt.Add(time.Hour),
	}}

	_, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote,
		push.Policy{OnConflict: "clobber"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clobber")
}

// Two kinds may share a natural key. Recording an outcome by key alone
// mis-attributes the id, the state and the outcome, and downgrades a partial
// push to a total failure.
func TestReceipt_RecordIsKeyedByKindAndKey(t *testing.T) {
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "shared", map[string]any{"a": 1}), Action: push.ActionCreate},
		{Entity: entity(push.KindArtifact, "shared", map[string]any{"a": 2}), Action: push.ActionCreate},
	}}
	receipt := push.NewReceipt(push.PackageRef{Name: "p"}, "t", "s", plan)

	receipt.Record(push.KindPOAM, "shared", push.OutcomeCreated, "poam-id", map[string]any{"a": 1}, nil)
	receipt.Record(push.KindArtifact, "shared", push.OutcomeCreated, "artifact-id", map[string]any{"a": 2}, nil)

	poam := receipt.Lookup(push.KindPOAM, "shared")
	require.NotNil(t, poam)
	assert.Equal(t, "poam-id", poam.RemoteID)
	artifact := receipt.Lookup(push.KindArtifact, "shared")
	require.NotNil(t, artifact)
	assert.Equal(t, "artifact-id", artifact.RemoteID, "the artifact must not inherit the POA&M's id")
	assert.Equal(t, push.OutcomeCreated, artifact.Outcome, "and must not be left planned")
}

// The exit-code consequence of the same defect: one entity wrote, another
// failed, and the caller must be able to tell that from total failure.
func TestExecute_PartialAcrossTwoKindsSharingAKeyExitsPartial(t *testing.T) {
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "shared", map[string]any{"a": 1}), Action: push.ActionCreate},
		{Entity: entity(push.KindArtifact, "shared", map[string]any{"a": 2}), Action: push.ActionCreate},
	}}
	target := &fakeTarget{
		name:     "fake",
		assignID: "written",
		failOn:   map[string]error{},
		failKind: map[push.EntityKind]error{push.KindArtifact: errors.New("target rejected the artifact")},
	}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, plan)
	require.Error(t, err)
	assert.Equal(t, push.OutcomeCreated, receipt.Lookup(push.KindPOAM, "shared").Outcome)
	assert.Equal(t, push.OutcomeFailed, receipt.Lookup(push.KindArtifact, "shared").Outcome)
	assert.True(t, receipt.Partial(), "one wrote and one failed")
	assert.Equal(t, push.ExitPartial, push.ExitCode(receipt))
}

// The receipt is the recovery record for a failed push, so it must not describe
// the target as holding content that was never sent. Seeding RemoteState from
// the desired content made a retry refuse to write, blaming a phantom edit.
func TestReceipt_FailedPushDoesNotSuppressTheRetry(t *testing.T) {
	ours := map[string]any{"description": "ours, newer"}
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "a", ours), Action: push.ActionCreate},
		{Entity: entity(push.KindPOAM, "b", ours), Action: push.ActionCreate},
	}}
	target := &fakeTarget{name: "fake", assignID: "1", failOn: map[string]error{"a": errors.New("rejected")}}

	kept, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, plan)
	require.Error(t, err)

	// Neither entity reached the target: "a" failed and "b" was never attempted.
	assert.Empty(t, kept.Lookup(push.KindPOAM, "a").RemoteState, "a failed write observed nothing on the target")
	assert.Empty(t, kept.Lookup(push.KindPOAM, "b").RemoteState, "an unattempted write observed nothing either")

	// The retry must still write both, not read the kept receipt as evidence
	// that someone else edited records that were never created.
	retry, err := push.Reconcile(
		push.Desired{PreparedAt: preparedAt, Entities: []push.Entity{entity(push.KindPOAM, "b", ours)}},
		[]push.Entity{{Kind: push.KindPOAM, Key: "b", ID: "9", Content: map[string]any{"description": "pre-existing"}}},
		push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionUpdate, retry.Steps[0].Action,
		"the retry must proceed; a receipt entry the push never wrote is not evidence of an edit")
	_ = kept
}

// Layer 3 may only trust an entry whose outcome means the target was actually
// observed. A conflicted skip records our content, not theirs, so it must not
// become the baseline for the next push's comparison.
func TestReceipt_OnlyObservedOutcomesFeedLayerThree(t *testing.T) {
	ours := map[string]any{"description": "ours"}
	for _, tc := range []struct {
		outcome push.Outcome
		trusted bool
	}{
		{push.OutcomeCreated, true},
		{push.OutcomeUpdated, true},
		{push.OutcomeSkippedUnchanged, true},
		{push.OutcomeFailed, false},
		{push.OutcomePlanned, false},
		{push.OutcomeSkippedConflicted, false},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			prior := &push.Receipt{Entries: []push.Entry{{
				Kind: push.KindPOAM, Key: "k", Outcome: tc.outcome,
				RemoteID: "9", RemoteState: map[string]any{"description": "what the receipt claims"},
			}}}
			remote := []push.Entity{{
				Kind: push.KindPOAM, Key: "k", ID: "9",
				Content:   map[string]any{"description": "what the target actually holds"},
				CreatedAt: preparedAt.Add(-48 * time.Hour),
			}}

			plan, err := push.Reconcile(
				push.Desired{PreparedAt: preparedAt, Entities: []push.Entity{entity(push.KindPOAM, "k", ours)}, Prior: prior},
				remote, push.Policy{})
			require.NoError(t, err)

			if tc.trusted {
				assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action,
					"an observed outcome is evidence, so the mismatch is an edit")
			} else {
				assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action,
					"an unobserved outcome is not evidence of anything")
				assert.True(t, plan.Steps[0].Ambiguous, "and the push says nothing could decide it")
			}
		})
	}
}

// A clean create recorded before a later failure must survive in the receipt,
// which is what makes "aborts the whole plan" meaningful on more than one entity.
func TestReconcile_OnConflictFail_DiscardsEarlierCleanSteps(t *testing.T) {
	desired := []push.Entity{
		entity(push.KindPOAM, "clean", map[string]any{"a": 1}),
		entity(push.KindPOAM, "conflicted", map[string]any{"a": 2}),
	}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "conflicted", ID: "9",
		Content:   map[string]any{"a": 99},
		CreatedAt: preparedAt.Add(time.Hour),
	}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote,
		push.Policy{OnConflict: push.ConflictFail})

	var conflictErr *push.ConflictError
	require.ErrorAs(t, err, &conflictErr)
	assert.Empty(t, plan.Steps, "the whole plan is discarded, including the clean create that preceded the conflict")
	assert.Contains(t, conflictErr.Error(), "conflicted", "the error names the entity a reader must go look at")
	assert.Contains(t, conflictErr.Error(), "poam")
}

// The receipt's RemoteState for a written entity comes from the target's own
// WriteResult, and it is what the next push reads as layer 3. Nothing asserted
// it on either write path, so the whole push-receipt-push loop this layer exists
// to build could be deleted with the suite staying green.
func TestExecute_RecordsTheTargetsReportedStateOnBothWritePaths(t *testing.T) {
	// What the target reports back is deliberately not what we sent, so an
	// assertion cannot pass by accident if the code echoes the desired content.
	reported := map[string]any{"description": "as the target normalized it"}

	t.Run("per-step path", func(t *testing.T) {
		target := &reportingTarget{fakeTarget: fakeTarget{name: "plain"}, state: reported}
		receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"},
			push.Plan{Steps: []push.Step{{Entity: entity(push.KindPOAM, "k", map[string]any{"description": "as sent"}), Action: push.ActionCreate}}})
		require.NoError(t, err)

		entry := receipt.Lookup(push.KindPOAM, "k")
		require.NotNil(t, entry)
		assert.Equal(t, reported, entry.RemoteState, "the receipt must carry what the target reported")
		assert.Equal(t, "assigned-id", entry.RemoteID)
	})

	t.Run("batch path", func(t *testing.T) {
		target := &reportingBatchTarget{fakeTarget: fakeTarget{name: "batching"}, state: reported}
		receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"},
			push.Plan{Steps: []push.Step{{Entity: entity(push.KindPOAM, "k", map[string]any{"description": "as sent"}), Action: push.ActionCreate}}})
		require.NoError(t, err)

		entry := receipt.Lookup(push.KindPOAM, "k")
		require.NotNil(t, entry)
		assert.Equal(t, reported, entry.RemoteState)
		assert.Equal(t, "assigned-id", entry.RemoteID)
	})

	t.Run("and the next push reads it as layer 3", func(t *testing.T) {
		target := &reportingTarget{fakeTarget: fakeTarget{name: "plain"}, state: reported}
		kept, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"},
			push.Plan{Steps: []push.Step{{Entity: entity(push.KindPOAM, "k", map[string]any{"description": "as sent"}), Action: push.ActionCreate}}})
		require.NoError(t, err)

		// The target now holds something else, so layer 3 must see the edit —
		// which only works if the receipt recorded the reported state above.
		plan, err := push.Reconcile(
			push.Desired{PreparedAt: preparedAt, Entities: []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}, Prior: kept},
			[]push.Entity{{Kind: push.KindPOAM, Key: "k", ID: "assigned-id", Content: map[string]any{"description": "someone edited it"}}},
			push.Policy{})
		require.NoError(t, err)
		assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action)
		assert.Contains(t, plan.Steps[0].Reason, "edited on the target")
	})
}

type reportingTarget struct {
	fakeTarget
	state map[string]any
}

func (r *reportingTarget) Write(_ context.Context, _ push.Step) (push.WriteResult, error) {
	return push.WriteResult{RemoteID: "assigned-id", RemoteState: r.state}, nil
}

type reportingBatchTarget struct {
	fakeTarget
	state map[string]any
}

func (r *reportingBatchTarget) WriteBatch(_ context.Context, _ push.EntityKind, steps []push.Step) ([]push.BatchOutcome, error) {
	out := make([]push.BatchOutcome, 0, len(steps))
	for _, step := range steps {
		out = append(out, push.BatchOutcome{
			Key:    step.Entity.Key,
			Result: push.WriteResult{RemoteID: "assigned-id", RemoteState: r.state},
		})
	}
	return out, nil
}

// The layers can disagree, and the precedence decides it: layer 2 would flag a
// record created after the package was prepared, but a receipt showing the
// target still holds what our own earlier push left clears it. Without that
// precedence, --on-conflict=fail would abort on records we created ourselves.
func TestReconcile_LayerThreeClearsWhatLayerTwoWouldFlag(t *testing.T) {
	left := map[string]any{"description": "what our last push left"}
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours, newer"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content: left,
		// Created after the package was prepared — by our own earlier push.
		CreatedAt: preparedAt.Add(time.Hour),
	}}
	prior := &push.Receipt{Entries: []push.Entry{{
		Kind: push.KindPOAM, Key: "k", Outcome: push.OutcomeCreated, RemoteID: "9", RemoteState: left,
	}}}

	t.Run("without a receipt, layer 2 flags it", func(t *testing.T) {
		plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
		require.NoError(t, err)
		assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action)
	})

	t.Run("with a receipt, layer 3 clears it and the update proceeds", func(t *testing.T) {
		plan, err := push.Reconcile(
			push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: prior}, remote, push.Policy{})
		require.NoError(t, err)
		assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
		assert.False(t, plan.Steps[0].Ambiguous, "the receipt decided it, so nothing is ambiguous")
	})

	t.Run("and --on-conflict=fail aborts only without the receipt", func(t *testing.T) {
		_, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote,
			push.Policy{OnConflict: push.ConflictFail})
		require.Error(t, err, "no receipt: layer 2's inference stands and fail aborts")

		_, err = push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: prior}, remote,
			push.Policy{OnConflict: push.ConflictFail})
		require.NoError(t, err, "with the receipt there is no conflict to fail on")
	})
}

// Two entities sharing a kind and key are out of contract, but the failure was
// silent: both wrote, the second receipt entry stayed planned, and the exit code
// said success. A plan that cannot be audited must not be produced.
func TestReconcile_DuplicateKeyWithinAKindIsRejected(t *testing.T) {
	desired := []push.Entity{
		entity(push.KindArtifact, "scan.json", map[string]any{"n": 1}),
		entity(push.KindArtifact, "scan.json", map[string]any{"n": 2}),
	}

	_, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, nil, push.Policy{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan.json")
	assert.Contains(t, err.Error(), "artifact")
}

// The same key under two different kinds is legitimate and must still pass.
func TestReconcile_DuplicateKeyAcrossKindsIsAllowed(t *testing.T) {
	desired := []push.Entity{
		entity(push.KindArtifact, "shared", map[string]any{"n": 1}),
		entity(push.KindPOAM, "shared", map[string]any{"n": 2}),
	}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, nil, push.Policy{})
	require.NoError(t, err)
	assert.Len(t, plan.Steps, 2)
}
