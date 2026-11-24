package push_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTarget is an in-memory Target. That this can stand in for a real one at
// all is the point of the interface: nothing in this package knows what system
// is on the other side.
type fakeTarget struct {
	name     string
	remote   []push.Entity
	written  []push.Step
	failOn   map[string]error
	failKind map[push.EntityKind]error
	assignID string
}

func (f *fakeTarget) Name() string { return f.name }

func (f *fakeTarget) Read(_ context.Context, _ string) ([]push.Entity, error) {
	return f.remote, nil
}

func (f *fakeTarget) Write(_ context.Context, step push.Step) (push.WriteResult, error) {
	if err, bad := f.failOn[step.Entity.Key]; bad {
		return push.WriteResult{}, err
	}
	if err, bad := f.failKind[step.Entity.Kind]; bad {
		return push.WriteResult{}, err
	}
	f.written = append(f.written, step)
	return push.WriteResult{RemoteID: f.assignID, RemoteState: step.Entity.Content}, nil
}

func planFor(keys ...string) push.Plan {
	plan := push.Plan{}
	for _, k := range keys {
		plan.Steps = append(plan.Steps, push.Step{
			Entity: entity(push.KindPOAM, k, map[string]any{"description": k}),
			Action: push.ActionCreate,
		})
	}
	return plan
}

func TestExecute_WritesEachStepAndRecordsTheReceipt(t *testing.T) {
	target := &fakeTarget{name: "fake", assignID: "100"}
	receipt, err := push.Execute(context.Background(), target, "sys-1",
		push.PackageRef{Name: "p", Integrity: "sha256:x"}, planFor("a", "b"))

	require.NoError(t, err)
	assert.Len(t, target.written, 2)
	assert.Equal(t, "fake", receipt.Target)
	for _, key := range []string{"a", "b"} {
		entry := receipt.Lookup(push.KindPOAM, key)
		require.NotNil(t, entry)
		assert.Equal(t, push.OutcomeCreated, entry.Outcome)
		assert.Equal(t, "100", entry.RemoteID)
	}
	assert.False(t, receipt.Partial())
}

// A skip is never sent to the target, however the plan got there.
func TestExecute_SkipsAreNotSent(t *testing.T) {
	target := &fakeTarget{name: "fake"}
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "unchanged", nil), Action: push.ActionSkipUnchanged},
		{Entity: entity(push.KindPOAM, "conflicted", nil), Action: push.ActionSkipConflicted},
	}}

	receipt, err := push.Execute(context.Background(), target, "sys-1", push.PackageRef{Name: "p"}, plan)
	require.NoError(t, err)
	assert.Empty(t, target.written)
	assert.Equal(t, push.OutcomeSkippedUnchanged, receipt.Lookup(push.KindPOAM, "unchanged").Outcome)
	assert.Equal(t, push.OutcomeSkippedConflicted, receipt.Lookup(push.KindPOAM, "conflicted").Outcome)
}

// A partial push's receipt is the only recovery record, so it must come back
// populated even though Execute reports an error.
func TestExecute_PartialFailureStillReturnsAReceipt(t *testing.T) {
	boom := errors.New("target rejected the write")
	target := &fakeTarget{name: "fake", assignID: "7", failOn: map[string]error{"b": boom}}

	receipt, err := push.Execute(context.Background(), target, "sys-1", push.PackageRef{Name: "p"}, planFor("a", "b", "c"))

	require.Error(t, err)
	require.NotNil(t, receipt, "the receipt is the recovery record and must survive the failure")
	assert.Equal(t, push.OutcomeCreated, receipt.Lookup(push.KindPOAM, "a").Outcome)
	assert.Equal(t, push.OutcomeFailed, receipt.Lookup(push.KindPOAM, "b").Outcome)
	assert.Contains(t, receipt.Lookup(push.KindPOAM, "b").Error, "rejected")
	assert.True(t, receipt.Partial())

	// It stops at the first failure rather than continuing, since a target of
	// this kind offers no transaction and the receipt is the recovery path.
	assert.Equal(t, push.OutcomePlanned, receipt.Lookup(push.KindPOAM, "c").Outcome,
		"a step after the failure is left planned, not silently dropped")
}

func TestExitCode_FollowsTheCLIVocabulary(t *testing.T) {
	newReceipt := func(outcomes ...push.Outcome) *push.Receipt {
		r := &push.Receipt{Version: push.ReceiptVersion}
		for i, o := range outcomes {
			r.Entries = append(r.Entries, push.Entry{Kind: push.KindPOAM, Key: string(rune('a' + i)), Outcome: o})
		}
		return r
	}

	cases := []struct {
		name    string
		receipt *push.Receipt
		want    int
	}{
		{"everything wrote", newReceipt(push.OutcomeCreated, push.OutcomeUpdated), push.ExitSuccess},
		{"everything was already current", newReceipt(push.OutcomeSkippedUnchanged), push.ExitNothingToDo},
		{"nothing to do on an empty plan", newReceipt(), push.ExitNothingToDo},
		{"some wrote and some failed", newReceipt(push.OutcomeCreated, push.OutcomeFailed), push.ExitPartial},
		{"everything failed", newReceipt(push.OutcomeFailed), push.ExitFailure},
		{"skipped as conflicted is not a failure", newReceipt(push.OutcomeCreated, push.OutcomeSkippedConflicted), push.ExitSuccess},
		{"only conflicts, nothing written", newReceipt(push.OutcomeSkippedConflicted), push.ExitNothingToDo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, push.ExitCode(tc.receipt))
		})
	}
}

// The numbers themselves, pinned: these are the CLI's documented vocabulary and
// a caller's scripts depend on them.
func TestExitCode_NumbersArePinned(t *testing.T) {
	assert.Equal(t, 0, push.ExitSuccess)
	assert.Equal(t, 1, push.ExitFailure)
	assert.Equal(t, 2, push.ExitUsage)
	assert.Equal(t, 3, push.ExitPartial)
	assert.Equal(t, 4, push.ExitNothingToDo)
}
