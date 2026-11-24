package push_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batchTarget implements the optional BatchWriter, as an adapter would for a
// target whose endpoint takes several records per request.
type batchTarget struct {
	fakeTarget
	calls   []batchCall
	failKey map[string]error
}

type batchCall struct {
	kind  push.EntityKind
	count int
}

func (b *batchTarget) WriteBatch(_ context.Context, kind push.EntityKind, steps []push.Step) ([]push.BatchOutcome, error) {
	b.calls = append(b.calls, batchCall{kind: kind, count: len(steps)})
	out := make([]push.BatchOutcome, 0, len(steps))
	for _, step := range steps {
		outcome := push.BatchOutcome{Key: step.Entity.Key}
		if err, bad := b.failKey[step.Entity.Key]; bad {
			outcome.Err = err
		} else {
			outcome.Result = push.WriteResult{RemoteID: "batched", RemoteState: step.Entity.Content}
		}
		out = append(out, outcome)
	}
	return out, nil
}

func mixedPlan() push.Plan {
	return push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindTestResult, "t1", map[string]any{"n": 1}), Action: push.ActionCreate},
		{Entity: entity(push.KindTestResult, "t2", map[string]any{"n": 2}), Action: push.ActionCreate},
		{Entity: entity(push.KindPOAM, "p1", map[string]any{"n": 3}), Action: push.ActionCreate},
		{Entity: entity(push.KindTestResult, "skipme", nil), Action: push.ActionSkipUnchanged},
	}}
}

func TestExecute_UsesTheBatchPathAndGroupsByKind(t *testing.T) {
	target := &batchTarget{fakeTarget: fakeTarget{name: "batching"}}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, mixedPlan())
	require.NoError(t, err)

	require.Len(t, target.calls, 2, "one request per kind, not one per entity")
	assert.Equal(t, push.KindTestResult, target.calls[0].kind)
	assert.Equal(t, 2, target.calls[0].count, "the skip is not sent")
	assert.Equal(t, push.KindPOAM, target.calls[1].kind)
	assert.Empty(t, target.written, "the per-step path must not also run")

	for _, key := range []string{"t1", "t2"} {
		entry := receipt.Lookup(push.KindTestResult, key)
		require.NotNil(t, entry)
		assert.Equal(t, push.OutcomeCreated, entry.Outcome)
		assert.Equal(t, "batched", entry.RemoteID)
	}
	assert.Equal(t, push.OutcomeSkippedUnchanged, receipt.Lookup(push.KindTestResult, "skipme").Outcome)
	assert.Equal(t, push.ExitSuccess, push.ExitCode(receipt))
}

// A batch reports per object, so one rejected entity must not discard the
// outcomes of the ones that succeeded in the same request.
func TestExecute_BatchPartialFailureIsRecordedPerEntity(t *testing.T) {
	target := &batchTarget{
		fakeTarget: fakeTarget{name: "batching"},
		failKey:    map[string]error{"t2": errors.New("that one was rejected")},
	}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, mixedPlan())
	require.Error(t, err)

	assert.Equal(t, push.OutcomeCreated, receipt.Lookup(push.KindTestResult, "t1").Outcome)
	failed := receipt.Lookup(push.KindTestResult, "t2")
	require.NotNil(t, failed)
	assert.Equal(t, push.OutcomeFailed, failed.Outcome)
	assert.Contains(t, failed.Error, "rejected")
	assert.Empty(t, failed.RemoteState, "a rejected entity was not observed on the target")

	assert.True(t, receipt.Partial())
	assert.Equal(t, push.ExitPartial, push.ExitCode(receipt))
}

// A target that implements Target alone keeps working, so an adapter without a
// batch endpoint carries nothing it cannot use.
func TestExecute_FallsBackToPerStepWritesWithoutBatchSupport(t *testing.T) {
	target := &fakeTarget{name: "plain", assignID: "one-at-a-time"}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, mixedPlan())
	require.NoError(t, err)
	assert.Len(t, target.written, 3, "three writes, one per entity, and the skip is not sent")
	assert.Equal(t, "one-at-a-time", receipt.Lookup(push.KindPOAM, "p1").RemoteID)
}

// A request that fails outright wrote nothing, so every entity in it is a
// failure and none may claim remote state.
func TestExecute_BatchRequestFailureMarksEveryEntityInIt(t *testing.T) {
	target := &wholeBatchFails{fakeTarget: fakeTarget{name: "batching"}}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, mixedPlan())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch")

	for _, key := range []string{"t1", "t2"} {
		entry := receipt.Lookup(push.KindTestResult, key)
		require.NotNil(t, entry)
		assert.Equal(t, push.OutcomeFailed, entry.Outcome)
		assert.Empty(t, entry.RemoteState)
	}
	// It stops at the failed request rather than sending the next kind.
	assert.Equal(t, push.OutcomePlanned, receipt.Lookup(push.KindPOAM, "p1").Outcome)
	assert.Equal(t, push.ExitFailure, push.ExitCode(receipt), "nothing wrote, so this is not partial")
}

type wholeBatchFails struct{ fakeTarget }

func (w *wholeBatchFails) WriteBatch(_ context.Context, _ push.EntityKind, _ []push.Step) ([]push.BatchOutcome, error) {
	return nil, errors.New("the batch request itself failed")
}

// A target that silently omits an entity from its outcomes must not leave that
// entity looking unattempted: an unreported write is a failure we can see.
func TestExecute_BatchOutcomeMissingForAnEntityIsAFailure(t *testing.T) {
	target := &silentBatch{fakeTarget: fakeTarget{name: "batching"}}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"},
		push.Plan{Steps: []push.Step{
			{Entity: entity(push.KindTestResult, "reported", map[string]any{"n": 1}), Action: push.ActionCreate},
			{Entity: entity(push.KindTestResult, "ignored", map[string]any{"n": 2}), Action: push.ActionCreate},
		}})
	require.Error(t, err)

	assert.Equal(t, push.OutcomeCreated, receipt.Lookup(push.KindTestResult, "reported").Outcome)
	ignored := receipt.Lookup(push.KindTestResult, "ignored")
	require.NotNil(t, ignored)
	assert.Equal(t, push.OutcomeFailed, ignored.Outcome)
	assert.Contains(t, ignored.Error, "no outcome")
	assert.Equal(t, push.ExitPartial, push.ExitCode(receipt))
}

type silentBatch struct{ fakeTarget }

func (s *silentBatch) WriteBatch(_ context.Context, _ push.EntityKind, steps []push.Step) ([]push.BatchOutcome, error) {
	return []push.BatchOutcome{{
		Key:    steps[0].Entity.Key,
		Result: push.WriteResult{RemoteID: "1", RemoteState: steps[0].Entity.Content},
	}}, nil
}

// An update, batched, is recorded as an update rather than a create.
func TestExecute_BatchedUpdateIsRecordedAsAnUpdate(t *testing.T) {
	target := &batchTarget{fakeTarget: fakeTarget{name: "batching"}}
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "existing", map[string]any{"n": 1}), Action: push.ActionUpdate, RemoteID: "9"},
	}}

	receipt, err := push.Execute(context.Background(), target, "s", push.PackageRef{Name: "p"}, plan)
	require.NoError(t, err)
	assert.Equal(t, push.OutcomeUpdated, receipt.Lookup(push.KindPOAM, "existing").Outcome)
}

// Lookup must not match on key alone, which is what made the receipt
// cross-attribute outcomes between kinds.
func TestReceipt_LookupDistinguishesKinds(t *testing.T) {
	r := &push.Receipt{Entries: []push.Entry{
		{Kind: push.KindPOAM, Key: "shared", RemoteID: "poam"},
		{Kind: push.KindArtifact, Key: "shared", RemoteID: "artifact"},
	}}
	assert.Equal(t, "poam", r.Lookup(push.KindPOAM, "shared").RemoteID)
	assert.Equal(t, "artifact", r.Lookup(push.KindArtifact, "shared").RemoteID)
	assert.Nil(t, r.Lookup(push.KindMilestone, "shared"), "a kind with no entry returns nothing")
}
