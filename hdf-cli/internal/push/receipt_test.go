package push_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func priorReceipt(state map[string]any) *push.Receipt {
	return &push.Receipt{
		Entries: []push.Entry{{
			Kind: push.KindPOAM, Key: "k", Outcome: push.OutcomeUpdated,
			RemoteID: "9", RemoteState: state,
		}},
	}
}

// Layer 3 is the only one that catches an in-place edit of a record that already
// existed when the package was prepared: a target that exposes no
// modification timestamp gives nothing else to detect it with.
func TestReconcile_ReceiptCatchesInPlaceEdit(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours, newer"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "edited by someone else"},
		CreatedAt: preparedAt.Add(-48 * time.Hour), // older, so layer 2 cannot help
	}}

	plan, err := push.Reconcile(
		push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: priorReceipt(map[string]any{"description": "what we left"})},
		remote, push.Policy{})
	require.NoError(t, err)

	require.Len(t, plan.Steps, 1)
	assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action)
	assert.Contains(t, plan.Steps[0].Reason, "edited on the target since the last push")
	assert.False(t, plan.Steps[0].Ambiguous)
}

// If the remote still carries exactly what the last push left, nobody edited it,
// so layer 3 must not flag it and our newer content goes.
func TestReconcile_ReceiptMatchesRemote_IsNotAConflict(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours, newer"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "what we left"},
		CreatedAt: preparedAt.Add(-48 * time.Hour),
	}}

	plan, err := push.Reconcile(
		push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: priorReceipt(map[string]any{"description": "what we left"})},
		remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
	assert.False(t, plan.Steps[0].Ambiguous, "the receipt decided that no one else touched it")
}

// A push with no receipt loses layer 3 and nothing else. The ADR is explicit
// that the receipt is an enhancement, never a precondition.
func TestReconcile_NoReceipt_StillPushes(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{Kind: push.KindPOAM, Key: "k", ID: "9", Content: map[string]any{"description": "theirs"}}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: nil}, remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
	assert.True(t, plan.Steps[0].Ambiguous, "without the receipt nothing could decide, so it writes and says so")
}

// Documented precedence: layer 3's direct evidence of an edit outranks layer 2's
// inference from a creation time, so the reported reason names the edit.
func TestReconcile_LayerPrecedence_ReceiptOutranksCreationTime(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "theirs"},
		CreatedAt: preparedAt.Add(time.Hour), // layer 2 would also flag this
	}}

	plan, err := push.Reconcile(
		push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: priorReceipt(map[string]any{"description": "what we left"})},
		remote, push.Policy{})
	require.NoError(t, err)
	assert.Contains(t, plan.Steps[0].Reason, "edited on the target since the last push",
		"both layers flag it; the more specific reason is reported")
}

// Content equality outranks every conflict layer: if the target already carries
// what we would write, there is nothing to conflict over.
func TestReconcile_ContentEqualityOutranksConflictLayers(t *testing.T) {
	same := map[string]any{"description": "identical"}
	desired := []push.Entity{entity(push.KindPOAM, "k", same)}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9", Content: same,
		CreatedAt: preparedAt.Add(time.Hour),
	}}

	plan, err := push.Reconcile(
		push.Desired{PreparedAt: preparedAt, Entities: desired, Prior: priorReceipt(map[string]any{"description": "different"})},
		remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionSkipUnchanged, plan.Steps[0].Action)
}

func TestReceipt_RecordsEverythingAnAuditNeeds(t *testing.T) {
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "created-key", nil), Action: push.ActionCreate},
		{Entity: entity(push.KindPOAM, "skipped-key", nil), Action: push.ActionSkipUnchanged, RemoteID: "5"},
	}}
	pkg := push.PackageRef{Name: "quarterly-scan", Integrity: "sha256:abc123"}

	receipt := push.NewReceipt(pkg, "target-under-test", "sys-42", plan)
	receipt.Record(push.KindPOAM, "created-key", push.OutcomeCreated, "601", map[string]any{"description": "as sent"}, nil)

	assert.Equal(t, push.ReceiptVersion, receipt.Version, "versioned from the start: others will parse this")
	assert.Equal(t, pkg, receipt.Package)
	assert.Equal(t, "target-under-test", receipt.Target)
	assert.Equal(t, "sys-42", receipt.SystemID)

	created := receipt.Lookup(push.KindPOAM, "created-key")
	require.NotNil(t, created)
	assert.Equal(t, push.OutcomeCreated, created.Outcome)
	assert.Equal(t, "601", created.RemoteID)
	assert.Equal(t, "baselines[0].requirements[0]", created.Source, "an auditor can trace the record back to its document")
	assert.Equal(t, map[string]any{"description": "as sent"}, created.RemoteState, "layer 3 of the next push reads this")

	skipped := receipt.Lookup(push.KindPOAM, "skipped-key")
	require.NotNil(t, skipped)
	assert.Equal(t, push.OutcomeSkippedUnchanged, skipped.Outcome)
}

// A partial push's receipt is the only recovery record, so a failure must be
// recorded rather than aborting the receipt.
func TestReceipt_RecordsFailuresAndIsEmittedAnyway(t *testing.T) {
	plan := push.Plan{Steps: []push.Step{
		{Entity: entity(push.KindPOAM, "ok", nil), Action: push.ActionCreate},
		{Entity: entity(push.KindPOAM, "bad", nil), Action: push.ActionCreate},
	}}
	receipt := push.NewReceipt(push.PackageRef{Name: "p"}, "t", "s", plan)
	receipt.Record(push.KindPOAM, "ok", push.OutcomeCreated, "1", nil, nil)
	receipt.Record(push.KindPOAM, "bad", push.OutcomeFailed, "", nil, assert.AnError)

	failed := receipt.Lookup(push.KindPOAM, "bad")
	require.NotNil(t, failed)
	assert.Equal(t, push.OutcomeFailed, failed.Outcome)
	assert.NotEmpty(t, failed.Error, "the error text is the recovery record")
	assert.True(t, receipt.Partial(), "some wrote and some failed")
}

func TestReceipt_RoundTripsThroughJSON(t *testing.T) {
	plan := push.Plan{Steps: []push.Step{{Entity: entity(push.KindPOAM, "k", nil), Action: push.ActionCreate}}}
	receipt := push.NewReceipt(push.PackageRef{Name: "p", Integrity: "sha256:x"}, "t", "s", plan)
	receipt.Record(push.KindPOAM, "k", push.OutcomeCreated, "7", map[string]any{"description": "d"}, nil)

	raw, err := json.Marshal(receipt)
	require.NoError(t, err)

	var back push.Receipt
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, push.ReceiptVersion, back.Version)
	entry := back.Lookup(push.KindPOAM, "k")
	require.NotNil(t, entry)
	assert.Equal(t, "7", entry.RemoteID)
	assert.Equal(t, map[string]any{"description": "d"}, entry.RemoteState,
		"the next push's layer 3 depends on this surviving a round trip")
}
