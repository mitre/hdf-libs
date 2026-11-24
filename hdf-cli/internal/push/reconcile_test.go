package push_test

import (
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// preparedAt for a package; remote records created after this cannot be ours.
var preparedAt = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func entity(kind push.EntityKind, key string, content map[string]any) push.Entity {
	return push.Entity{Kind: kind, Key: key, Source: "baselines[0].requirements[0]", Content: content}
}

// The clean re-push: a target already carrying exactly what the package would
// write must produce no writes at all. This is Decision 3's layer 1, content
// equality, and it is the only layer available on every push.
func TestReconcile_UnchangedPackageProducesNoWrites(t *testing.T) {
	desired := []push.Entity{
		entity(push.KindTestResult, "AC-1/AC-1.1", map[string]any{"status": "passed"}),
		entity(push.KindPOAM, "RHEL-08-010010", map[string]any{"description": "remediation pending"}),
	}
	remote := []push.Entity{
		{Kind: push.KindTestResult, Key: "AC-1/AC-1.1", ID: "501", Content: map[string]any{"status": "passed"}},
		{Kind: push.KindPOAM, Key: "RHEL-08-010010", ID: "77", Content: map[string]any{"description": "remediation pending"}},
	}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)

	assert.Empty(t, plan.Writes(), "a package the target already carries must produce no writes")
	require.Len(t, plan.Steps, 2)
	for _, step := range plan.Steps {
		assert.Equal(t, push.ActionSkipUnchanged, step.Action, "entity %s", step.Entity.Key)
	}
	assert.True(t, plan.NothingToDo())
}

// Layer 2, on its own: a remote record created after the package was prepared
// cannot be one the package knows about. No receipt, no content match needed.
func TestReconcile_RemoteCreatedAfterPreparedAt_RemoteWins(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "RHEL-08-010010", map[string]any{"description": "ours"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "RHEL-08-010010", ID: "88",
		Content:   map[string]any{"description": "someone else's, written later"},
		CreatedAt: preparedAt.Add(24 * time.Hour),
	}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)

	require.Len(t, plan.Steps, 1)
	assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action)
	assert.Contains(t, plan.Steps[0].Reason, "after the package was prepared")
	assert.False(t, plan.Steps[0].Ambiguous, "layer 2 decided, so this is not ambiguous")
	assert.Empty(t, plan.Writes())
}

// A record created BEFORE the package was prepared is one the package may
// legitimately know about, so layer 2 must not flag it.
func TestReconcile_RemoteCreatedBeforePreparedAt_IsNotAConflict(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "updated"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "older"},
		CreatedAt: preparedAt.Add(-24 * time.Hour),
	}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
}

// With every layer unavailable — no creation time, and content that differs —
// the permissive default writes and the ambiguity is reported, not hidden.
func TestReconcile_NoLayerCanDecide_WritesAndReportsAmbiguity(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{Kind: push.KindPOAM, Key: "k", ID: "9", Content: map[string]any{"description": "theirs"}}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)

	require.Len(t, plan.Writes(), 1, "the default is to write")
	require.Len(t, plan.Ambiguous(), 1, "and to say that nothing could decide it")
	assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
}

// An entity the target does not hold is a create, whatever the layers say.
func TestReconcile_AbsentFromTarget_IsACreate(t *testing.T) {
	desired := []push.Entity{entity(push.KindArtifact, "scan.json", map[string]any{"name": "scan.json"})}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, nil, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionCreate, plan.Steps[0].Action)
	assert.False(t, plan.NothingToDo())
}

func TestReconcile_OnConflictPolicies(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content:   map[string]any{"description": "theirs"},
		CreatedAt: preparedAt.Add(time.Hour),
	}}
	pkg := push.Desired{PreparedAt: preparedAt, Entities: desired}

	t.Run("skip is the default and leaves the remote alone", func(t *testing.T) {
		plan, err := push.Reconcile(pkg, remote, push.Policy{})
		require.NoError(t, err)
		assert.Equal(t, push.ActionSkipConflicted, plan.Steps[0].Action)
	})

	t.Run("overwrite writes anyway and says why", func(t *testing.T) {
		plan, err := push.Reconcile(pkg, remote, push.Policy{OnConflict: push.ConflictOverwrite})
		require.NoError(t, err)
		assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
		assert.Contains(t, plan.Steps[0].Reason, "--on-conflict=overwrite")
	})

	t.Run("fail aborts the whole plan before any write", func(t *testing.T) {
		plan, err := push.Reconcile(pkg, remote, push.Policy{OnConflict: push.ConflictFail})
		var conflictErr *push.ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Equal(t, "k", conflictErr.Key)
		assert.Empty(t, plan.Steps, "no plan is returned, so nothing can be sent")
	})
}

// A remote entity the adapter could not read back comparably is indeterminate,
// not unchanged — otherwise an unreadable record would silently suppress a write.
func TestReconcile_RemoteWithNoComparableContent_IsNotTreatedAsUnchanged(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "ours"})}
	remote := []push.Entity{{Kind: push.KindPOAM, Key: "k", ID: "9", Content: nil}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionUpdate, plan.Steps[0].Action)
	assert.True(t, plan.Steps[0].Ambiguous)
}

// An omitted field and an explicit nil are the same absence, so a target that
// echoes nulls must not look like a difference on every push.
func TestReconcile_OmittedAndExplicitNilCompareEqual(t *testing.T) {
	desired := []push.Entity{entity(push.KindPOAM, "k", map[string]any{"description": "same"})}
	remote := []push.Entity{{
		Kind: push.KindPOAM, Key: "k", ID: "9",
		Content: map[string]any{"description": "same", "comments": nil},
	}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionSkipUnchanged, plan.Steps[0].Action)
}

// Two kinds may legitimately share a natural key; they must not collide.
func TestReconcile_SameKeyDifferentKinds_AreDistinctEntities(t *testing.T) {
	desired := []push.Entity{
		entity(push.KindPOAM, "shared", map[string]any{"a": 1}),
		entity(push.KindArtifact, "shared", map[string]any{"a": 2}),
	}
	remote := []push.Entity{{Kind: push.KindPOAM, Key: "shared", ID: "1", Content: map[string]any{"a": 1}}}

	plan, err := push.Reconcile(push.Desired{PreparedAt: preparedAt, Entities: desired}, remote, push.Policy{})
	require.NoError(t, err)
	assert.Equal(t, push.ActionSkipUnchanged, plan.Steps[0].Action)
	assert.Equal(t, push.ActionCreate, plan.Steps[1].Action, "the artifact is absent and must be created")
}
