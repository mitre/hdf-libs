package push_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercising this layer against a real evidence package needs a package on
// disk, which no committed fixture can supply without pinning a preparedAt that
// the wall clock would pass. So it is opt-in, following the convention
// HDF_PROVENANCE_NETWORK uses in hdf-converters/shared/go/schemaload_test.go.
//
// Build one and run it:
//
//	cp hdf-fixtures/results/inspec-multilayered.json /tmp/live/results.json
//	cd /tmp/live && hdf evidence build --results results.json -o package.json
//	HDF_PUSH_LIVE_PACKAGE=/tmp/live/package.json go test ./internal/push/... -run Live -v
func TestLive_ReconcileAndExecuteAgainstARealPackage(t *testing.T) {
	path := os.Getenv("HDF_PUSH_LIVE_PACKAGE")
	if path == "" {
		t.Skip("set HDF_PUSH_LIVE_PACKAGE to an evidence package built by `hdf evidence build` to run this")
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)

	var pkg struct {
		Name       string    `json:"name"`
		PreparedAt time.Time `json:"preparedAt"`
		// Integrity is algorithm + checksum in the evidence-package schema. Note
		// that `hdf evidence build` populates no integrity today, so this is
		// empty on a package built that way and the receipt records it as such.
		Integrity struct {
			Algorithm string `json:"algorithm"`
			Checksum  string `json:"checksum"`
		} `json:"integrity"`
		Contents []struct {
			Type     string `json:"type"`
			URI      string `json:"uri"`
			Checksum struct {
				Value string `json:"value"`
			} `json:"checksum"`
		} `json:"contents"`
	}
	require.NoError(t, json.Unmarshal(raw, &pkg))
	require.NotEmpty(t, pkg.Contents, "the package lists no documents, so there is nothing to reconcile")

	// One artifact entity per listed document, keyed by its filename — the
	// natural key an adapter would derive. Deriving entities from HDF fields is
	// the adapter's job; this stands in for it so the layer can be exercised.
	desired := make([]push.Entity, 0, len(pkg.Contents))
	for i, doc := range pkg.Contents {
		desired = append(desired, push.Entity{
			Kind:    push.KindArtifact,
			Key:     filepath.Base(doc.URI),
			Source:  "contents[" + strconv.Itoa(i) + "]",
			Content: map[string]any{"filename": filepath.Base(doc.URI), "type": doc.Type},
		})
	}
	ref := push.PackageRef{Name: pkg.Name, Integrity: pkg.Integrity.Checksum}

	t.Run("first push against an empty target creates everything", func(t *testing.T) {
		target := &fakeTarget{name: "in-memory", assignID: "id-1"}
		plan, err := push.Reconcile(push.Desired{PreparedAt: pkg.PreparedAt, Entities: desired}, nil, push.Policy{})
		require.NoError(t, err)
		require.Len(t, plan.Writes(), len(desired))

		receipt, err := push.Execute(context.Background(), target, "live-system", ref, plan)
		require.NoError(t, err)
		assert.Equal(t, push.ExitSuccess, push.ExitCode(receipt))
		t.Log(render(t, "plan", plan), render(t, "receipt", receipt))
	})

	t.Run("re-pushing the same package writes nothing", func(t *testing.T) {
		// The target now carries what the first push left, which is what the
		// receipt records and what content equality compares against.
		remote := make([]push.Entity, 0, len(desired))
		for _, want := range desired {
			remote = append(remote, push.Entity{
				Kind: want.Kind, Key: want.Key, ID: "id-1", Content: want.Content,
				CreatedAt: pkg.PreparedAt.Add(-time.Hour),
			})
		}
		target := &fakeTarget{name: "in-memory", remote: remote}
		plan, err := push.Reconcile(push.Desired{PreparedAt: pkg.PreparedAt, Entities: desired}, target.remote, push.Policy{})
		require.NoError(t, err)

		assert.True(t, plan.NothingToDo(), "a clean re-push must be a no-op")
		receipt, err := push.Execute(context.Background(), target, "live-system", ref, plan)
		require.NoError(t, err)
		assert.Empty(t, target.written)
		assert.Equal(t, push.ExitNothingToDo, push.ExitCode(receipt))
		t.Log(render(t, "receipt", receipt))
	})
}

func render(t *testing.T, label string, v any) string {
	t.Helper()
	out, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	return "\n" + label + ": " + string(out)
}
