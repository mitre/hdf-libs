package shared

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// MustFindRequirement returns the requirement with the given ID from reqs, or
// fails the test if none matches. Returning a value the caller uses directly
// (rather than the find-then-manual-nil-check pattern) keeps staticcheck's
// SA5011 dataflow satisfied — it does not treat t.Fatal as terminating, so a
// deref after an inline nil guard reads as a possible nil dereference.
func MustFindRequirement(t *testing.T, reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	t.Helper()
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	t.Fatalf("expected requirement %q not found", id)
	return nil
}
