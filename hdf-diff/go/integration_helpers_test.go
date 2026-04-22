package diff

// integration_helpers_test.go provides shared fixture loading for integration tests.

import (
	"encoding/json"
	"os"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// v1FixturePair holds a pair of v1 fixtures loaded, normalized, and diffed.
type v1FixturePair struct {
	beforeRaw   map[string]any
	afterRaw    map[string]any
	before      hdf.HDFResults
	after       hdf.HDFResults
	diff        HdfComparison
	initialized bool
}

// loadV1FixturePair reads two v1-format fixture files, parses their raw JSON,
// normalizes them to v2, and computes the diff (before -> after).
// It skips the test if fixtures are not found, and fails on any parse/normalize error.
func loadV1FixturePair(t *testing.T, pair *v1FixturePair, beforeFile, afterFile string) {
	t.Helper()
	if pair.initialized {
		return
	}

	dir := fixturesDir(t)
	beforePath := dir + "/" + beforeFile
	afterPath := dir + "/" + afterFile

	if _, err := os.Stat(beforePath); os.IsNotExist(err) {
		t.Skipf("fixture %s not found -- run from monorepo root", beforeFile)
	}
	if _, err := os.Stat(afterPath); os.IsNotExist(err) {
		t.Skipf("fixture %s not found -- run from monorepo root", afterFile)
	}

	beforeData, err := os.ReadFile(beforePath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", beforeFile, err)
	}
	afterData, err := os.ReadFile(afterPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", afterFile, err)
	}

	// Parse raw JSON for v1 format detection.
	if err := json.Unmarshal(beforeData, &pair.beforeRaw); err != nil {
		t.Fatalf("failed to parse %s: %v", beforeFile, err)
	}
	if err := json.Unmarshal(afterData, &pair.afterRaw); err != nil {
		t.Fatalf("failed to parse %s: %v", afterFile, err)
	}

	// Normalize v1 -> v2.
	pair.before, _, err = ToV2(beforeData)
	if err != nil {
		t.Fatalf("failed to normalize %s: %v", beforeFile, err)
	}
	pair.after, _, err = ToV2(afterData)
	if err != nil {
		t.Fatalf("failed to normalize %s: %v", afterFile, err)
	}

	// Compute diff: before -> after.
	pair.diff, err = DiffHdf(pair.before, []hdf.HDFResults{pair.after}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	pair.initialized = true
}
