package hdfengine

import (
	"os"
	"path/filepath"
	"testing"
)

// The cross-language parity contract for the evidence-verify engine: over the
// shared committed fixtures under hdf-engine/testdata/evidence, Go and the TS
// peer (test/evidence.test.ts) must agree on planned baseline refs, covered
// baseline names, the completeness diff, and the checksum classification. This
// table is asserted here on the Go side; test/evidence.test.ts asserts the SAME
// fixtures to the SAME expected values on the TS side. A behavioural divergence
// fails one side of the pair. See loader_parity_test.go for the same pattern.
func TestEvidence_CrossLanguageParity(t *testing.T) {
	dir := filepath.Join("..", "testdata", "evidence")
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return b
	}
	fetch := func(uri string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, uri)) }

	planned, err := PlannedBaselineRefs(read("plan.json"))
	if err != nil {
		t.Fatalf("PlannedBaselineRefs: %v", err)
	}
	if len(planned) != 2 || planned[0] != "RHEL9-STIG" || planned[1] != "PostgreSQL-STIG" {
		t.Fatalf("planned = %v, want [RHEL9-STIG PostgreSQL-STIG]", planned)
	}

	covered, err := CoveredBaselineNames(read("rhel-results.json"))
	if err != nil {
		t.Fatalf("CoveredBaselineNames: %v", err)
	}
	if len(covered) != 1 || covered[0] != "RHEL9-STIG" {
		t.Fatalf("covered = %v, want [RHEL9-STIG]", covered)
	}

	comp := Completeness(planned, covered)
	if comp.Complete {
		t.Error("completeness should be incomplete")
	}
	if len(comp.Missing) != 1 || comp.Missing[0] != "PostgreSQL-STIG" {
		t.Fatalf("missing = %v, want [PostgreSQL-STIG]", comp.Missing)
	}

	// Checksums: a correct hash matches, a wrong hash mismatches, empty skips.
	goodHash := sha256HexOf(read("rhel-results.json"))
	contents := []EvidenceContent{
		{URI: "rhel-results.json", Type: "hdf-results", Checksum: goodHash},
		{URI: "plan.json", Type: "hdf-plan", Checksum: "0000000000000000000000000000000000000000000000000000000000000000"},
		{URI: "rhel-results.json", Type: "hdf-results", Checksum: ""},
	}
	got := VerifyChecksums(contents, fetch)
	wantStatus := []ChecksumStatus{ChecksumMatch, ChecksumMismatch, ChecksumSkipped}
	for i, w := range wantStatus {
		if got[i].Status != w {
			t.Errorf("checksum[%d] status = %s, want %s", i, got[i].Status, w)
		}
	}
}
