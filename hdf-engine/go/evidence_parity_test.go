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
	goodHash, hashErr := ChecksumHex("sha256", read("rhel-results.json"))
	if hashErr != nil {
		t.Fatalf("ChecksumHex: %v", hashErr)
	}
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

// ParseExternalEvidence joins the parity contract: the shared package fixture carries
// three externalEvidence shapes — a recorded checksum, a recorded-but-BLANK value, and
// no checksum object — and both languages must preserve all three distinctions, because
// a blank value is unverifiable while an absent one is not a claim at all. The same
// assertions run in test/evidence.test.ts against the same fixture.
func TestExternalEvidence_CrossLanguageParity(t *testing.T) {
	dir := filepath.Join("..", "testdata", "evidence")
	pkg, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	entries, err := ParseExternalEvidence(pkg)
	if err != nil {
		t.Fatalf("ParseExternalEvidence: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d externalEvidence entries, want 4", len(entries))
	}

	want := []struct {
		uri, format, checksum string
		recorded              bool
	}{
		{"rhel-results.json", "raw-log", "128300c53536f190fe8f9f1161d55965142e7621de9223fe49ce7fe082b77282", true},
		{"agent-results.json", "ecs", "", true},
		{"plan.json", "ocsf", "", false},
		// An EMPTY uri is schema-valid (uri is required but has no minLength) and must
		// SURVIVE the parse rather than be dropped, so a caller can report an entry that
		// names nothing to carry. That property used to live in the CLI; it moved here
		// when bundle's own parse became an adapter over this function, so it needs a
		// test in this module rather than relying on one in another.
		{"", "spdx", "", false},
	}
	for i, w := range want {
		got := entries[i]
		if got.URI != w.uri || got.Format != w.format {
			t.Errorf("entry[%d] = {%s %s}, want {%s %s}", i, got.URI, got.Format, w.uri, w.format)
		}
		if got.Checksum != w.checksum || got.ChecksumRecorded != w.recorded {
			t.Errorf("entry[%d] checksum = %q recorded=%t, want %q recorded=%t",
				i, got.Checksum, got.ChecksumRecorded, w.checksum, w.recorded)
		}
		// Type belongs to contents[]; an external entry must not borrow it.
		if got.Type != "" {
			t.Errorf("entry[%d] Type = %q, want empty — externalEvidence records a format, not a Content_Type", i, got.Type)
		}
	}

	// And the SAME verifier runs on them: one implementation of the hashing, not one
	// per array. The three shapes classify as match / skipped / skipped.
	fetch := func(uri string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, uri)) }
	results := VerifyChecksums(entries, fetch)
	wantStatus := []ChecksumStatus{ChecksumMatch, ChecksumSkipped, ChecksumSkipped, ChecksumSkipped}
	for i, w := range wantStatus {
		if results[i].Status != w {
			t.Errorf("externalEvidence[%d] status = %s, want %s", i, results[i].Status, w)
		}
		// Carried through, not dropped: a caller reporting the result needs to know
		// what the artifact is without reading Type's vocabulary onto it.
		if results[i].Format != want[i].format {
			t.Errorf("externalEvidence[%d] result Format = %q, want %q", i, results[i].Format, want[i].format)
		}
	}
}

// The package-level aggregators walk the same shared package fixture in both languages:
// every hdf-results entry is fetched and parsed and the per-document results are
// concatenated in entry order. The skip-an-unreadable-entry path is NOT exercised here —
// every entry this fixture names now resolves — and is covered by the unit tests in both
// languages instead.
func TestEvidence_PackageAggregation_CrossLanguageParity(t *testing.T) {
	dir := filepath.Join("..", "testdata", "evidence")
	pkg, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	fetch := func(uri string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, uri)) }
	_, contents, err := ParseEvidencePackage(pkg)
	if err != nil {
		t.Fatalf("ParseEvidencePackage: %v", err)
	}

	covered := CoveredBaselinesInPackage(contents, fetch)
	want := []string{"RHEL9-STIG", "PostgreSQL-STIG", "RHEL9-STIG"}
	if len(covered) != len(want) {
		t.Fatalf("covered = %v, want %v", covered, want)
	}
	for i := range want {
		if covered[i] != want[i] {
			t.Fatalf("covered = %v, want %v", covered, want)
		}
	}
	if got := AgentOverridesInPackage(contents, fetch); got != 2 {
		t.Fatalf("agent overrides = %d, want 2 (system and username overrides excluded)", got)
	}
}

// The checksum-algorithm contract, pinned on the SHARED package fixture so both
// languages read the same recorded algorithms rather than two hand-kept copies.
// test/evidence.test.ts asserts these same four outcomes over the same file.
// The fixture states an algorithm on every entry because the schema's Checksum
// requires one — the sha256 default for an omitted algorithm is defensive
// handling of off-schema input and is pinned by each language's unit tests.
func TestEvidence_ChecksumAlgorithm_CrossLanguageParity(t *testing.T) {
	dir := filepath.Join("..", "testdata", "evidence")
	pkg, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	fetch := func(uri string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, uri)) }

	_, contents, err := ParseEvidencePackage(pkg)
	if err != nil {
		t.Fatalf("ParseEvidencePackage: %v", err)
	}

	wantAlgorithms := []string{"sha512", "sha384", "sha256", "blake3"}
	for i, want := range wantAlgorithms {
		if got := contents[i].ChecksumAlgorithm; got != want {
			t.Errorf("contents[%d] algorithm = %q, want %q", i, got, want)
		}
	}

	// Each entry records a CORRECT hash under its own algorithm, so guessing sha256 for any
	// of them would report a mismatch. Entries [0] and [3] name the SAME file under sha512
	// and blake3: one set of bytes, two algorithms, both of which must match, which is what
	// pins the two languages' blake3 against one real document. It is the PLAN rather than a
	// results document deliberately — a second hdf-results entry for one file would be
	// counted twice by the aggregation helpers, making this fixture's blake3 coverage change
	// a different test's subject.
	got := VerifyChecksums(contents, fetch)
	wantStatus := []ChecksumStatus{ChecksumMatch, ChecksumMatch, ChecksumMatch, ChecksumMatch}
	for i, want := range wantStatus {
		if got[i].Status != want {
			t.Errorf("checksum[%d] (%s) status = %s, want %s — error %q",
				i, contents[i].ChecksumAlgorithm, got[i].Status, want, got[i].Error)
		}
	}
	if got[3].Algorithm != "blake3" {
		t.Errorf("checksum[3] algorithm = %q, want blake3", got[3].Algorithm)
	}
	// Only a mismatch carries expected+actual, so a match reports no actual hash. Asserted
	// so the blake3 entry is held to the same contract as every other status.
	if got[3].Actual != "" {
		t.Errorf("a matched entry reports no actual hash, got %q", got[3].Actual)
	}
}
