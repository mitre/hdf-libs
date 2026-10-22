package hdfengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memFetch builds a FetchFunc over an in-memory uri→bytes map.
func memFetch(files map[string][]byte) FetchFunc {
	return func(uri string) ([]byte, error) {
		b, ok := files[uri]
		if !ok {
			return nil, fmt.Errorf("no such file: %s", uri)
		}
		return b, nil
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestVerifyChecksums_MismatchAndMatch(t *testing.T) {
	good := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	files := map[string][]byte{"good.json": good, "other.json": []byte("other")}
	contents := []EvidenceContent{
		{URI: "good.json", Type: "hdf-results", Checksum: sha256Hex(good)},
		{URI: "other.json", Type: "hdf-results", Checksum: "0000000000000000000000000000000000000000000000000000000000000000"},
		{URI: "nocs.json", Type: "hdf-system", Checksum: ""},
		{URI: "missing.json", Type: "hdf-results", Checksum: "abc"},
	}
	got := VerifyChecksums(contents, memFetch(files))
	if len(got) != 4 {
		t.Fatalf("want 4 results, got %d", len(got))
	}
	if got[0].Status != ChecksumMatch {
		t.Errorf("good.json: status=%s want match", got[0].Status)
	}
	if got[1].Status != ChecksumMismatch {
		t.Errorf("other.json: status=%s want mismatch", got[1].Status)
	}
	if got[1].Expected == "" || got[1].Actual == "" {
		t.Errorf("mismatch must carry expected+actual, got %+v", got[1])
	}
	if got[2].Status != ChecksumSkipped {
		t.Errorf("nocs.json: status=%s want skipped", got[2].Status)
	}
	if got[3].Status != ChecksumError || got[3].Error == "" {
		t.Errorf("missing.json: want error with message, got %+v", got[3])
	}
}

func TestParseEvidencePackage(t *testing.T) {
	pkg := []byte(`{
		"planRef": "plan.json",
		"contents": [
			{"type":"hdf-plan","uri":"plan.json","checksum":{"algorithm":"sha256","value":"aa"}},
			{"type":"hdf-results","uri":"r.json"}
		]
	}`)
	planRef, contents, err := ParseEvidencePackage(pkg)
	if err != nil {
		t.Fatalf("ParseEvidencePackage: %v", err)
	}
	if planRef != "plan.json" {
		t.Errorf("planRef=%q", planRef)
	}
	if len(contents) != 2 {
		t.Fatalf("want 2 contents, got %d", len(contents))
	}
	if contents[0].Checksum != "aa" {
		t.Errorf("contents[0].Checksum=%q want aa", contents[0].Checksum)
	}
	if contents[1].Checksum != "" {
		t.Errorf("contents[1] should have empty checksum, got %q", contents[1].Checksum)
	}
}

func TestParseEvidencePackage_Invalid(t *testing.T) {
	if _, _, err := ParseEvidencePackage([]byte("not json")); err == nil {
		t.Fatal("expected error on malformed package")
	}
}

func TestPlannedBaselineRefs(t *testing.T) {
	plan := []byte(`{"assessments":[{"baselineRef":"A"},{"baselineRef":"B"},{"baselineRef":"A"},{"baselineRef":""}]}`)
	got, err := PlannedBaselineRefs(plan)
	if err != nil {
		t.Fatalf("PlannedBaselineRefs: %v", err)
	}
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("want [A B] deduped in order, got %v", got)
	}
	if _, err := PlannedBaselineRefs([]byte("x")); err == nil {
		t.Fatal("expected error on malformed plan")
	}
}

func TestCoveredBaselineNames(t *testing.T) {
	results := []byte(`{"baselines":[{"name":"RHEL9-STIG"},{"name":""},{"name":"RHEL9-STIG"}]}`)
	got, err := CoveredBaselineNames(results)
	if err != nil {
		t.Fatalf("CoveredBaselineNames: %v", err)
	}
	if len(got) != 1 || got[0] != "RHEL9-STIG" {
		t.Fatalf("want [RHEL9-STIG] deduped, got %v", got)
	}
	if _, err := CoveredBaselineNames([]byte("x")); err == nil {
		t.Fatal("expected error on malformed results")
	}
}

func TestCompleteness(t *testing.T) {
	comp := Completeness([]string{"A", "B", "C"}, []string{"B"})
	if comp.Complete {
		t.Error("should be incomplete")
	}
	if len(comp.Missing) != 2 || comp.Missing[0] != "A" || comp.Missing[1] != "C" {
		t.Fatalf("missing should be sorted [A C], got %v", comp.Missing)
	}
	full := Completeness([]string{"A"}, []string{"A", "extra"})
	if !full.Complete || len(full.Missing) != 0 {
		t.Fatalf("should be complete, got %+v", full)
	}
}

// Only hdf-results entries with a URI are consulted; a fetch failure or an
// unparseable document is skipped rather than failing the aggregation.
func TestPackageAggregators_SkipNonResultsUnreadableAndUnparseable(t *testing.T) {
	agent := []byte(`{"baselines":[{"name":"A","requirements":[{"statusOverrides":[{"appliedBy":{"type":"agent"}}]}]}]}`)
	files := map[string][]byte{"a.json": agent, "b.json": []byte("not json"), "base.json": agent}
	contents := []EvidenceContent{
		{URI: "a.json", Type: "hdf-results"},
		{URI: "b.json", Type: "hdf-results"},
		{URI: "missing.json", Type: "hdf-results"},
		{URI: "", Type: "hdf-results"},
		{URI: "base.json", Type: "hdf-baseline"},
	}
	fetch := memFetch(files)
	covered := CoveredBaselinesInPackage(contents, fetch)
	if len(covered) != 1 || covered[0] != "A" {
		t.Fatalf("covered = %v, want [A]", covered)
	}
	if got := AgentOverridesInPackage(contents, fetch); got != 1 {
		t.Fatalf("agent overrides = %d, want 1", got)
	}
	if got := CoveredBaselinesInPackage(nil, fetch); got != nil {
		t.Fatalf("empty package must yield no covered names, got %v", got)
	}
}

// Real InSpec-derived HDF carries zone-less result timestamps, which a typed
// decode rejects outright — so a package referencing one must still be counted,
// not silently skipped as unparseable.
func TestAgentOverridesInPackage_CountsZonelessTimestamps(t *testing.T) {
	zoneless := []byte(`{"baselines":[{"name":"A","requirements":[{"statusOverrides":[{"appliedBy":{"type":"agent"}}],` +
		`"results":[{"status":"passed","startTime":"2024-01-01T00:00:00"}]}]}]}`)
	contents := []EvidenceContent{{URI: "z.json", Type: "hdf-results"}}
	fetch := memFetch(map[string][]byte{"z.json": zoneless})
	if got := AgentOverridesInPackage(contents, fetch); got != 1 {
		t.Fatalf("agent overrides = %d, want 1 — a zone-less startTime must not drop the document", got)
	}
}

// The count deliberately does not require a schema-valid document: an agent's
// judgment is worth reporting even where validation would reject the file. This
// pins that choice, which is otherwise only stated in a comment.
func TestAgentOverridesInPackage_CountsSchemaInvalidDocuments(t *testing.T) {
	// No baseline name and no results: rejected by the schema, decodable as JSON.
	invalid := []byte(`{"baselines":[{"requirements":[{"statusOverrides":[{"appliedBy":{"type":"agent"}}]}]}]}`)
	contents := []EvidenceContent{{URI: "bad.json", Type: "hdf-results"}}
	fetch := memFetch(map[string][]byte{"bad.json": invalid})
	if got := AgentOverridesInPackage(contents, fetch); got != 1 {
		t.Fatalf("agent overrides = %d, want 1 — schema validity is deliberately not required", got)
	}
}

// The schema's Hash_Algorithm enum is sha256|sha384|sha512|blake3, so flattening
// a checksum to its value loses which algorithm the package recorded and leaves
// every caller guessing. VerifyChecksums guessed sha256, which reports a correct
// sha512 as a mismatch — telling an operator their evidence changed when it did not.
func TestParseEvidencePackage_KeepsTheChecksumAlgorithm(t *testing.T) {
	pkg := []byte(`{
	  "name": "p",
	  "contents": [
	    {"type": "hdf-results", "uri": "a.json", "checksum": {"algorithm": "sha512", "value": "abc"}},
	    {"type": "hdf-plan",    "uri": "b.json", "checksum": {"value": "def"}},
	    {"type": "bom",         "uri": "c.json"}
	  ]
	}`)

	_, contents, err := ParseEvidencePackage(pkg)
	if err != nil {
		t.Fatalf("ParseEvidencePackage: %v", err)
	}
	if len(contents) != 3 {
		t.Fatalf("contents = %d entries, want 3", len(contents))
	}
	if got := contents[0].ChecksumAlgorithm; got != "sha512" {
		t.Errorf("entry 0 algorithm = %q, want sha512", got)
	}
	// An absent algorithm stays absent on the struct; the sha256 default belongs
	// to verification, not to the parse, so a round-trip cannot invent a value.
	if got := contents[1].ChecksumAlgorithm; got != "" {
		t.Errorf("entry 1 algorithm = %q, want empty for an unstated algorithm", got)
	}
	if got := contents[2].ChecksumAlgorithm; got != "" {
		t.Errorf("entry 2 algorithm = %q, want empty when there is no checksum", got)
	}
	if contents[0].Checksum != "abc" || contents[1].Checksum != "def" || contents[2].Checksum != "" {
		t.Errorf("values = %q/%q/%q, want abc/def/empty",
			contents[0].Checksum, contents[1].Checksum, contents[2].Checksum)
	}
}

// VerifyChecksums hashed sha256 regardless of what the entry recorded, so a
// package carrying a CORRECT sha512 was reported as a mismatch. The statuses below
// are the contract: an algorithm this build cannot compute is UNSUPPORTED — never a
// mismatch, which asserts the evidence changed, and never an error, which asserts
// something went wrong when the bytes may be perfectly intact.
func TestVerifyChecksums_HonoursTheRecordedAlgorithm(t *testing.T) {
	data := []byte(`{"hello":"world"}`)
	fetch := func(string) ([]byte, error) { return data, nil }

	hexOf := func(algorithm string) string {
		t.Helper()
		h, err := ChecksumHex(algorithm, data)
		if err != nil {
			t.Fatalf("ChecksumHex(%q): %v", algorithm, err)
		}
		return h
	}

	for _, tc := range []struct {
		name      string
		algorithm string
		value     string
		want      ChecksumStatus
		wantErr   string
	}{
		{name: "sha256 stated", algorithm: "sha256", value: hexOf("sha256"), want: ChecksumMatch},
		{name: "sha384 stated", algorithm: "sha384", value: hexOf("sha384"), want: ChecksumMatch},
		{name: "sha512 stated", algorithm: "sha512", value: hexOf("sha512"), want: ChecksumMatch},
		// An unstated algorithm must keep meaning sha256, or every package already
		// written changes meaning under this change.
		{name: "algorithm absent defaults to sha256", algorithm: "", value: hexOf("sha256"), want: ChecksumMatch},
		// The sha256 of the same bytes is not its sha512, so guessing sha256 for a
		// sha512 entry is exactly the false mismatch this card removes.
		{name: "sha512 entry is not compared as sha256", algorithm: "sha512", value: hexOf("sha256"), want: ChecksumMismatch},
		{name: "a genuinely wrong sha512 still mismatches", algorithm: "sha512", value: "00", want: ChecksumMismatch},
		{name: "blake3 stated", algorithm: "blake3", value: hexOf("blake3"), want: ChecksumMatch},
		// The point of computing blake3 at all: a wrong one has to FAIL, where it was
		// previously waved through as unverifiable.
		{name: "a genuinely wrong blake3 mismatches", algorithm: "blake3", value: "00", want: ChecksumMismatch},
		{name: "blake3 entry is not compared as sha256", algorithm: "blake3", value: hexOf("sha256"), want: ChecksumMismatch},
		{
			// md5 can only arrive in an off-schema document: Hash_Algorithm admits only
			// sha256, sha384, sha512 and blake3, every one of which this build now computes.
			// So unsupported is reachable ONLY from outside the enum.
			name: "an off-enum algorithm is unsupported", algorithm: "md5", value: hexOf("sha256"),
			want: ChecksumUnsupported, wantErr: `unsupported checksum algorithm "md5"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyChecksums([]EvidenceContent{{
				URI: "a.json", Type: "hdf-results",
				Checksum: tc.value, ChecksumAlgorithm: tc.algorithm,
			}}, fetch)
			if len(got) != 1 {
				t.Fatalf("got %d results, want 1", len(got))
			}
			if got[0].Status != tc.want {
				t.Errorf("status = %s, want %s (error: %q)", got[0].Status, tc.want, got[0].Error)
			}
			if tc.wantErr != "" && !strings.Contains(got[0].Error, tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", got[0].Error, tc.wantErr)
			}
			if tc.want == ChecksumUnsupported && got[0].Actual != "" {
				t.Errorf("an unverifiable entry must not report an actual hash, got %q", got[0].Actual)
			}
		})
	}
}

// A skipped entry has no checksum VALUE to verify. It either carries no checksum at
// all, or carries one whose value is blank — schema-valid, since Checksum.value has
// no minLength — and that second case DOES name an algorithm, which is why the
// rationale is "nothing was hashed" rather than "the package made no claim".
func TestVerifyChecksums_ReportsNoAlgorithmForAnEntryItNeverHashed(t *testing.T) {
	fetch := func(string) ([]byte, error) { return []byte("x"), nil }
	got := VerifyChecksums([]EvidenceContent{
		{URI: "none.json", Type: "bom"},
		{URI: "empty.json", Type: "bom", Checksum: "", ChecksumAlgorithm: "sha512", ChecksumRecorded: true},
	}, fetch)
	for i, r := range got {
		if r.Status != ChecksumSkipped {
			t.Fatalf("entry %d status = %s, want skipped", i, r.Status)
		}
		if r.Algorithm != "" {
			t.Errorf("entry %d reported algorithm %q; a skipped entry was never hashed", i, r.Algorithm)
		}
	}
}

// An algorithm this build cannot compute is not the same failure as a file it
// cannot read: the bytes may be perfectly intact and the package perfectly valid.
// Conflating the two made a schema-valid blake3 package fail verification, while a
// package recording a reference nobody can reach passes — both are claims this tool
// cannot check, so the asymmetry was accidental. Kept distinct so each caller
// chooses: the CLI reports it and does not fail, the MCP notices it and stays valid.
func TestVerifyChecksums_SeparatesAnUncomputableAlgorithmFromAReadFailure(t *testing.T) {
	data := []byte(`{"hello":"world"}`)
	present := func(string) ([]byte, error) { return data, nil }
	absent := func(string) ([]byte, error) { return nil, errors.New("file not found") }

	// md5, not blake3: every algorithm the schema admits is now computable, so the only
	// way to reach "uncomputable" is an off-schema document.
	got := VerifyChecksums([]EvidenceContent{
		{URI: "a.json", Type: "hdf-system", Checksum: "ab", ChecksumAlgorithm: "md5", ChecksumRecorded: true},
	}, present)
	if got[0].Status != ChecksumUnsupported {
		t.Errorf("md5 status = %s, want %s", got[0].Status, ChecksumUnsupported)
	}
	if !strings.Contains(got[0].Error, `unsupported checksum algorithm "md5"`) {
		t.Errorf("error = %q, want it to name the algorithm", got[0].Error)
	}
	if got[0].Actual != "" {
		t.Errorf("nothing was hashed, so actual must be empty, got %q", got[0].Actual)
	}

	// A genuine read failure stays an error — this is the distinction, so it is
	// asserted alongside rather than in a separate test.
	readFail := VerifyChecksums([]EvidenceContent{
		{URI: "b.json", Type: "hdf-results", Checksum: "ab", ChecksumAlgorithm: "sha256", ChecksumRecorded: true},
	}, absent)
	if readFail[0].Status != ChecksumError {
		t.Errorf("unreadable file status = %s, want %s", readFail[0].Status, ChecksumError)
	}
}

// blake3Vectors is the committed subset of the BLAKE3 reference implementation's own
// test_vectors.json (see testdata/blake3-vectors.json, which records its provenance). The
// expected digests therefore come from the specification's authors, not from the library
// this repo depends on — a digest produced by that library and pasted back in would prove
// only that it agrees with itself.
type blake3Vectors struct {
	Cases []struct {
		InputLen int    `json:"input_len"`
		Hash     string `json:"hash"`
	} `json:"cases"`
}

// blake3VectorInput builds the input the vector file specifies: the first n bytes of the
// repeating 251-byte sequence 0, 1, 2, ..., 250, 0, 1, ... Generated here rather than
// committed, so the rule is stated in code in both languages.
func blake3VectorInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func loadBlake3Vectors(t *testing.T) blake3Vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "blake3-vectors.json"))
	if err != nil {
		t.Fatalf("reading the committed BLAKE3 vectors: %v", err)
	}
	var v blake3Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing the committed BLAKE3 vectors: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("the committed BLAKE3 vectors are empty, so this test would assert nothing")
	}
	return v
}

func TestChecksumHex_ComputesBlake3(t *testing.T) {
	v := loadBlake3Vectors(t)

	// Named explicitly so a vector file that lost its multi-chunk cases fails here rather
	// than silently narrowing coverage to inputs below one chunk.
	var sawEmpty, sawMultiChunk bool
	for _, c := range v.Cases {
		switch {
		case c.InputLen == 0:
			sawEmpty = true
		case c.InputLen > 1024:
			sawMultiChunk = true
		}

		got, err := ChecksumHex("blake3", blake3VectorInput(c.InputLen))
		if err != nil {
			t.Fatalf("ChecksumHex(blake3, %d bytes): %v", c.InputLen, err)
		}
		// The vector's hash is an extended output; a default-length digest is its first
		// 32 bytes, which is what the upstream file directs implementations to check.
		want := c.Hash[:64]
		if got != want {
			t.Errorf("ChecksumHex(blake3, %d bytes) = %s, want %s", c.InputLen, got, want)
		}
	}
	if !sawEmpty {
		t.Error("no empty-input vector was exercised")
	}
	if !sawMultiChunk {
		t.Error("no multi-chunk vector was exercised, so the parent-node path is untested")
	}
}

// An off-schema algorithm still has to be refused: no schema-valid document can carry one,
// but the status exists for documents this tooling did not write. The WHOLE message is
// pinned, list included, because the TypeScript peer asserts the identical string — that
// is what keeps one refusal from drifting into two spellings across the two languages.
func TestChecksumHex_StillRefusesAnOffSchemaAlgorithm(t *testing.T) {
	_, err := ChecksumHex("md5", []byte("x"))
	if err == nil {
		t.Fatal("ChecksumHex(md5) returned no error; an off-schema algorithm must be refused")
	}
	const want = `unsupported checksum algorithm "md5": this build computes sha256, sha384, sha512 and blake3`
	if err.Error() != want {
		t.Errorf("message = %q, want %q (the TypeScript peer asserts this same string)", err.Error(), want)
	}
}

// The SHARED table, read rather than restated, so Go and TypeScript cannot drift: both
// read testdata/reference-decode-vectors.json and a divergence fails on one side.
func TestDecodeReference_MatchesTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "reference-decode-vectors.json"))
	if err != nil {
		t.Fatalf("the shared table is the contract; without it this test proves nothing: %v", err)
	}
	var table struct {
		Vectors []struct {
			Why       string `json:"why"`
			URI       string `json:"uri"`
			Decoded   string `json:"decoded"`
			Malformed bool   `json:"malformed"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("read the shared table: %v", err)
	}
	if len(table.Vectors) <= 5 {
		t.Fatalf("a pass must not mean an empty table: got %d vectors", len(table.Vectors))
	}

	for _, v := range table.Vectors {
		t.Run(v.Why, func(t *testing.T) {
			got, decErr := DecodeReference(v.URI)
			if v.Malformed {
				if decErr == nil {
					t.Fatalf("%q is malformed and must be reported, not guessed at; got %q", v.URI, got)
				}
				if !strings.Contains(decErr.Error(), "not a valid uri-reference") {
					t.Errorf("the error must name the contract it breaks: %v", decErr)
				}
				return
			}
			if decErr != nil {
				t.Fatalf("decode %q: %v", v.URI, decErr)
			}
			if got != v.Decoded {
				t.Errorf("decode %q = %q, want %q", v.URI, got, v.Decoded)
			}
		})
	}
}
