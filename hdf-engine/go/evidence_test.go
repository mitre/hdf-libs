package hdfengine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
