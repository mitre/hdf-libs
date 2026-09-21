package nist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The TypeScript peer (test/nist.test.ts) asserts this same table, which is what
// keeps the two normalizers agreeing on every spelling.
type spellingCase struct {
	Input      string          `json:"input"`
	Normalized *string         `json:"normalized"`
	Exists     map[string]bool `json:"exists"`
	Why        string          `json:"why"`
}

func loadSpellingCases(t *testing.T) []spellingCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "nist-id-spelling-cases.json"))
	if err != nil {
		t.Fatalf("shared spelling table is unreadable: %v", err)
	}
	var table struct {
		Cases []spellingCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("shared spelling table is invalid JSON: %v", err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("shared spelling table has no cases")
	}
	return table.Cases
}

func TestNormalizeIDSpellingCases(t *testing.T) {
	for _, c := range loadSpellingCases(t) {
		t.Run(c.Input, func(t *testing.T) {
			got, ok := NormalizeID(c.Input)
			if c.Normalized == nil {
				if ok {
					t.Errorf("NormalizeID(%q) = %q, want no match (%s)", c.Input, got, c.Why)
				}
				return
			}
			if !ok || got != *c.Normalized {
				t.Errorf("NormalizeID(%q) = %q, %v; want %q (%s)", c.Input, got, ok, *c.Normalized, c.Why)
			}
		})
	}
}

func TestNistExistsSpellingCases(t *testing.T) {
	for _, c := range loadSpellingCases(t) {
		t.Run(c.Input, func(t *testing.T) {
			if len(c.Exists) != len(SupportedRevisions()) {
				t.Fatalf("case %q must give a result for every supported revision %v", c.Input, SupportedRevisions())
			}
			for _, rev := range SupportedRevisions() {
				want, ok := c.Exists[strconv.Itoa(rev)]
				if !ok {
					t.Fatalf("case %q has no result for revision %d", c.Input, rev)
				}
				if got := NistExistsForRevision(c.Input, rev); got != want {
					t.Errorf("NistExistsForRevision(%q, %d) = %v, want %v (%s)", c.Input, rev, got, want, c.Why)
				}
			}
		})
	}
}

func TestNistExistsAcceptsEveryDescriptionKey(t *testing.T) {
	for _, rev := range SupportedRevisions() {
		ids := descriptionIDsFor(rev)
		if len(ids) == 0 {
			t.Fatalf("no description ids loaded for revision %d", rev)
		}
		for id := range ids {
			if !NistExistsForRevision(id, rev) {
				t.Errorf("NistExistsForRevision(%q, %d) = false for a description key", id, rev)
			}
			if got, ok := NormalizeID(id); !ok || got != id {
				t.Errorf("NormalizeID(%q) = %q, %v; a description key must normalize to itself", id, got, ok)
			}
		}
	}
}

func TestNistExistsUsesProcessRevision(t *testing.T) {
	defer ResetRevision()

	if !NistExists("SR-3") {
		t.Error("NistExists(SR-3) = false at the default revision, want true")
	}
	if err := SetRevision(4); err != nil {
		t.Fatalf("SetRevision(4): %v", err)
	}
	if NistExists("SR-3") {
		t.Error("NistExists(SR-3) = true at revision 4, want false")
	}
}

func TestNistExistsUnsupportedRevisionUsesDefaultData(t *testing.T) {
	if got, want := NistExistsForRevision("SR-3", 99), NistExistsForRevision("SR-3", DefaultRevision); got != want {
		t.Errorf("NistExistsForRevision(SR-3, 99) = %v, want the default revision's %v", got, want)
	}
}

func TestParseDescriptionIDsRejectsInvalidJSON(t *testing.T) {
	if _, err := parseDescriptionIDs([]byte("{")); err == nil {
		t.Error("parseDescriptionIDs accepted invalid JSON")
	}
}
