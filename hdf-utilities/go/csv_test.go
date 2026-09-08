package hdfutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type csvSanitizeCase struct {
	Value     string `json:"value"`
	Sanitized string `json:"sanitized"`
	Why       string `json:"why"`
}

func loadCSVSanitizeCases(t *testing.T) ([]string, []csvSanitizeCase) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "csv-sanitize-cases.json"))
	if err != nil {
		t.Fatalf("read shared table: %v", err)
	}
	var table struct {
		Triggers []string          `json:"triggers"`
		Cases    []csvSanitizeCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("parse shared table: %v", err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("empty table would pass vacuously")
	}
	return table.Triggers, table.Cases
}

// The trigger set is a security policy, so it lives in one table both languages
// read rather than in two hand-kept copies: adding a character to one side alone
// leaves the other exporting CSVs a spreadsheet will execute.
func TestSanitizeCSVValue_MatchesSharedTable(t *testing.T) {
	_, cases := loadCSVSanitizeCases(t)
	for _, c := range cases {
		if got := SanitizeCSVValue(c.Value); got != c.Sanitized {
			t.Errorf("SanitizeCSVValue(%q) = %q, want %q — %s", c.Value, got, c.Sanitized, c.Why)
		}
	}
}

// Guards the table itself: every declared trigger must actually be neutralised,
// so a character added to the list without being handled fails here.
func TestSanitizeCSVValue_EveryDeclaredTriggerIsNeutralised(t *testing.T) {
	triggers, _ := loadCSVSanitizeCases(t)
	if len(triggers) == 0 {
		t.Fatal("no triggers declared")
	}
	for _, trigger := range triggers {
		in := trigger + "payload"
		if got := SanitizeCSVValue(in); got != "'"+in {
			t.Errorf("declared trigger %q is not neutralised: SanitizeCSVValue(%q) = %q", trigger, in, got)
		}
	}
}
