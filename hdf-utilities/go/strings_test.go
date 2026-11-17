package hdfutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The TypeScript peer (asciiLower) asserts against this same table.
func TestASCIILower_SharedTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "ascii-lower-cases.json"))
	if err != nil {
		t.Fatalf("read shared table: %v", err)
	}
	var table struct {
		Cases []struct {
			Input   string `json:"input"`
			Lowered string `json:"lowered"`
			Why     string `json:"why"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("parse shared table: %v", err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("empty table would pass vacuously")
	}
	for _, c := range table.Cases {
		if got := ASCIILower(c.Input); got != c.Lowered {
			t.Errorf("ASCIILower(%q) = %q, want %q: %s", c.Input, got, c.Lowered, c.Why)
		}
	}
}
