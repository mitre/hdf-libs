package xccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzConvertXccdfToHDF drives the auto-detecting XCCDF entry point (results
// and benchmark paths, ARF wrappers, schema versions 1.1/1.2) with mutations
// of the real fixture corpus: it must never panic, and a nil error must come
// with valid JSON output and a document kind.
func FuzzConvertXccdfToHDF(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.xml"))
	if err != nil || len(seeds) == 0 {
		f.Fatalf("no .xml seed fixtures found: %v", err)
	}
	for _, path := range seeds {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("reading seed %s: %v", path, err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		output, kind, err := ConvertXccdfToHDF(input, "fuzz")
		if err != nil {
			return
		}
		if kind == "" {
			t.Error("nil error with empty document kind")
		}
		if !json.Valid(output) {
			t.Error("nil error with invalid JSON output")
		}
	})
}
