package cklb

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConvertCKLBToHDF drives the converter with mutations of the real .cklb
// fixture corpus: it must never panic, and a nil error must come with a
// non-nil document.
func FuzzConvertCKLBToHDF(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.cklb"))
	if err != nil || len(seeds) == 0 {
		f.Fatalf("no .cklb seed fixtures found: %v", err)
	}
	for _, path := range seeds {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("reading seed %s: %v", path, err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := ConvertCKLBToHDF(input, "fuzz")
		if err == nil && result == nil {
			t.Error("nil error with nil result")
		}
	})
}
