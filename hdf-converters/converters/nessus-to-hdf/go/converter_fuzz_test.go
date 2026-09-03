package nessus

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConvertNessusToHDF drives the converter with mutations of the real
// .nessus fixture corpus: it must never panic, and a nil error must come
// with a non-nil document.
func FuzzConvertNessusToHDF(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.nessus"))
	if err != nil || len(seeds) == 0 {
		f.Fatalf("no .nessus seed fixtures found: %v", err)
	}
	for _, path := range seeds {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("reading seed %s: %v", path, err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := ConvertNessusToHDF(input, "fuzz")
		if err == nil && result == nil {
			t.Error("nil error with nil result")
		}
	})
}
