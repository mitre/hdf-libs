package veracode

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConvertVeracodeToHDF drives the converter with mutations of the real
// Veracode detailed-report XML fixture corpus: it must never panic, and a nil
// error must come with a non-nil document.
func FuzzConvertVeracodeToHDF(f *testing.F) {
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
		result, err := ConvertVeracodeToHDF(input, "fuzz")
		if err == nil && result == nil {
			t.Error("nil error with nil result")
		}
	})
}
