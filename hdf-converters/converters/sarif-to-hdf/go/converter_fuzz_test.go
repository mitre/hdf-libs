package sarif

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConvertSarifToHDF drives the SARIF base entry point that the checkov,
// gosec, msft-defender-devops, semgrep, snyk, trivy and zap converters all
// delegate to, using mutations of the real .sarif fixture corpus (2.0 and 2.1
// inputs from several producers). It must never panic, and a nil error must
// come with a non-nil document.
func FuzzConvertSarifToHDF(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.sarif"))
	if err != nil || len(seeds) == 0 {
		f.Fatalf("no .sarif seed fixtures found: %v", err)
	}
	for _, path := range seeds {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("reading seed %s: %v", path, err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := ConvertSarifToHDF(input, "fuzz")
		if err == nil && result == nil {
			t.Error("nil error with nil result")
		}
	})
}
