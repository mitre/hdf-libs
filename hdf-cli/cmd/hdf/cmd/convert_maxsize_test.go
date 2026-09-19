package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// A converter's own input guard must honor the configured process default (set by
// the CLI from --max-size), for both JSON and XML converters — the #334 fix. Before
// it, the guard passed a literal 0 = the built-in default no matter the flag.
// Exercised directly at the converter (no CLI, no giant fixture): lower the
// configured default and hand each converter a tiny over-limit input.
func TestConverterGuardHonorsConfiguredDefault(t *testing.T) {
	t.Cleanup(func() { hdfutil.SetDefaultMaxInputSize(0) })
	hdfutil.SetDefaultMaxInputSize(1024)

	for _, from := range []string{"grype" /* JSON */, "nessus" /* XML */} {
		t.Run(from, func(t *testing.T) {
			conv, err := GetConverter(from, "hdf")
			if err != nil {
				t.Fatalf("GetConverter(%s): %v", from, err)
			}
			// 2 KiB > the 1 KiB configured default; the size guard runs before any
			// parse, so the bytes need not be valid input.
			if _, err := conv.Convert(make([]byte, 2048)); err == nil ||
				!strings.Contains(err.Error(), "exceeds maximum") {
				t.Fatalf("%s converter should reject input over the configured default; got %v", from, err)
			}
		})
	}
}

// The CLI threads --max-size into the convert read path: a file over a small
// --max-size is rejected, so the flag actually governs convert input.
func TestConvertCommand_MaxSizeCapsRead(t *testing.T) {
	t.Cleanup(func() { hdfutil.SetDefaultMaxInputSize(0) })
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, make([]byte, 2*1024*1024), 0o600); err != nil { // 2 MB
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "o.json")
	_, stderr, err := executeCommand("convert", "--from", "grype", path, "--max-size", "1", "-o", out)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("convert should reject a 2 MB input under --max-size 1; err=%v stderr=%s", err, stderr)
	}
}

// outputSizeWarning fires only when output exceeds the default read limit, and
// names the --max-size a downstream read will need. Pure function → no giant
// conversion needed to exercise it.
func TestOutputSizeWarning(t *testing.T) {
	if got := outputSizeWarning(hdfutil.DefaultMaxInputSize); got != "" {
		t.Errorf("no warning expected at/below the default; got %q", got)
	}
	if got := outputSizeWarning(1024); got != "" {
		t.Errorf("no warning for small output; got %q", got)
	}
	over := hdfutil.DefaultMaxInputSize + 5*1024*1024
	got := outputSizeWarning(over)
	if got == "" {
		t.Fatal("expected a warning for output over the default read limit")
	}
	for _, want := range []string{"default read limit", "downstream", "--max-size"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q missing %q", got, want)
		}
	}
}
