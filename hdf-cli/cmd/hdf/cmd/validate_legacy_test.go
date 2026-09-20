package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A minimal well-formed InSpec exec-json (legacy HDF v2) document: profiles[] +
// platform, which looksLikeLegacyHDFv2 keys on. hdf convert detects this shape at
// 100% confidence, but hdf validate only knows the v3 schemas.
const minimalLegacyInSpec = `{
  "platform": {"name": "test", "release": "1.0.0"},
  "version": "5.22.0",
  "statistics": {"duration": 0.01},
  "profiles": [{"name": "p", "version": "1.0.0", "supports": [], "controls": [], "groups": [], "attributes": [], "sha256": ""}]
}`

func writeLegacyInSpec(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "min-v1.json")
	if err := os.WriteFile(path, []byte(minimalLegacyInSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertLegacyRedirect(t *testing.T, stderr string) {
	t.Helper()
	// Names the legacy InSpec exec-json shape and points at convert...
	if !strings.Contains(stderr, "InSpec exec-json") {
		t.Errorf("expected the error to name the legacy InSpec exec-json shape; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "hdf convert") {
		t.Errorf("expected the error to point at hdf convert; stderr=%s", stderr)
	}
	// ...and NOT the opaque generic message.
	if strings.Contains(stderr, "input not recognized as any HDF document type") {
		t.Errorf("should not fall through to the generic unrecognized message; stderr=%s", stderr)
	}
}

// Auto-detect path: a legacy InSpec exec-json doc gets the actionable convert
// redirect, not the generic "not recognized as any HDF document type" (#233).
func TestValidateLegacyInSpecExecJSON_RedirectsToConvert(t *testing.T) {
	path := writeLegacyInSpec(t)
	_, stderr, err := executeCommand("validate", path)
	if err == nil {
		t.Fatalf("validate should fail on a legacy v2 document; stderr=%s", stderr)
	}
	assertLegacyRedirect(t, stderr)
}

// Forced --type results on a legacy doc surfaces the same version-mismatch
// redirect, not the opaque v3 "baselines is required" schema error (#233).
func TestValidateLegacyInSpecExecJSON_ForcedTypeRedirects(t *testing.T) {
	path := writeLegacyInSpec(t)
	_, stderr, err := executeCommand("validate", "--type", "results", path)
	if err == nil {
		t.Fatalf("validate --type results should fail on a legacy v2 document; stderr=%s", stderr)
	}
	assertLegacyRedirect(t, stderr)
	if strings.Contains(stderr, "baselines is required") {
		t.Errorf("should name the version mismatch, not only the v3 schema error; stderr=%s", stderr)
	}
}
