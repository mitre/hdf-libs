package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
)

// grafts the SAF-supplement top-level keys onto a real v2 InSpec exec-json
// fixture — exactly what `saf supplement target/passthrough write` produces —
// and writes it to a temp file for the convert command to read.
func writeSupplementedLegacyFixture(t *testing.T) string {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(fixtures.Inspec.Ubi9Scan, &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	doc["target"] = map[string]interface{}{"id": "prod-account", "type": "cloudAccount", "boundary": "sparc"}
	doc["passthrough"] = map[string]interface{}{"audit": map[string]interface{}{"runId": "r-123"}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "supplemented.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertSAFAbsorbed(t *testing.T, stdout, stderr string) {
	t.Helper()
	var out struct {
		Components []map[string]interface{} `json:"components"`
		Extensions map[string]interface{}   `json:"extensions"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	found := false
	for _, c := range out.Components {
		if c["type"] == "cloudAccount" && c["name"] == "prod-account" {
			found = true
		}
	}
	if !found {
		t.Errorf("SAF target not absorbed into a cloudAccount component; components=%v", out.Components)
	}
	pt, _ := out.Extensions["passthrough"].(map[string]interface{})
	audit, _ := pt["audit"].(map[string]interface{})
	if audit["runId"] != "r-123" {
		t.Errorf("SAF passthrough not absorbed into extensions.passthrough; extensions=%v", out.Extensions)
	}
	// The deprecation warnings must fire, consistent with the v3-base parse path.
	if !strings.Contains(stderr, "normalized into components[]") {
		t.Errorf("expected the target deprecation warning on stderr; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "normalized into extensions.passthrough") {
		t.Errorf("expected the passthrough deprecation warning on stderr; stderr=%s", stderr)
	}
}

// Auto-detected InSpec exec-json input carrying SAF target/passthrough must have
// them absorbed into the v3 output — the fromFormat=="hdf" gate previously skipped
// the legacyhdf-detected path, dropping attribution (issue #234).
func TestConvertCommand_AbsorbsSAFSupplement_AutoDetectedLegacy(t *testing.T) {
	path := writeSupplementedLegacyFixture(t)
	stdout, stderr, err := executeCommand("convert", path, "--to", "hdf@3")
	if err != nil {
		t.Fatalf("convert failed: %v (stderr: %s)", err, stderr)
	}
	assertSAFAbsorbed(t, stdout, stderr)
}

// The forced --from hdf path on the same legacy input must also absorb the
// supplement (the v2→v3 upgrade previously discarded the injected carriers).
func TestConvertCommand_AbsorbsSAFSupplement_ForcedFromHDF(t *testing.T) {
	path := writeSupplementedLegacyFixture(t)
	stdout, stderr, err := executeCommand("convert", "--from", "hdf", path, "--to", "hdf@3")
	if err != nil {
		t.Fatalf("convert failed: %v (stderr: %s)", err, stderr)
	}
	assertSAFAbsorbed(t, stdout, stderr)
}
