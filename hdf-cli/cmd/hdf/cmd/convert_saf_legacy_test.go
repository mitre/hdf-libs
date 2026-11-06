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

// A NON-HDF export target must also absorb the supplement. The absorption runs
// before normalizeLegacyHDFInput; otherwise that helper upgrades legacy→v3 for a
// non-hdf target first and drops the top-level target before it can be captured.
func TestConvertCommand_AbsorbsSAFSupplement_NonHDFTarget(t *testing.T) {
	path := writeSupplementedLegacyFixture(t)
	stdout, stderr, err := executeCommand("convert", path, "--to", "oscal-sar")
	if err != nil {
		t.Fatalf("convert failed: %v (stderr: %s)", err, stderr)
	}
	// Both deprecation warnings prove the SAF rewrite ran before the drop.
	if !strings.Contains(stderr, "normalized into components[]") ||
		!strings.Contains(stderr, "normalized into extensions.passthrough") {
		t.Errorf("expected both SAF deprecation warnings on a non-hdf conversion; stderr=%s", stderr)
	}
	// The cloudAccount absorbed from target reaches the OSCAL output (was dropped
	// before the capture/absorb was moved ahead of the legacy upgrade).
	if !strings.Contains(stdout, "prod-account") {
		t.Error("SAF target's cloudAccount did not survive into the oscal-sar output")
	}
}

// The classic Heimdall/InSpec target shape ({type, name, labels}, no id) on a
// real exec-json scan whose platform describes the same host. The fixture's
// platform is {name: redhat, release: 9.7}.
func writeLegacyTargetFixture(t *testing.T) string {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(fixtures.Inspec.Ubi9Scan, &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	doc["target"] = map[string]interface{}{"type": "host", "name": "my-host-01", "labels": map[string]interface{}{"environment": "prod"}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy-target.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// platform and target describe one assessed host, so the output carries exactly
// one component: the target's name and labels with the platform's OS facts.
func TestConvertCommand_LegacyTargetMergesWithPlatform(t *testing.T) {
	for name, args := range map[string][]string{
		"auto-detected": {"--to", "hdf@3"},
		"--from hdf":    {"--from", "hdf", "--to", "hdf@3"},
		"--from inspec": {"--from", "inspec", "--to", "hdf"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, err := executeCommand(append([]string{"convert", writeLegacyTargetFixture(t)}, args...)...)
			if err != nil {
				t.Fatalf("convert failed: %v (stderr: %s)", err, stderr)
			}
			var out struct {
				Components []map[string]interface{} `json:"components"`
			}
			if err := json.Unmarshal([]byte(stdout), &out); err != nil {
				t.Fatalf("output not JSON: %v", err)
			}
			if len(out.Components) != 1 {
				t.Fatalf("want 1 component, got %d: %v", len(out.Components), out.Components)
			}
			c := out.Components[0]
			labels, _ := c["labels"].(map[string]interface{})
			if c["type"] != "host" || c["name"] != "my-host-01" || c["osName"] != "redhat" ||
				c["osVersion"] != "9.7" || labels["environment"] != "prod" {
				t.Errorf("platform and target not merged into one named host: %v", c)
			}
			if !strings.Contains(stderr, "normalized into components[]") {
				t.Errorf("expected the target deprecation warning on stderr; stderr=%s", stderr)
			}
		})
	}
}
