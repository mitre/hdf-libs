package all

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureRoot returns the path to hdf-converters/converters/ relative to this test file.
func fixtureRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "converters")
}

func readFixture(t *testing.T, converter, filename string) []byte {
	t.Helper()
	// The hdf-to-xml minimal.json moved to the shared @mitre/hdf-fixtures
	// package (per bead hdf-libs-e95o boundary rule) since multiple workspace
	// packages consume it. Other converter fixtures stay where they are.
	if converter == "hdf-to-xml" && filename == "minimal.json" {
		return fixtures.Results.Minimal
	}
	path := filepath.Join(fixtureRoot(), converter, "fixtures", "input", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "fixture must exist: %s", path)
	return data
}

func TestAllFingerprintsRegistered(t *testing.T) {
	fps := registry.GetFingerprints()
	// 33 ingest + 7 OSCAL + 4 export + hdf-v2 + legacyhdf = 46+
	assert.GreaterOrEqual(t, len(fps), 40, "expected at least 40 fingerprints, got %d", len(fps))
}

func TestIngestFingerprintsCount(t *testing.T) {
	fps := registry.GetIngestFingerprints()
	assert.GreaterOrEqual(t, len(fps), 35, "expected at least 35 ingest fingerprints")
}

// derivedSourceName reproduces how hdf convert turns a detected fingerprint ID
// into the source-format name it resolves against the convert registry
// (autoDetectFormat in hdf-cli/cmd/hdf/cmd/convert.go).
func derivedSourceName(fingerprintID string) string {
	if idx := strings.Index(fingerprintID, "-to-"); idx > 0 {
		return fingerprintID[:idx]
	}
	return fingerprintID
}

// fingerprintsNotResolvedByName are the fingerprints whose derived name is
// deliberately not a registered converter name.
var fingerprintsNotResolvedByName = map[string]string{
	// Native HDF input needs no conversion; convert normalizes this detection to
	// the "hdf" source name when resolving an export converter.
	"hdf-passthrough": "normalized to the \"hdf\" source name by convert",
}

// TestFingerprintDerivedNameResolves keeps auto-detect and the convert registry
// in agreement: a format that detects but whose derived name nothing registers
// is undetectable in practice — detection reports high confidence and the
// conversion then fails with "no converter found". Counting fingerprints cannot
// catch that, which is how oscal-component and oscal-sap regressed.
func TestFingerprintDerivedNameResolves(t *testing.T) {
	for _, fp := range registry.GetIngestFingerprints() {
		name := derivedSourceName(fp.ID)
		if reason, exempt := fingerprintsNotResolvedByName[fp.ID]; exempt {
			_, err := convreg.GetConverter(name, "hdf")
			require.Error(t, err, "%s is exempt (%s) but now resolves — drop the exemption", fp.ID, reason)
			continue
		}
		_, err := convreg.GetConverter(name, "hdf")
		assert.NoError(t, err, "fingerprint %q detects but its derived source name %q is not a registered converter, so `hdf convert` without --from cannot convert this format", fp.ID, name)
	}
}

// Integration: detect real fixtures
var fixtureTests = []struct {
	converter string
	fixture   string
	expectID  string
}{
	// JSON ingest
	{"aws-config-to-hdf", "minimal.json", "aws-config-to-hdf"},
	{"cklb-to-hdf", "firefox-stig.cklb", "cklb-to-hdf"},
	{"cyclonedx-to-hdf", "minimal-vulns.json", "cyclonedx-to-hdf"},
	{"conveyor-to-hdf", "sample-results.json", "conveyor-to-hdf"},
	{"deptrack-to-hdf", "fpf-default.json", "deptrack-to-hdf"},
	{"gitlab-to-hdf", "minimal-sast.json", "gitlab-to-hdf"},
	{"gosec-to-hdf", "real.json", "gosec-to-hdf"},
	{"grype-to-hdf", "anchore_grype.json", "grype-to-hdf"},
	{"jfrog-xray-to-hdf", "jfrog_xray_sample.json", "jfrog-xray-to-hdf"},
	{"kics-to-hdf", "minimal.json", "kics-to-hdf"},
	{"msft-defender-cloud-to-hdf", "minimal.json", "msft-defender-cloud-to-hdf"},
	{"msft-defender-endpoint-to-hdf", "minimal.json", "msft-defender-endpoint-to-hdf"},
	{"msft-secure-score-to-hdf", "minimal.json", "msft-secure-score-to-hdf"},
	{"neuvector-to-hdf", "minimal.json", "neuvector-to-hdf"},
	{"nikto-to-hdf", "minimal.json", "nikto-to-hdf"},
	{"semgrep-to-hdf", "real.json", "semgrep-to-hdf"},
	{"snyk-to-hdf", "minimal.json", "snyk-to-hdf"},
	{"sonarqube-to-hdf", "minimal.json", "sonarqube-to-hdf"},
	{"splunk-to-hdf", "splunk-minimal.json", "splunk-to-hdf"},
	{"trufflehog-to-hdf", "minimal.json", "trufflehog-to-hdf"},
	{"twistlock-to-hdf", "twistlock-twistcli-sample-1.json", "twistlock-to-hdf"},
	{"zap-to-hdf", "minimal.json", "zap-to-hdf"},
	{"legacyhdf-to-hdf", "minimal.json", "legacyhdf-to-hdf"},
	// XML
	{"nessus-to-hdf", "sample.nessus", "nessus-to-hdf"},
	{"netsparker-to-hdf", "sample-netsparker-invicti.xml", "netsparker-to-hdf"},
	{"burpsuite-to-hdf", "zero.webappsecurity.com.xml", "burpsuite-to-hdf"},
	{"fortify-to-hdf", "fortify_webgoat_results.fvdl", "fortify-to-hdf"},
	{"dbprotect-to-hdf", "sample-check-results.xml", "dbprotect-to-hdf"},
	{"xccdf-results-to-hdf", "minimal.xml", "xccdf-results-to-hdf"},
	{"xccdf-results-to-hdf", "arf-minimal.xml", "xccdf-results-to-hdf"},
	{"ckl-to-hdf", "firefox-stig.ckl", "ckl-to-hdf"},
	{"veracode-to-hdf", "veracode.xml", "veracode-to-hdf"},
	{"junit-to-hdf", "testsuites-mixed.xml", "junit-to-hdf"},
	// SARIF
	{"sarif-to-hdf", "sarif_input.sarif", "sarif-to-hdf"},
	// HDF native
	{"hdf-to-xml", "minimal.json", "hdf-passthrough"},
}

func TestDetectConverterFixtures(t *testing.T) {
	for _, tc := range fixtureTests {
		t.Run(tc.expectID+"/"+tc.fixture, func(t *testing.T) {
			data := readFixture(t, tc.converter, tc.fixture)
			result := registry.DetectConverter(data)
			require.NotNilf(t, result, "detectConverter returned nil for %s/%s", tc.converter, tc.fixture)
			assert.Equal(t, tc.expectID, result.Fingerprint.ID)
		})
	}
}

func TestSarifTierOrdering(t *testing.T) {
	data := readFixture(t, "msft-defender-devops-to-hdf", "minimal.sarif")
	results := registry.DetectConverterAll(data)
	require.NotEmpty(t, results)
	// MSDO (0.95) should outrank generic SARIF (0.9)
	assert.Equal(t, "msft-defender-devops-to-hdf", results[0].Fingerprint.ID)
	if len(results) > 1 {
		assert.Greater(t, results[0].Confidence, results[1].Confidence)
	}
}

func TestEdgeCases(t *testing.T) {
	assert.Nil(t, registry.DetectConverter(nil))
	assert.Nil(t, registry.DetectConverter([]byte{}))
	assert.Nil(t, registry.DetectConverter([]byte("plain text garbage")))
	assert.Nil(t, registry.DetectConverter([]byte("{broken json")))
}
