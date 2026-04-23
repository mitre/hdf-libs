package all

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
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

// Integration: detect real fixtures
var fixtureTests = []struct {
	converter string
	fixture   string
	expectID  string
}{
	// JSON ingest
	{"aws-config-to-hdf", "minimal.json", "aws-config-to-hdf"},
	{"cyclonedx-to-hdf", "minimal-vulns.json", "cyclonedx-to-hdf"},
	{"conveyor-to-hdf", "sample-results.json", "conveyor-to-hdf"},
	{"deptrack-to-hdf", "fpf-default.json", "deptrack-to-hdf"},
	{"gitlab-to-hdf", "minimal-sast.json", "gitlab-to-hdf"},
	{"gosec-to-hdf", "real.json", "gosec-to-hdf"},
	{"grype-to-hdf", "anchore_grype.json", "grype-to-hdf"},
	{"jfrog-xray-to-hdf", "jfrog_xray_sample.json", "jfrog-xray-to-hdf"},
	{"msft-defender-cloud-to-hdf", "minimal.json", "msft-defender-cloud-to-hdf"},
	{"msft-defender-endpoint-to-hdf", "minimal.json", "msft-defender-endpoint-to-hdf"},
	{"msft-secure-score-to-hdf", "minimal.json", "msft-secure-score-to-hdf"},
	{"neuvector-to-hdf", "minimal.json", "neuvector-to-hdf"},
	{"nikto-to-hdf", "minimal.json", "nikto-to-hdf"},
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
	{"veracode-to-hdf", "veracode.xml", "veracode-to-hdf"},
	{"junit-to-hdf", "testsuites-mixed.xml", "junit-to-hdf"},
	// SARIF
	{"sarif-to-hdf", "sarif_input.sarif", "sarif-to-hdf"},
	// HDF v2
	{"hdf-to-xml", "minimal.json", "hdf-v2-passthrough"},
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
