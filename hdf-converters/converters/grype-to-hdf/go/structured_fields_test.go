package grype_to_hdf

import (
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// TestStructuredCvss verifies Grype's vulnerability.cvss[] array is mapped to
// the schema-defined []Cvss field on EvaluatedRequirement, one entry per
// array element. Uses CVE-2024-7592 (python binary) which has a single
// NVD CVSS 3.1 entry in amazon.json.
func TestStructuredCvss_SingleEntry(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/CVE-2024-7592")

	if len(req.Cvss) != 1 {
		t.Fatalf("Expected 1 Cvss entry, got %d", len(req.Cvss))
	}

	entry := req.Cvss[0]
	if string(entry.Version) != "3.1" {
		t.Errorf("Expected CVSS version 3.1, got %q", entry.Version)
	}
	if entry.Source == nil || *entry.Source != "CVE-2024-7592" {
		t.Errorf("Expected source CVE-2024-7592, got %v", entry.Source)
	}
	expectedVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
	if entry.BaseVector == nil || *entry.BaseVector != expectedVector {
		t.Errorf("Expected baseVector %q, got %v", expectedVector, entry.BaseVector)
	}
	if entry.BaseScore == nil || *entry.BaseScore != 7.5 {
		t.Errorf("Expected baseScore 7.5, got %v", entry.BaseScore)
	}
	if entry.BaseSeverity == nil || *entry.BaseSeverity != hdf.CVSSSeverityHigh {
		t.Errorf("Expected baseSeverity high (CVSS 7.5 falls in high band), got %v", entry.BaseSeverity)
	}
}

// TestStructuredCvss_NoEntries verifies a finding whose vulnerability.cvss
// array is empty produces no Cvss entries (ALAS-2024-2607 has cvss:[] in amazon.json;
// the related-vulnerability CVSS is NOT pulled into the primary Cvss[]).
func TestStructuredCvss_EmptyArrayProducesNoEntries(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/ALAS-2024-2607")

	if len(req.Cvss) != 0 {
		t.Errorf("Expected 0 Cvss entries (vulnerability.cvss is empty), got %d", len(req.Cvss))
	}
}

// TestAffectedPackages_FromArtifact verifies the artifact block is mapped to
// the AffectedPackage primitive. Uses ALAS-2024-2607 (ca-certificates rpm).
func TestAffectedPackages_FromArtifact(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/ALAS-2024-2607")

	if len(req.AffectedPackages) != 1 {
		t.Fatalf("Expected 1 AffectedPackage, got %d", len(req.AffectedPackages))
	}

	pkg := req.AffectedPackages[0]
	if pkg.Name == nil || *pkg.Name != "ca-certificates" {
		t.Errorf("Expected name ca-certificates, got %v", pkg.Name)
	}
	if pkg.Version == nil || *pkg.Version != "2023.2.64-1.amzn2.0.1" {
		t.Errorf("Expected version 2023.2.64-1.amzn2.0.1, got %v", pkg.Version)
	}
	if pkg.Ecosystem == nil || *pkg.Ecosystem != hdf.RPM {
		t.Errorf("Expected ecosystem rpm, got %v", pkg.Ecosystem)
	}
	if pkg.Cpe == nil || !strings.HasPrefix(*pkg.Cpe, "cpe:2.3:a:ca-certificates:ca-certificates:") {
		t.Errorf("Expected first canonical CPE entry, got %v", pkg.Cpe)
	}
	if pkg.Purl == nil || !strings.HasPrefix(*pkg.Purl, "pkg:rpm/amzn/ca-certificates@") {
		t.Errorf("Expected PURL pkg:rpm/amzn/ca-certificates@..., got %v", pkg.Purl)
	}
	if pkg.FixedInVersion == nil || *pkg.FixedInVersion != "2023.2.68-1.amzn2.0.1" {
		t.Errorf("Expected fixedInVersion 2023.2.68-1.amzn2.0.1, got %v", pkg.FixedInVersion)
	}
}

// TestAffectedPackages_NoFixWhenStateUnknown verifies fixedInVersion is omitted
// when fix.state != "fixed". Uses CVE-2024-7592 (python) which has fix state "unknown".
func TestAffectedPackages_NoFixWhenStateUnknown(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/CVE-2024-7592")

	if len(req.AffectedPackages) != 1 {
		t.Fatalf("Expected 1 AffectedPackage, got %d", len(req.AffectedPackages))
	}
	pkg := req.AffectedPackages[0]
	if pkg.FixedInVersion != nil {
		t.Errorf("Expected fixedInVersion nil (fix state=unknown), got %q", *pkg.FixedInVersion)
	}
	// Artifact.type is "binary" which has no specific schema ecosystem; should be generic.
	if pkg.Ecosystem == nil || *pkg.Ecosystem != hdf.Generic {
		t.Errorf("Expected ecosystem generic for 'binary' artifact, got %v", pkg.Ecosystem)
	}
}

// TestAffectedPackages_EcosystemMapping verifies each Grype artifact.type
// maps to the correct schema Ecosystem enum value.
func TestAffectedPackages_EcosystemMapping(t *testing.T) {
	cases := []struct {
		grypeType string
		expected  hdf.Ecosystem
	}{
		{"rpm", hdf.RPM},
		{"deb", hdf.Deb},
		{"apk", hdf.Generic},
		{"npm", hdf.Npm},
		{"python", hdf.Pypi},
		{"gem", hdf.Gem},
		{"go-module", hdf.Go},
		{"java-archive", hdf.Maven},
		{"dotnet", hdf.Nuget},
		{"rust-crate", hdf.Cargo},
		{"binary", hdf.Generic},
		{"", hdf.Generic},
		{"some-future-type", hdf.Generic},
	}

	for _, tc := range cases {
		got := mapGrypeTypeToEcosystem(tc.grypeType)
		if got != tc.expected {
			t.Errorf("mapGrypeTypeToEcosystem(%q): got %q, want %q", tc.grypeType, got, tc.expected)
		}
	}
}

// TestStructuredCvss_BaseSeverityBands verifies CvssScoreToSeverity is used to
// derive baseSeverity from baseScore (not Grype's qualitative severity field).
func TestStructuredCvss_BaseSeverityBands(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	// Iterate every requirement that has cvss entries and confirm baseSeverity
	// derivation matches band thresholds.
	checked := 0
	for _, req := range result.Baselines[0].Requirements {
		for _, c := range req.Cvss {
			if c.BaseSeverity == nil {
				t.Errorf("requirement %s: cvss entry missing baseSeverity", req.ID)
				continue
			}
			if c.BaseScore == nil {
				t.Errorf("requirement %s: cvss entry missing baseScore", req.ID)
				continue
			}
			score := *c.BaseScore
			var expected hdf.CVSSSeverity
			switch {
			case score < 0.1:
				expected = hdf.None
			case score < 4.0:
				expected = hdf.CVSSSeverityLow
			case score < 7.0:
				expected = hdf.CVSSSeverityMedium
			case score < 9.0:
				expected = hdf.CVSSSeverityHigh
			default:
				expected = hdf.CVSSSeverityCritical
			}
			if *c.BaseSeverity != expected {
				t.Errorf("requirement %s: score %v → baseSeverity %q, want %q",
					req.ID, score, *c.BaseSeverity, expected)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no CVSS entries to validate band derivation against")
	}
}

// TestCweField_EmptyWhenNotEmittedByGrype confirms cwe[] is absent when
// Grype output has no vulnerability.cwe array (which is the case for all
// fixtures in this converter). Guards against accidentally fabricating data.
func TestCweField_EmptyWhenNotEmittedByGrype(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	for _, req := range result.Baselines[0].Requirements {
		if len(req.Cwe) != 0 {
			t.Errorf("requirement %s: expected cwe[] empty (no upstream CWE in fixture), got %v",
				req.ID, req.Cwe)
		}
	}
}

// TestCweField_ParsedFromVulnerabilityCwe verifies that when Grype output does
// contain a vulnerability.cwe array, valid CWE-N entries are surfaced and
// malformed entries are dropped.
func TestCweField_ParsedFromVulnerabilityCwe(t *testing.T) {
	input := `{
		"descriptor": {"name": "grype", "version": "0.79.3"},
		"source": {"target": {"userInput": "test-image"}},
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-9999",
				"severity": "High",
				"cwe": ["CWE-79", "CWE-89", "CWE-bogus", "CWE-0", "junk"]
			},
			"matchDetails": [{"type": "exact-direct-match"}],
			"artifact": {"name": "pkg", "version": "1.0", "type": "rpm"}
		}]
	}`
	result, err := ConvertGrypeToHDF([]byte(input), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/CVE-2024-9999")
	if len(req.Cwe) != 2 {
		t.Fatalf("Expected 2 valid CWE entries, got %d: %v", len(req.Cwe), req.Cwe)
	}
	if req.Cwe[0] != "CWE-79" || req.Cwe[1] != "CWE-89" {
		t.Errorf("Expected [CWE-79, CWE-89], got %v", req.Cwe)
	}
}

// TestEpss_PopulatedWhenPresent verifies the Epss block is populated from
// vulnerability.epss[] (most recent entry).
func TestEpss_PopulatedWhenPresent(t *testing.T) {
	input := `{
		"descriptor": {"name": "grype", "version": "0.79.3"},
		"source": {"target": {"userInput": "test-image"}},
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-1111",
				"severity": "High",
				"epss": [
					{"cve": "CVE-2024-1111", "epss": 0.92, "percentile": 0.99, "date": "2024-08-29"},
					{"cve": "CVE-2024-1111", "epss": 0.45, "percentile": 0.85, "date": "2024-08-22"}
				]
			},
			"matchDetails": [{"type": "exact-direct-match"}],
			"artifact": {"name": "pkg", "version": "1.0", "type": "rpm"}
		}]
	}`
	result, err := ConvertGrypeToHDF([]byte(input), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/CVE-2024-1111")
	if req.Epss == nil {
		t.Fatal("Expected Epss to be populated")
	}
	if req.Epss.Score != 0.92 {
		t.Errorf("Expected EPSS score 0.92 (most recent), got %v", req.Epss.Score)
	}
	if req.Epss.Percentile != 0.99 {
		t.Errorf("Expected EPSS percentile 0.99, got %v", req.Epss.Percentile)
	}
	if req.Epss.Date != "2024-08-29" {
		t.Errorf("Expected EPSS date 2024-08-29, got %q", req.Epss.Date)
	}
}

// TestKev_PopulatedWhenPresent verifies the Kev block is populated when
// Grype emits vulnerability.kev.
func TestKev_PopulatedWhenPresent(t *testing.T) {
	input := `{
		"descriptor": {"name": "grype", "version": "0.79.3"},
		"source": {"target": {"userInput": "test-image"}},
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-2222",
				"severity": "Critical",
				"kev": {
					"inKev": true,
					"dateAdded": "2024-01-15",
					"dueDate": "2024-02-05",
					"notes": "Actively exploited"
				}
			},
			"matchDetails": [{"type": "exact-direct-match"}],
			"artifact": {"name": "pkg", "version": "1.0", "type": "rpm"}
		}]
	}`
	result, err := ConvertGrypeToHDF([]byte(input), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/CVE-2024-2222")
	if req.Kev == nil {
		t.Fatal("Expected Kev to be populated")
	}
	if !req.Kev.InKev {
		t.Error("Expected inKev=true")
	}
	if req.Kev.DateAdded == nil || *req.Kev.DateAdded != "2024-01-15" {
		t.Errorf("Expected dateAdded 2024-01-15, got %v", req.Kev.DateAdded)
	}
	if req.Kev.DueDate == nil || *req.Kev.DueDate != "2024-02-05" {
		t.Errorf("Expected dueDate 2024-02-05, got %v", req.Kev.DueDate)
	}
}

// TestKev_NotPopulatedWhenAbsent ensures Kev stays nil when Grype output
// has no kev block.
func TestKev_NotPopulatedWhenAbsent(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	for _, req := range result.Baselines[0].Requirements {
		if req.Kev != nil {
			t.Errorf("requirement %s: expected Kev nil, got %+v", req.ID, req.Kev)
		}
	}
}

// TestAffectedPackages_NoCpesArray verifies a finding whose artifact has no
// cpes array still produces an AffectedPackage (with Cpe nil).
func TestAffectedPackages_NoCpesArray(t *testing.T) {
	input := `{
		"descriptor": {"name": "grype", "version": "0.79.3"},
		"source": {"target": {"userInput": "test-image"}},
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-3333",
				"severity": "Medium"
			},
			"matchDetails": [{"type": "exact-direct-match"}],
			"artifact": {"name": "thing", "version": "2.0", "type": "npm"}
		}]
	}`
	result, err := ConvertGrypeToHDF([]byte(input), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Grype/CVE-2024-3333")
	if len(req.AffectedPackages) != 1 {
		t.Fatalf("Expected 1 AffectedPackage, got %d", len(req.AffectedPackages))
	}
	pkg := req.AffectedPackages[0]
	if pkg.Cpe != nil {
		t.Errorf("Expected nil CPE, got %q", *pkg.Cpe)
	}
	if pkg.Purl != nil {
		t.Errorf("Expected nil PURL, got %q", *pkg.Purl)
	}
	if pkg.Ecosystem == nil || *pkg.Ecosystem != hdf.Npm {
		t.Errorf("Expected ecosystem npm, got %v", pkg.Ecosystem)
	}
}
