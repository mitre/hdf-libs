package gosec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

// ---- ConvertGosecToHDF top-level ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "gosec-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertGosecToHDF(input, testVersion) },
		MinimalFixture: "ethereum.json",
	})
}

func TestConvertGosecToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "gosec-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

func TestConvertGosecToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "gosec", *result.Tool.Name)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "dev", *result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestConvertGosecToHDF_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
}

func TestConvertGosecToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "gosec Scan", result.Baselines[0].Name)
}

func TestConvertGosecToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Grouping by rule_id ----

func TestConvertGosecToHDF_GroupsByRuleID(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	// ethereum.json has G104, G301, G302, G304, G404 → 5 requirements
	reqs := result.Baselines[0].Requirements
	assert.Len(t, reqs, 5)
}

func TestConvertGosecToHDF_MultipleResultsPerRequirement(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	var g304 *hdf.EvaluatedRequirement
	for i := range reqs {
		if reqs[i].ID == "G304" {
			g304 = &reqs[i]
			break
		}
	}
	require.NotNil(t, g304, "expected requirement G304")
	assert.Len(t, g304.Results, 6, "G304 should have 6 results (one per issue)")
}

// ---- Requirement fields ----

func TestConvertGosecToHDF_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	ids := make(map[string]bool)
	for _, req := range result.Baselines[0].Requirements {
		ids[req.ID] = true
	}
	assert.True(t, ids["G304"], "expected requirement ID G304")
	assert.True(t, ids["G404"], "expected requirement ID G404")
	assert.True(t, ids["G104"], "expected requirement ID G104")
	assert.True(t, ids["G301"], "expected requirement ID G301")
	assert.True(t, ids["G302"], "expected requirement ID G302")
}

func TestConvertGosecToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			require.NotNil(t, req.Title)
			assert.Equal(t, "Potential file inclusion via variable", *req.Title)
		}
	}
}

// ---- Impact mapping ----

func TestConvertGosecToHDF_ImpactHigh(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G404" {
			assert.InDelta(t, 0.7, req.Impact, 0.001)
		}
	}
}

func TestConvertGosecToHDF_ImpactMedium(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			assert.InDelta(t, 0.5, req.Impact, 0.001)
		}
	}
}

func TestConvertGosecToHDF_ImpactLow(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G104" {
			assert.InDelta(t, 0.3, req.Impact, 0.001)
		}
	}
}

// ---- Status mapping ----

func TestConvertGosecToHDF_StatusFailed(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			for _, r := range req.Results {
				assert.Equal(t, hdf.Failed, r.Status)
			}
		}
	}
}

func TestConvertGosecToHDF_StatusNotReviewedWhenSuppressed(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	// G301 has 2 issues, both with external suppression → notReviewed
	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G301" {
			require.Len(t, req.Results, 2)
			for _, r := range req.Results {
				assert.Equal(t, hdf.NotReviewed, r.Status)
			}
		}
	}
}

func TestConvertGosecToHDF_StatusNotReviewedWhenNosec(t *testing.T) {
	// Use inline fixture since real Go Ethereum data has no nosec=true issues
	input := []byte(`{
		"Golang errors": {},
		"Issues": [
			{
				"severity": "LOW", "confidence": "HIGH",
				"cwe": {"id": "703", "url": "https://cwe.mitre.org/data/definitions/703.html"},
				"rule_id": "G104", "details": "Errors unhandled.",
				"file": "/app/main.go", "code": "defer f.Close()\n",
				"line": "5", "column": "2", "nosec": true, "suppressions": null
			},
			{
				"severity": "LOW", "confidence": "HIGH",
				"cwe": {"id": "703", "url": "https://cwe.mitre.org/data/definitions/703.html"},
				"rule_id": "G104", "details": "Errors unhandled.",
				"file": "/app/util.go", "code": "_ = conn.Close()\n",
				"line": "10", "column": "8", "nosec": false, "suppressions": null
			}
		],
		"Stats": {"files": 2, "lines": 50, "nosec": 1, "found": 2},
		"GosecVersion": "dev"
	}`)
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G104" {
			// Two issues: one nosec=true (notReviewed), one nosec=false (failed)
			statuses := make(map[hdf.ResultStatus]int)
			for _, r := range req.Results {
				statuses[r.Status]++
			}
			assert.Equal(t, 1, statuses[hdf.NotReviewed], "nosec=true issue should be notReviewed")
			assert.Equal(t, 1, statuses[hdf.Failed], "nosec=false issue should be failed")
		}
	}
}

// ---- Skip message ----

func TestConvertGosecToHDF_SkipMessageWithJustification(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G301" {
			r := req.Results[0]
			require.NotNil(t, r.Message)
			assert.Contains(t, *r.Message, "Globally suppressed.")
			assert.Contains(t, *r.Message, "external")
		}
	}
}

func TestConvertGosecToHDF_SkipMessageNoJustification(t *testing.T) {
	// suppressions list is non-nil but justification is empty
	input := []byte(`{
		"Golang errors": {},
		"Issues": [{
			"severity": "MEDIUM", "confidence": "HIGH",
			"cwe": {"id": "22", "url": "https://cwe.mitre.org/data/definitions/22.html"},
			"rule_id": "G304", "details": "File inclusion",
			"file": "/app/main.go", "code": "f, _ := os.Open(x)\n",
			"line": "5", "column": "2", "nosec": false,
			"suppressions": [{"kind": "inSource", "justification": ""}]
		}],
		"Stats": {"files": 1, "lines": 10, "nosec": 0, "found": 1},
		"GosecVersion": "2.18.0"
	}`)
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)
	r := result.Baselines[0].Requirements[0].Results[0]
	assert.Equal(t, hdf.NotReviewed, r.Status)
	require.NotNil(t, r.Message)
	assert.Contains(t, *r.Message, "No justification provided")
}

// ---- CodeDesc and Message ----

func TestConvertGosecToHDF_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			found := false
			for _, r := range req.Results {
				if r.CodeDesc != "" {
					assert.Contains(t, r.CodeDesc, "G304")
					assert.Contains(t, r.CodeDesc, "go-ethereum-master")
					found = true
					break
				}
			}
			assert.True(t, found, "expected at least one result with non-empty CodeDesc")
		}
	}
}

func TestConvertGosecToHDF_Message(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			r := req.Results[0]
			require.NotNil(t, r.Message)
			assert.Contains(t, *r.Message, "HIGH")
			assert.Contains(t, *r.Message, "os.OpenFile")
		}
	}
}

// ---- Descriptions ----

func TestConvertGosecToHDF_DescriptionDefault(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			defaultDesc := findDescription(req.Descriptions, "default")
			require.NotNil(t, defaultDesc, "expected a 'default' description")
			assert.Equal(t, "Potential file inclusion via variable", defaultDesc.Data)
		}
	}
}

func TestConvertGosecToHDF_DescriptionCheck(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			checkDesc := findDescription(req.Descriptions, "check")
			require.NotNil(t, checkDesc, "expected a 'check' description")
			assert.Contains(t, checkDesc.Data, "CWE-22")
			assert.Contains(t, checkDesc.Data, "cwe.mitre.org")
		}
	}
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- NIST / CWE tags ----

func TestConvertGosecToHDF_NISTTagsFromCWE(t *testing.T) {
	// CWE-338 → SC-13 (from cwe-nist-mappings.json)
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G404" {
			nist, ok := req.Tags["nist"].([]string)
			require.True(t, ok, "nist tag should be []string")
			assert.Contains(t, nist, "SC-13")
		}
	}
}

func TestConvertGosecToHDF_NISTFallback(t *testing.T) {
	// CWE-9999 does not exist → fallback ["SI-2", "RA-5"]
	input := []byte(`{
		"Golang errors": {},
		"Issues": [{
			"severity": "MEDIUM", "confidence": "HIGH",
			"cwe": {"id": "9999", "url": "https://cwe.mitre.org/data/definitions/9999.html"},
			"rule_id": "G999", "details": "Unknown rule",
			"file": "/app/main.go", "code": "x()\n",
			"line": "1", "column": "1", "nosec": false, "suppressions": null
		}],
		"Stats": {"files": 1, "lines": 5, "nosec": 0, "found": 1},
		"GosecVersion": "2.18.0"
	}`)
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)
	nist, ok := result.Baselines[0].Requirements[0].Tags["nist"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"SI-2", "RA-5"}, nist)
}

func TestConvertGosecToHDF_CWETag(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "G304" {
			cweTag, ok := req.Tags["cwe"].(map[string]interface{})
			require.True(t, ok, "cwe tag should be map[string]interface{}")
			assert.Equal(t, "22", cweTag["id"])
			assert.Equal(t, "https://cwe.mitre.org/data/definitions/22.html", cweTag["url"])
		}
	}
}

// ---- Empty Issues ----

func TestConvertGosecToHDF_EmptyIssues(t *testing.T) {
	input := []byte(`{
		"Golang errors": {},
		"Issues": [],
		"Stats": {"files": 0, "lines": 0, "nosec": 0, "found": 0},
		"GosecVersion": "2.18.0"
	}`)
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "gosec-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "gosec")
	assert.Contains(t, req.Results[0].CodeDesc, "Go codebase")
}

func TestConvertGosecToHDF_EmptyIssuesFixture(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "gosec-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "gosec")
	assert.Contains(t, req.Results[0].CodeDesc, "Go codebase")
}

// ---- Real fixture smoke test ----

func TestConvertGosecToHDF_RealFixture(t *testing.T) {
	input := loadFixture(t, "input/real.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.NotEmpty(t, reqs)
	for _, req := range reqs {
		assert.NotEmpty(t, req.ID)
		assert.NotEmpty(t, req.Results)
	}
}

// ---- Helper: getImpact ----

func TestGetImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"HIGH", 0.7},
		{"high", 0.7},
		{"MEDIUM", 0.5},
		{"medium", 0.5},
		{"LOW", 0.3},
		{"low", 0.3},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

// ---- Helper: isSuppressed ----

func TestIsSuppressed(t *testing.T) {
	// nosec=false, nil suppressions → not suppressed
	assert.False(t, isSuppressed(GosecIssue{Nosec: false, Suppressions: nil}))
	// nosec=true → suppressed
	assert.True(t, isSuppressed(GosecIssue{Nosec: true, Suppressions: nil}))
	// non-nil suppressions list → suppressed
	assert.True(t, isSuppressed(GosecIssue{Nosec: false, Suppressions: []GosecSuppression{{Kind: "external", Justification: "ok"}}}))
}

// ---- Helper: formatSkipMessage ----

func TestFormatSkipMessage(t *testing.T) {
	// nil suppressions → no skip message
	assert.Nil(t, formatSkipMessage(nil))

	// empty slice → "No justification provided"
	msg := formatSkipMessage([]GosecSuppression{})
	require.NotNil(t, msg)
	assert.Equal(t, "No justification provided", *msg)

	// with justification
	msg = formatSkipMessage([]GosecSuppression{{Kind: "external", Justification: "Globally suppressed."}})
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "Globally suppressed.")
	assert.Contains(t, *msg, "external")

	// justification empty in a suppression → "No justification provided"
	msg = formatSkipMessage([]GosecSuppression{{Kind: "inSource", Justification: ""}})
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "No justification provided")
	assert.Contains(t, *msg, "inSource")
}

// ---- Helper: formatCodeDesc ----

func TestFormatCodeDesc(t *testing.T) {
	issue := GosecIssue{RuleID: "G304", File: "/app/main.go", Line: "42", Column: "12"}
	desc := formatCodeDesc(issue)
	assert.Contains(t, desc, "G304")
	assert.Contains(t, desc, "/app/main.go")
	assert.Contains(t, desc, "42")
	assert.Contains(t, desc, "12")
}

// ---- Helper: formatMessage ----

func TestFormatMessage(t *testing.T) {
	issue := GosecIssue{Confidence: "HIGH", Code: "os.Open(x)\n"}
	msg := formatMessage(issue)
	assert.Contains(t, msg, "HIGH")
	assert.Contains(t, msg, "os.Open(x)")
}

// ---- Helper: nistTags ----

func TestNistTagsForIssue_KnownCWE(t *testing.T) {
	issue := GosecIssue{CWE: GosecCWE{ID: "338", URL: "https://cwe.mitre.org/data/definitions/338.html"}}
	tags := nistTagsForIssue(issue)
	assert.Contains(t, tags, "SC-13")
}

func TestNistTagsForIssue_UnknownCWE(t *testing.T) {
	issue := GosecIssue{CWE: GosecCWE{ID: "99999"}}
	tags := nistTagsForIssue(issue)
	assert.Equal(t, []string{"SI-2", "RA-5"}, tags)
}

func TestNistTagsForIssue_EmptyCWE(t *testing.T) {
	issue := GosecIssue{CWE: GosecCWE{ID: ""}}
	tags := nistTagsForIssue(issue)
	assert.Equal(t, []string{"SI-2", "RA-5"}, tags)
}

// ---- SARIF format detection and routing ----

func TestConvertGosecToHDF_SARIFRouting(t *testing.T) {
	// Load the gosec SARIF fixture from the SARIF converter's fixtures
	sarifPath := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input", "gosec.sarif")
	input, err := os.ReadFile(sarifPath)
	require.NoError(t, err, "Failed to read gosec.sarif fixture")

	// Should be detected as SARIF and routed to the SARIF converter
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err, "SARIF input should be accepted by gosec converter")
	require.NotNil(t, result)

	// Verify the SARIF converter produced the output (baseline name = tool driver name)
	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "gosec", result.Baselines[0].Name)
	assert.NotEmpty(t, result.Baselines[0].Requirements)

	// Verify enriched SARIF data came through (CWE from relationships)
	reqs := result.Baselines[0].Requirements
	var g201 *hdf.EvaluatedRequirement
	for i := range reqs {
		if reqs[i].ID == "G201" {
			g201 = &reqs[i]
			break
		}
	}
	require.NotNil(t, g201, "expected G201 requirement from SARIF")
	cweIds, ok := g201.Tags["cwe"].([]string)
	require.True(t, ok, "CWE should be []string from SARIF converter")
	assert.Contains(t, cweIds, "CWE-89")
}

func TestConvertGosecToHDF_NativeJSONNotRoutedToSARIF(t *testing.T) {
	// Native gosec JSON should not be detected as SARIF
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	// Native output uses "gosec Scan" baseline name (not tool driver name)
	assert.Equal(t, "gosec Scan", result.Baselines[0].Name)
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "gosec-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertGosecToHDF(input, "1.0.0")
	})
}

// countDistinctGosecRules unmarshals raw gosec JSON into a minimal local struct
// — deliberately NOT the converter's structs — and returns the number of
// distinct rule_id values across all Issues. gosec's emission unit is the
// distinct rule (issues sharing a rule_id collapse into one requirement with
// many results), so a plain Issues count would overshoot.
func countDistinctGosecRules(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Issues []struct {
			RuleID string `json:"rule_id"`
		} `json:"Issues"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse gosec JSON for anchor count")
	distinct := make(map[string]struct{})
	for _, i := range doc.Issues {
		distinct[i.RuleID] = struct{}{}
	}
	return len(distinct)
}

// Ground-truth anchor: the converter emits one requirement per DISTINCT rule_id.
// The distinct count is derived independently of the converter's parser, so a
// silent under-extraction (e.g. dropping a rule group) fails even when Go/TS
// golden parity agrees. ethereum.json's 173 issues collapse to 5 rules.
func TestConvertGosecToHDF_DistinctRuleAnchor(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctGosecRules(t, input),
		"ethereum.json: one requirement per distinct rule_id")
}

func TestConvertGosecToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

func TestConvertGosecToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/ethereum.json")
	result, err := ConvertGosecToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "every requirement must have verificationMethod set")
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q should be marked automated", req.ID)
	}
}
