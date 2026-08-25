package hdftocsv

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertHDFToCSV_Minimal(t *testing.T) {
	// Load minimal fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-csv", "fixtures", "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.json fixture")

	// Convert
	result, err := ConvertHDFToCSV(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, result, "Result should not be empty")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(string(result)))
	records, err := reader.ReadAll()
	require.NoError(t, err, "Should parse CSV")

	// Verify structure
	require.Len(t, records, 4, "Should have header + 3 data rows")

	// Verify header
	header := records[0]
	assert.Contains(t, header, "Baseline ID")
	assert.Contains(t, header, "Requirement ID")
	assert.Contains(t, header, "Status")

	// Column order: 0 Baseline ID .. 7 Description, 8 Check, 9 Fix, 10 Rationale,
	// 11 Code, 12 References, 13 Severity, 14 Impact, 15 Status, 16 NIST, 17 CCI,
	// 18 Control Type, 19 Verification Method, 20 Applicability, 21 Result Message,
	// 22 Effective Status, 23 Effective Impact, 24 Disposition, 25 Override Reason,
	// 26 Applied By, 27 Expires At, 28 CVSS, 29 CWE, 30 EPSS, 31 KEV, 32 Target FQDN,
	// 33 Target IP.
	assert.Equal(t, "Description", header[7])
	assert.Equal(t, "Check", header[8])
	assert.Equal(t, "Fix", header[9])
	assert.Equal(t, "Rationale", header[10])
	assert.Equal(t, "Code", header[11])
	assert.Equal(t, "References", header[12])
	assert.Equal(t, "Effective Status", header[22])
	assert.Equal(t, "Effective Impact", header[23])
	assert.Equal(t, "Disposition", header[24])
	assert.Equal(t, "Override Reason", header[25])
	assert.Equal(t, "Applied By", header[26])
	assert.Equal(t, "Expires At", header[27])
	assert.Equal(t, "CVSS", header[28])
	assert.Equal(t, "CWE", header[29])
	assert.Equal(t, "EPSS", header[30])
	assert.Equal(t, "KEV", header[31])
	assert.Equal(t, "Target FQDN", header[32])
	assert.Equal(t, "Target IP", header[33])

	// Verify first data row — populated check/fix/rationale/code/refs; no override
	// or CVE data, so effective columns fall back to raw values.
	row1 := records[1]
	assert.Equal(t, "Example STIG Baseline", row1[0])                                         // Baseline ID
	assert.Equal(t, "SV-123456", row1[5])                                                     // Requirement ID
	assert.Contains(t, row1[8], "minlen")                                                     // Check
	assert.Contains(t, row1[9], "minimum password length")                                    // Fix
	assert.Contains(t, row1[10], "Longer passwords")                                          // Rationale
	assert.Contains(t, row1[11], "control 'SV-123456'")                                       // Code
	assert.Equal(t, "https://public.cyber.mil/stigs/; https://www.first.org/cvss/", row1[12]) // References
	assert.Equal(t, "passed", row1[15])                                                       // Status
	assert.Contains(t, row1[16], "IA-5 (1)")                                                  // NIST Controls
	assert.Contains(t, row1[17], "CCI-000192")                                                // CCI Controls
	assert.Equal(t, "passed", row1[22])                                                       // Effective Status (fallback)
	assert.Equal(t, "0.7", row1[23])                                                          // Effective Impact (fallback)
	assert.Equal(t, "", row1[24])                                                             // Disposition
	assert.Equal(t, "test-server-01.example.com", row1[32])                                   // Target FQDN
	assert.Equal(t, "10.1.2.3", row1[33])                                                     // Target IP

	// Verify second data row — waived-but-failing control: raw Status stays failed
	// while Effective Status/Impact reflect the falsePositive override.
	row2 := records[2]
	assert.Equal(t, "SV-123457", row2[5])                                                                         // Requirement ID
	assert.Equal(t, "", row2[8])                                                                                  // Check
	assert.Equal(t, "failed", row2[15])                                                                           // Status (raw)
	assert.Equal(t, "Audit logging is not configured", row2[21])                                                  // Result Message
	assert.Equal(t, "passed", row2[22])                                                                           // Effective Status (override)
	assert.Equal(t, "0.0", row2[23])                                                                              // Effective Impact (override)
	assert.Equal(t, "falsePositive", row2[24])                                                                    // Disposition
	assert.Equal(t, "Authentication logging is handled by an external SIEM the scanner cannot observe", row2[25]) // Override Reason
	assert.Equal(t, "jdoe", row2[26])                                                                             // Applied By
	assert.Equal(t, "2099-12-31T00:00:00Z", row2[27])                                                             // Expires At

	// Verify third data row — CVE-scan finding carries the vulnerability quartet.
	row3 := records[3]
	assert.Equal(t, "CVE-2021-44228", row3[5])    // Requirement ID
	assert.Equal(t, "failed", row3[15])           // Status
	assert.Equal(t, "failed", row3[22])           // Effective Status (fallback)
	assert.Equal(t, "10.0", row3[28])             // CVSS
	assert.Equal(t, "CWE-502; CWE-917", row3[29]) // CWE
	assert.Equal(t, "0.94360", row3[30])          // EPSS
	assert.Equal(t, "true", row3[31])             // KEV
}

func TestConvertHDFToCSV_EmptyBaselines(t *testing.T) {
	input := `{
		"baselines": [],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")
	assert.Empty(t, result, "Result should be empty for no data")
}

func TestConvertHDFToCSV_NoRequirements(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Empty Baseline",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": []
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")
	assert.Empty(t, result, "Result should be empty for no requirements")
}

func TestConvertHDFToCSV_MultipleBaselines(t *testing.T) {
	input, _ := json.Marshal(testhdf.Doc(
		testhdf.Baseline("Baseline 1", testhdf.Req("REQ-001",
			testhdf.Title("Test Requirement"), testhdf.Desc("Test description"),
			testhdf.Impact(0.5), testhdf.Tag("severity", "medium"), testhdf.Status(hdf.Passed))),
		testhdf.Baseline("Baseline 2", testhdf.Req("REQ-002",
			testhdf.Title("Another Requirement"), testhdf.Desc("Another description"),
			testhdf.Impact(0.7), testhdf.Tag("severity", "high"), testhdf.Status(hdf.Failed))),
	))

	result, err := ConvertHDFToCSV(input)
	require.NoError(t, err, "Conversion should succeed")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(string(result)))
	records, err := reader.ReadAll()
	require.NoError(t, err, "Should parse CSV")

	// Should have header + 2 data rows
	require.Len(t, records, 3)

	// Verify both baselines present
	assert.Equal(t, "Baseline 1", records[1][0])
	assert.Equal(t, "Baseline 2", records[2][0])
}

func TestConvertHDFToCSV_MultipleComponents(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Test Baseline",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test Requirement",
				"descriptions": [{ "label": "default", "data": "Test description" }],
				"impact": 0.5,
				"tags": { "severity": "medium" },
				"sourceLocation": { "ref": "REQ-001", "line": 1 },
				"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
			}]
		}],
		"components": [
			{ "name": "target1", "type": "host" },
			{ "name": "target2", "type": "container" }
		],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")

	resultStr := string(result)
	assert.Contains(t, resultStr, "target1,host")
	assert.Contains(t, resultStr, "target2,container")
}

func TestConvertHDFToCSV_FieldExtraction(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Test",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test",
				"descriptions": [{ "label": "default", "data": "Test" }],
				"impact": 0.5,
				"tags": {
					"nist": ["AC-2", "AC-3", "IA-5 (1)"],
					"cci": ["CCI-000001", "CCI-000002"],
					"severity": "medium"
				},
				"sourceLocation": { "ref": "REQ-001", "line": 1 },
				"results": [{
					"status": "failed",
					"codeDesc": "Test",
					"message": "Security control not implemented",
					"startTime": "2026-01-29T18:00:00.000Z"
				}]
			}]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")

	resultStr := string(result)
	assert.Contains(t, resultStr, "AC-2; AC-3; IA-5 (1)")
	assert.Contains(t, resultStr, "CCI-000001; CCI-000002")
	assert.Contains(t, resultStr, "Security control not implemented")
}

func TestConvertHDFToCSV_CSVInjection(t *testing.T) {
	mkReq := func(id, title, desc string) hdf.EvaluatedRequirement {
		return testhdf.Req(id, testhdf.Title(title), testhdf.Desc(desc),
			testhdf.Impact(0.5), testhdf.Tag("severity", "medium"), testhdf.Status(hdf.Passed))
	}
	input, _ := json.Marshal(testhdf.Doc(testhdf.Baseline("Test",
		mkReq("REQ-001", "=1+1", "=SUM(A1:A10)"),
		mkReq("REQ-002", "+dangerous", "test"),
		mkReq("REQ-003", "-dangerous", "test"),
		mkReq("REQ-004", "@dangerous", "test"),
	)))

	result, err := ConvertHDFToCSV(input)
	require.NoError(t, err, "Conversion should succeed")

	resultStr := string(result)
	assert.Contains(t, resultStr, "'=1+1")
	assert.Contains(t, resultStr, "'=SUM(A1:A10)")
	assert.Contains(t, resultStr, "'+dangerous")
	assert.Contains(t, resultStr, "'-dangerous")
	assert.Contains(t, resultStr, "'@dangerous")
}

func TestGetSeverity_ArrayPath(t *testing.T) {
	t.Run("severity tag as []interface{} slice returns first element", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{
			Impact: 0.5,
			Tags: map[string]interface{}{
				"severity": []interface{}{"high", "critical"},
			},
		}
		result := getSeverity(req)
		assert.Equal(t, "high", result)
	})

	t.Run("impact exactly 0.7 returns high", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.7}
		assert.Equal(t, "high", getSeverity(req))
	})

	t.Run("impact exactly 0.4 returns medium", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.4}
		assert.Equal(t, "medium", getSeverity(req))
	})

	t.Run("impact 0.39 returns low", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.39}
		assert.Equal(t, "low", getSeverity(req))
	})

	t.Run("impact 0.0 returns low (below medium threshold)", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.0}
		assert.Equal(t, "low", getSeverity(req))
	})
}

func TestConvertHDFToCSV_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte("not valid json"))
	assert.Error(t, err)
}

func TestConvertHDFToCSV_MissingBaselines(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte("{}"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing baselines")
}

func TestConvertHDFToCSV_InvalidStructure(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte(`{ "baselines": "not an array" }`))
	assert.Error(t, err)
}

// TestGoldenParity asserts byte-for-byte output against the frozen golden.
// The TypeScript test asserts against the SAME file, which is what guarantees
// TS<->Go parity: previously only TS compared to this golden, so Go's trailing
// newline (encoding/csv terminates every record) went unnoticed for months.
func TestGoldenParity(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-csv", "fixtures", "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	out, err := ConvertHDFToCSV(inputData)
	require.NoError(t, err)

	goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-csv", "fixtures", "expected", "minimal.csv")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, out, 0o600))
		return
	}

	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "read golden %s", goldenPath)
	assert.Equal(t, string(golden), string(out), "golden mismatch")
}

// A requirement with no results is malformed: hdf-results puts minItems 1 on
// results, no requirement in this repo's HDF fixtures carries an empty one, and
// "not evaluated" already has its own representation as a result with status
// notReviewed. So there is no legitimate producer, and the converter rejects
// rather than emitting a row whose blank Status cell is indistinguishable from a
// genuinely blank one.
//
// Go previously indexed Results[0] unchecked and panicked, taking the process
// down — there is no recover() in the CLI call path.
func TestConvertHDFToCSV_EmptyResultsIsRejected(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0,"tags":{},` +
		`"descriptions":[{"label":"default","data":"d"}],"results":[]}]}]}`)

	require.NotPanics(t, func() {
		_, err := ConvertHDFToCSV(input)
		require.Error(t, err, "a requirement with no results must be rejected, not rendered")
		assert.EqualError(t, err, `hdf-to-csv: requirement "V-1" has no results`,
			"the message names the offending requirement so the input can be found")
	})
}

// The guard owns this wording so the two languages cannot drift; before, Go said
// "invalid" and TypeScript "Invalid", and neither carried the converter prefix.
func TestConvertHDFToCSV_MissingBaselinesMessage(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte(`{}`))
	require.Error(t, err)
	assert.EqualError(t, err, "hdf-to-csv: invalid HDF structure: missing baselines field")
}

// csvStructureValidator is this converter's stand-in for a target schema: CSV
// has no published schema, but a document that does not parse, or whose rows
// disagree on column count, is malformed in the way a schema would catch. A
// no-op validator would make every MustConvert contract pass vacuously.
type csvStructureValidator struct{}

func (csvStructureValidator) Validate(doc []byte) error {
	if len(doc) == 0 {
		return nil // the converter's zero-row output
	}
	r := csv.NewReader(bytes.NewReader(doc))
	r.FieldsPerRecord = 0 // first record fixes the count; later mismatches error
	if _, err := r.ReadAll(); err != nil {
		return fmt.Errorf("output is not well-formed CSV: %w", err)
	}
	return nil
}

// TestConvertHDFToCSV_AdversarialCorpus holds this converter to the shared
// corpus contracts. Strictness makes the empty-results case a rejection, which
// the MustNotCorrupt contract permits.
func TestConvertHDFToCSV_AdversarialCorpus(t *testing.T) {
	shared.RunSchemaCorpus(t, csvStructureValidator{}, shared.ResultsCorpus(), ConvertHDFToCSV)
}

// corpusRejected marks a corpus case the converter refuses; the two languages
// phrase the error differently, so only the fact of refusing is compared.
const corpusRejected = "REJECTED"

// TestConvertHDFToCSV_CorpusOutputGolden pins what this converter emits for every
// corpus input so the two languages are compared against one another rather than
// each against its own expectations. Go owns regeneration
// (go test ./converters/hdf-to-csv/go/ -update); TypeScript only verifies.
func TestConvertHDFToCSV_CorpusOutputGolden(t *testing.T) {
	outputs := make(map[string]string, len(shared.ResultsCorpus()))
	for _, c := range shared.ResultsCorpus() {
		// A panic here would abort the whole package run rather than failing this
		// one test. It is folded into the same marker as a clean rejection, so this
		// golden pins output parity only — crash-versus-rejection is the corpus
		// contract's job, which type-switches on PanicError.
		out, err := shared.ConvertNoPanic(ConvertHDFToCSV, c.Input)
		if err != nil {
			outputs[c.Name] = corpusRejected
			continue
		}
		outputs[c.Name] = string(out)
	}

	actual, err := json.MarshalIndent(outputs, "", "  ")
	require.NoError(t, err)
	actual = append(actual, '\n')

	path := filepath.Join("..", "fixtures", "expected", "corpus-outputs.json")
	if shared.UpdateSnapshots() {
		require.NoError(t, os.WriteFile(path, actual, 0o600))
		t.Logf("updated %s", path)
		return
	}
	expected, err := os.ReadFile(path)
	require.NoError(t, err, "missing corpus output golden; regenerate with -update")
	require.JSONEq(t, string(expected), string(actual),
		"corpus output changed; if intentional regenerate with: go test ./converters/hdf-to-csv/go/ -update")
}

// Both shapes reach the same guard: an absent id must be named as empty rather
// than rendered from a zero value that reads like a real id, and a nil results
// (what "results": null decodes to) must report the same error as an empty one.
// These pin that Go agrees with the TypeScript peer on both.
func TestConvertHDFToCSV_MalformedResultsShapes(t *testing.T) {
	for _, tc := range []struct{ name, requirement, want string }{
		{
			"absent id",
			`{"impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],"results":[]}`,
			`hdf-to-csv: requirement "" has no results`,
		},
		{
			"null results",
			`{"id":"V-1","impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],"results":null}`,
			`hdf-to-csv: requirement "V-1" has no results`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(`{"baselines":[{"name":"b","requirements":[` + tc.requirement + `]}]}`)
			require.NotPanics(t, func() {
				_, err := ConvertHDFToCSV(input)
				require.Error(t, err)
				assert.EqualError(t, err, tc.want)
			})
		})
	}
}
