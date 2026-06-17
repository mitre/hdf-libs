package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectHDFDocType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{
			name:   "Results doc has baselines key",
			input:  `{"baselines":[],"timestamp":"2026-01-01T00:00:00Z"}`,
			want:   "results",
			wantOK: true,
		},
		{
			name:   "Baseline doc has requirements key",
			input:  `{"requirements":[],"name":"Some Baseline"}`,
			want:   "baseline",
			wantOK: true,
		},
		{
			name:   "non-HDF JSON is not detected",
			input:  `{"items":[],"some":"other"}`,
			want:   "",
			wantOK: false,
		},
		{
			name:   "non-JSON bytes are not detected",
			input:  `<xml>not json</xml>`,
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty input is not detected",
			input:  "",
			want:   "",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := detectHDFDocType([]byte(tc.input))
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValidateHDFOutput_RejectsEmptyRequirements(t *testing.T) {
	t.Parallel()

	// HDF Results doc with empty requirements array — violates minItems: 1.
	// This is exactly the issue #80 anti-pattern: an empty baseline that
	// satisfies all other invariants but breaks requirements.minItems=1.
	invalid := `{
		"timestamp": "2026-01-01T00:00:00Z",
		"generator": {"name": "test", "version": "0.0.1"},
		"baselines": [
			{
				"name": "Test Scan",
				"resultsChecksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
				"requirements": []
			}
		]
	}`

	err := validateHDFOutput([]byte(invalid))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
}

func TestValidateHDFOutput_AcceptsValidResults(t *testing.T) {
	t.Parallel()

	// HDF Results with one passed placeholder — the synthesized clean-scan shape.
	valid := `{
		"timestamp": "2026-01-01T00:00:00Z",
		"generator": {"name": "test", "version": "0.0.1"},
		"baselines": [
			{
				"name": "Test Scan",
				"resultsChecksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
				"requirements": [
					{
						"id": "test-no-findings",
						"title": "No findings reported",
						"impact": 0,
						"tags": {},
						"descriptions": [{"label": "default", "data": "test scanned and found nothing"}],
						"results": [{"status": "passed", "codeDesc": "test scanned and found nothing", "startTime": "2026-01-01T00:00:00Z"}]
					}
				]
			}
		]
	}`

	err := validateHDFOutput([]byte(valid))
	assert.NoError(t, err)
}

func TestValidateHDFOutput_SkipsNonHDF(t *testing.T) {
	t.Parallel()

	// Non-HDF output (e.g., CKL XML or CSV bytes) should not be validated.
	cases := []string{
		`<?xml version="1.0"?><CHECKLIST></CHECKLIST>`,
		`col1,col2\nval1,val2`,
		`{"oscalCatalog":{"uuid":"test"}}`,
	}
	for _, in := range cases {
		assert.NoError(t, validateHDFOutput([]byte(in)))
	}
}

func TestWriteValidatedHDFOutput_BlocksInvalidOutput(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	addNoValidateFlag(cmd)

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "out.json")

	invalid := []byte(`{"baselines":[{"name":"Bad","resultsChecksum":{"algorithm":"sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"requirements":[]}],"timestamp":"2026-01-01T00:00:00Z"}`)

	err := writeValidatedHDFOutput(cmd, invalid, outPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
	assert.Contains(t, err.Error(), noValidateFlag)

	// Critical: the file must not have been written.
	_, statErr := os.Stat(outPath)
	assert.True(t, os.IsNotExist(statErr), "writeValidatedHDFOutput must not write the invalid file")
}

func TestWriteValidatedHDFOutput_NoValidateFlagSkipsCheck(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	addNoValidateFlag(cmd)
	require.NoError(t, cmd.Flags().Set(noValidateFlag, "true"))

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "out.json")

	invalid := []byte(`{"baselines":[{"name":"Bad","resultsChecksum":{"algorithm":"sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"requirements":[]}],"timestamp":"2026-01-01T00:00:00Z"}`)

	err := writeValidatedHDFOutput(cmd, invalid, outPath)
	require.NoError(t, err)

	// File must be written when --no-validate is set, even with invalid content.
	written, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(written), `"baselines"`))
}

func TestDetectHDFDocType_DetectsAmendments(t *testing.T) {
	t.Parallel()
	docType, ok := detectHDFDocType([]byte(`{"overrides":[{"type":"waiver","requirementId":"AC-1"}]}`))
	assert.True(t, ok)
	assert.Equal(t, "amendments", docType)
}

func TestValidateHDFOutput_RejectsInvalidAmendments(t *testing.T) {
	t.Parallel()
	invalid := []byte(`{"overrides":[{"type":"waiver","requirementId":"AC-1"}]}`)
	err := validateHDFOutput(invalid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Amendments")
}

func TestValidateHDFOutput_AcceptsValidAmendments(t *testing.T) {
	t.Parallel()
	valid := []byte(`{
		"name": "Test Waivers",
		"overrides": [
			{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "Compensating control documented",
				"appliedBy": {"type": "email", "identifier": "ao@agency.gov"},
				"appliedAt": "2026-01-01T00:00:00Z",
				"expiresAt": "2027-01-01T00:00:00Z"
			}
		]
	}`)
	err := validateHDFOutput(valid)
	assert.NoError(t, err)
}

// --- System / Plan / EvidencePackage / Comparison detection + validation ---

func TestDetectHDFDocType_DetectsSystemPlanEvidenceComparison(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"system via components", `{"name":"s","components":[{"name":"c","type":"application"}]}`, "system"},
		{"plan via assessments", `{"name":"p","assessments":[{"baselineRef":"x"}]}`, "plan"},
		{"evidence via contents", `{"name":"e","contents":[{"type":"hdf-results","uri":"a","checksum":{"algorithm":"sha256","value":"abc"}}]}`, "evidencePackage"},
		{"comparison via requirementDiffs", `{"formatVersion":"1.0.0","requirementDiffs":[]}`, "comparison"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := detectHDFDocType([]byte(tc.input))
			assert.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValidateHDFOutput_AcceptsValidSystem(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"name":"sys","components":[{"name":"c","type":"application"}]}`)
	assert.NoError(t, validateHDFOutput(valid))
}

func TestValidateHDFOutput_RejectsInvalidSystem(t *testing.T) {
	t.Parallel()
	// components is required and minItems=1; the discriminator probe still
	// sees the (empty) components key so detection succeeds, but validation
	// rejects the doc.
	invalid := []byte(`{"name":"sys","components":[]}`)
	err := validateHDFOutput(invalid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "System")
}

func TestValidateHDFOutput_AcceptsValidPlan(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"name":"plan","assessments":[{"baselineRef":"RHEL9-STIG"}]}`)
	assert.NoError(t, validateHDFOutput(valid))
}

func TestValidateHDFOutput_RejectsInvalidPlan(t *testing.T) {
	t.Parallel()
	invalid := []byte(`{"assessments":[]}`)
	err := validateHDFOutput(invalid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Plan")
}

func TestValidateHDFOutput_AcceptsValidEvidencePackage(t *testing.T) {
	t.Parallel()
	valid := []byte(`{
		"name": "ep",
		"contents": [
			{"type":"hdf-results","uri":"a.json","checksum":{"algorithm":"sha256","value":"abc"}}
		]
	}`)
	assert.NoError(t, validateHDFOutput(valid))
}

func TestValidateHDFOutput_RejectsInvalidEvidencePackage(t *testing.T) {
	t.Parallel()
	invalid := []byte(`{"contents":[]}`)
	err := validateHDFOutput(invalid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Evidence Package")
}

func TestValidateHDFOutput_AcceptsValidComparison(t *testing.T) {
	t.Parallel()
	valid := []byte(`{
		"formatVersion": "1.0.0",
		"comparisonMode": "temporal",
		"sources": [
			{"role": "old", "label": "v1"},
			{"role": "new", "label": "v2"}
		],
		"summary": {"total":0,"matchedCount":0,"unmatchedOldCount":0,"unmatchedNewCount":0},
		"requirementDiffs": []
	}`)
	assert.NoError(t, validateHDFOutput(valid))
}

func TestValidateHDFOutput_RejectsInvalidComparison(t *testing.T) {
	t.Parallel()
	// requirementDiffs present (detection passes) but formatVersion is wrong.
	invalid := []byte(`{"formatVersion":"0.0.1","requirementDiffs":[]}`)
	err := validateHDFOutput(invalid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Comparison")
}
