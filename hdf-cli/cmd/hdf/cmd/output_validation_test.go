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
