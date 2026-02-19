package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvertCommand_ArgValidation(t *testing.T) {
	// Note: Cobra's Args validation errors are returned but not printed
	// when SilenceErrors is true, so we only check wantErr, not wantErrMsg
	runCLITests(t, []cliTest{
		{name: "no args", args: []string{"convert"}, wantErr: true},
		{name: "one arg", args: []string{"convert", "legacyhdf"}, wantErr: true},
		{name: "two args", args: []string{"convert", "legacyhdf", "to"}, wantErr: true},
		{name: "three args", args: []string{"convert", "legacyhdf", "to", "hdf"}, wantErr: true},
		{name: "missing to keyword", args: []string{"convert", "legacyhdf", "hdf", "input.json"}, wantErr: true},
		{name: "wrong to keyword", args: []string{"convert", "legacyhdf", "into", "hdf", "input.json"}, wantErr: true},
		{name: "too many args", args: []string{"convert", "legacyhdf", "to", "hdf", "in.json", "out.json", "extra"}, wantErr: true},
	})
}

func TestConvertCommand_UnsupportedFormats(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	// Note: Unsupported format errors come from Args validation, which
	// doesn't print to stderr when SilenceErrors is true
	runCLITests(t, []cliTest{
		{name: "unknown source format", args: []string{"convert", "unknown", "to", "hdf", fixture}, wantErr: true},
		{name: "unknown dest format", args: []string{"convert", "legacyhdf", "to", "unknown", fixture}, wantErr: true},
		{name: "both unknown", args: []string{"convert", "foo", "to", "bar", fixture}, wantErr: true},
	})
}

func TestConvertCommand_FileNotFound(t *testing.T) {
	runCLITests(t, []cliTest{
		{name: "nonexistent file", args: []string{"convert", "legacyhdf", "to", "hdf", "nonexistent.json"}, wantErr: true, wantErrMsg: "not found"},
	})
}

func TestConvertCommand_BasicConversion(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	stdout, stderr, err := executeCommand("convert", "legacyhdf", "to", "hdf", fixture)
	if err != nil {
		t.Errorf("convert command failed: %v (stderr: %s)", err, stderr)
		return
	}

	// Verify output is valid JSON with v2.0 structure
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
		return
	}

	if _, ok := result["baselines"]; !ok {
		t.Error("output missing 'baselines' field")
	}
	if _, ok := result["targets"]; !ok {
		t.Error("output missing 'targets' field")
	}
}

func TestConvertCommand_CaseInsensitive(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	tests := []struct {
		name   string
		source string
		dest   string
	}{
		{"lowercase", "legacyhdf", "hdf"},
		{"uppercase", "LEGACYHDF", "HDF"},
		{"mixed case", "LegacyHDF", "HDF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := executeCommand("convert", tt.source, "to", tt.dest, fixture)
			if err != nil {
				t.Errorf("convert %s to %s failed: %v", tt.source, tt.dest, err)
				return
			}

			var result map[string]interface{}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Errorf("output is not valid JSON: %v", err)
			}
		})
	}
}

func TestConvertCommand_OutputToFile(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.json")

	_, stderr, err := executeCommand("convert", "legacyhdf", "to", "hdf", fixture, outputPath)
	if err != nil {
		t.Errorf("convert command failed: %v (stderr: %s)", err, stderr)
		return
	}

	// Verify output file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("output file was not created")
		return
	}

	// Verify output file is valid JSON
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Errorf("failed to read output file: %v", err)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Errorf("output file is not valid JSON: %v", err)
	}
}

func TestConvertCommand_InvalidInput(t *testing.T) {
	// Create a temp file with invalid content
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidFile, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("failed to create invalid file: %v", err)
	}

	_, _, err := executeCommand("convert", "legacyhdf", "to", "hdf", invalidFile)
	if err == nil {
		t.Error("expected error for invalid input, got nil")
	}
}

func TestConvertCommand_Help(t *testing.T) {
	stdout, _, _ := executeCommand("convert", "--help")

	// Should show usage examples
	if !strings.Contains(stdout, "legacyhdf") {
		t.Error("help should mention legacyhdf format")
	}
	if !strings.Contains(stdout, "to") {
		t.Error("help should mention 'to' keyword")
	}
}

func TestConvertCommand_ListsConverters(t *testing.T) {
	stdout, _, _ := executeCommand("convert", "--help")

	// Should list available conversions
	if !strings.Contains(strings.ToLower(stdout), "legacyhdf") {
		t.Error("help should list legacyhdf converter")
	}
}

func TestConvertCommand_ErrorMessages(t *testing.T) {
	// These tests exercise the three switch cases in buildConverterNotFoundError:
	//   case len(sourceDestinations) > 0: source format is known, dest is unknown
	//   case len(destSources) > 0:        dest format is known, source is unknown
	//   default:                           neither format is recognized
	//
	// The error is emitted to stderr via executeCommand's "Error: %v" wrapper.
	fixture := legacyhdfFixturePath(t, "input/minimal.json")

	tests := []struct {
		name       string
		src        string
		dst        string
		wantErrMsg string
	}{
		{
			name:       "known source unknown dest (sourceDestinations>0 branch)",
			src:        "legacyhdf",
			dst:        "unknown",
			wantErrMsg: "legacyhdf",
		},
		{
			name:       "unknown source known dest (destSources>0 branch)",
			src:        "unknown",
			dst:        "hdf",
			wantErrMsg: "hdf",
		},
		{
			name:       "both unknown (default branch)",
			src:        "foo",
			dst:        "bar",
			wantErrMsg: "foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, err := executeCommand("convert", tt.src, "to", tt.dst, fixture)
			if err == nil {
				t.Fatalf("expected error for %s->%s, got nil", tt.src, tt.dst)
			}
			if !strings.Contains(stderr, tt.wantErrMsg) {
				t.Errorf("stderr = %q, expected to contain %q", stderr, tt.wantErrMsg)
			}
		})
	}
}
