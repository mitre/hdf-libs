package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadFromFile_NotFound(t *testing.T) {
	_, err := readFromFile("/nonexistent/path/to/file.json", false)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadFromFile_IsDirectory(t *testing.T) {
	// Use temp directory
	tmpDir := t.TempDir()
	_, err := readFromFile(tmpDir, false)
	if err == nil {
		t.Error("expected error for directory")
	}
	if err.Error() != tmpDir+" is a directory, not a file" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadFromFile_EmptyFile(t *testing.T) {
	// Create empty temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.json")
	if err := os.WriteFile(tmpFile, []byte{}, 0o600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	_, err := readFromFile(tmpFile, false)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestReadFromFile_ValidFile(t *testing.T) {
	// Create temp file with content
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.json")
	content := []byte(`{"test": "data"}`)
	if err := os.WriteFile(tmpFile, content, 0o600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	data, err := readFromFile(tmpFile, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", data, content)
	}
}

func TestReadInputFile_StripsBOM(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bom.json")
	content := []byte(`{"test": "data"}`)
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, content...)
	if err := os.WriteFile(tmpFile, withBOM, 0o600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	data, err := readInputFile(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("BOM not stripped: got %q, want %q", data, content)
	}
}

func TestReadInputFile_NoBOMUnchanged(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "plain.json")
	content := []byte(`{"test": "data"}`)
	if err := os.WriteFile(tmpFile, content, 0o600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	data, err := readInputFile(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content altered: got %q, want %q", data, content)
	}
}

func TestReadInputFile_BOMOnly(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bomonly.json")
	if err := os.WriteFile(tmpFile, []byte{0xEF, 0xBB, 0xBF}, 0o600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	_, err := readInputFile(tmpFile)
	if err == nil {
		t.Fatal("expected error for a file containing only a BOM")
	}
	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadFromFileReportsTheLimitInEffect(t *testing.T) {
	oldMax := maxSizeMB
	maxSizeMB = 0 // --max-size 0 falls back to the default limit
	defer func() { maxSizeMB = oldMax }()

	// A sparse file reports its full size to Stat without writing the bytes.
	big := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(getMaxFileSize() + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = readFromFile(big, false)
	if err == nil {
		t.Fatal("expected an error for a file over the default limit")
	}
	want := fmt.Sprintf("max %d MB", DefaultMaxSizeMB)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q should report the limit in effect (%s)", err, want)
	}
	if !strings.Contains(err.Error(), big) {
		t.Errorf("error %q should name the file it refused", err)
	}
}

func TestMaxSizeFlag_RejectsAValueWhoseByteCountOverflows(t *testing.T) {
	oldMax := maxSizeMB
	defer func() { maxSizeMB = oldMax }()

	_, _, err := executeCommand("--max-size", "17592186044416", "version")
	if err == nil {
		t.Fatal("expected --max-size 17592186044416 to be refused: its byte count wraps to 0")
	}
	for _, want := range []string{"--max-size 17592186044416", "largest supported value"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err, want)
		}
	}
	if maxSizeMB != oldMax {
		t.Errorf("a refused flag must not reach the global: got %d", maxSizeMB)
	}
}

func TestParseHDFResults_InvalidJSON(t *testing.T) {
	_, err := parseHDFResults([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseHDFResults_TrailingGarbage(t *testing.T) {
	// Valid JSON followed by extra data
	_, err := parseHDFResults([]byte(`{"version": "1.0"}extra`))
	if err == nil {
		t.Error("expected error for trailing garbage")
	}
}

func TestParseHDFResults_ValidMinimal(t *testing.T) {
	// Minimal valid HDF v2.0 structure
	json := `{
		"baselines": [],
		"statistics": {}
	}`
	result, err := parseHDFResults([]byte(json))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result.Baselines) != 0 {
		t.Errorf("baselines length mismatch: got %d, want 0", len(result.Baselines))
	}
}

func TestParseHDFBaseline_InvalidJSON(t *testing.T) {
	_, err := parseHDFBaseline([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestGetMaxFileSize(t *testing.T) {
	// Verify default max size matches DefaultMaxSizeMB (256MB).
	expected := int64(DefaultMaxSizeMB) * 1024 * 1024
	actual := getMaxFileSize()
	if actual != expected {
		t.Errorf("getMaxFileSize() = %d, want %d", actual, expected)
	}
}

func TestReadStatted_ReturnsTheStattedBytes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		size  int64
	}{
		{"exactly the stat'd size", "abc", 3},
		{"shrunk since the stat", "ab", 3},
		{"empty file", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := readStatted(strings.NewReader(c.input), c.size, "scan.json")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(data) != c.input {
				t.Errorf("got %q, want %q", data, c.input)
			}
		})
	}
}

// A file appended to between its Stat and its read delivers more bytes than the Stat
// reported. That is a partial snapshot of a file still being written, so it is refused
// however far under --max-size it is, instead of being parsed, hashed or archived.
func TestReadStatted_RefusesAFileThatGrewSinceTheStat(t *testing.T) {
	data, err := readStatted(strings.NewReader("abcd"), 3, "scan.json")
	if err == nil {
		t.Fatalf("a reader yielding more than the stat'd 3 bytes must error, got %q", data)
	}
	if data != nil {
		t.Errorf("got %d bytes alongside the error, want none", len(data))
	}
	for _, want := range []string{"input grew while it was read", "scan.json", "(3 bytes at open)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err, want)
		}
	}
}

func TestReadStatted_ReportsAReadFailureWithThePath(t *testing.T) {
	cause := errors.New("disk fell over")
	data, err := readStatted(iotest.ErrReader(cause), 3, "scan.json")
	if data != nil {
		t.Errorf("got %d bytes alongside the error, want none", len(data))
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error %v should wrap the read failure %v", err, cause)
	}
	if !strings.Contains(err.Error(), "failed to read scan.json") {
		t.Errorf("error %q should name the path", err)
	}
}

func TestGetMaxFileSize_LargestFlagDoesNotOverflow(t *testing.T) {
	oldMax := maxSizeMB
	maxSizeMB = maxMaxSizeMB
	defer func() { maxSizeMB = oldMax }()

	if got := getMaxFileSize(); got <= 0 || got != int64(maxMaxSizeMB)*1024*1024 {
		t.Errorf("getMaxFileSize() at the largest flag = %d, want %d", got, int64(maxMaxSizeMB)*1024*1024)
	}
}
