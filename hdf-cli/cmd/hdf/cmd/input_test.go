package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestReadFromFile_TooLarge(t *testing.T) {
	// Create a file that exceeds the size limit
	// We'll test this by temporarily setting a small limit
	// Since MaxHDFFileSize is a const, we can't easily test this
	// without creating a huge file, so we'll skip this test
	t.Skip("skipping large file test - would require creating 50MB+ file")
}

func TestReadInputFile_StdinPath(t *testing.T) {
	// When path is "-", it should try to read from stdin
	// This is hard to test without mocking stdin
	// The function returns "no input provided" for empty stdin
	t.Skip("skipping stdin test - requires stdin mocking")
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
	// Verify default max size is 50MB
	expected := int64(50 * 1024 * 1024)
	actual := getMaxFileSize()
	if actual != expected {
		t.Errorf("getMaxFileSize() = %d, want %d", actual, expected)
	}
}

// ── safePath tests ──────────────────────────────────────────────────────
// Use t.TempDir() for cross-platform paths (Windows uses C:\Users\...).

func TestSafePath_ValidRelative(t *testing.T) {
	base := t.TempDir()
	result, err := safePath(base, "subdir/file.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(base, "subdir", "file.json")
	if result != want {
		t.Errorf("got %q, want %q", result, want)
	}
}

func TestSafePath_ValidBasename(t *testing.T) {
	base := t.TempDir()
	result, err := safePath(base, "file.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(base, "file.json")
	if result != want {
		t.Errorf("got %q, want %q", result, want)
	}
}

func TestSafePath_TraversalBlocked(t *testing.T) {
	base := t.TempDir()
	_, err := safePath(base, "../outside.json")
	if err == nil {
		t.Fatal("expected error for ../ traversal")
	}
}

func TestSafePath_DeepTraversalBlocked(t *testing.T) {
	base := t.TempDir()
	_, err := safePath(base, "subdir/../../outside.json")
	if err == nil {
		t.Fatal("expected error for deep traversal")
	}
}

func TestSafePath_EmptyPathBlocked(t *testing.T) {
	base := t.TempDir()
	_, err := safePath(base, "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSafePath_DotResolvesToBase(t *testing.T) {
	base := t.TempDir()
	result, err := safePath(base, ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Clean(base)
	if result != want {
		t.Errorf("got %q, want %q", result, want)
	}
}
