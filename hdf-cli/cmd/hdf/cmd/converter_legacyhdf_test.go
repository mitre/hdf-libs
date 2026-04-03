package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// legacyhdfFixturePath returns the path to a legacyhdf test fixture.
func legacyhdfFixturePath(t *testing.T, name string) string {
	t.Helper()
	// Navigate from cmd/hdf/cmd to hdf-converters/converters/legacyhdf-to-hdf/fixtures
	path := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "legacyhdf-to-hdf", "fixtures", name)
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		t.Skipf("fixture not found: %s", absPath)
	}
	return absPath
}

func TestLegacyHDFConverter_IsRegistered(t *testing.T) {
	// The converter should be registered on init
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Errorf("legacyhdf->hdf converter not registered: %v", err)
	}
	if conv == nil {
		t.Error("GetConverter returned nil converter")
	}
}

func TestLegacyHDFConverter_Name(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skipf("legacyhdf converter not registered: %v", err)
	}

	name := conv.Name()
	if name == "" {
		t.Error("converter Name() returned empty string")
	}
}

func TestLegacyHDFConverter_Convert_Minimal(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skipf("legacyhdf converter not registered: %v", err)
	}

	inputPath := legacyhdfFixturePath(t, "input/minimal.json")
	input, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("failed to read input fixture: %v", err)
	}

	output, err := conv.Convert(input)
	if err != nil {
		t.Errorf("Convert() error = %v", err)
		return
	}

	// Verify output is valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Errorf("Convert() output is not valid JSON: %v", err)
	}

	// Verify it has v2.0 structure (baselines, targets)
	if _, ok := result["baselines"]; !ok {
		t.Error("Convert() output missing 'baselines' field")
	}
	if _, ok := result["components"]; !ok {
		t.Error("Convert() output missing 'targets' field")
	}
}

func TestLegacyHDFConverter_Convert_ContainerScan(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skipf("legacyhdf converter not registered: %v", err)
	}

	inputPath := legacyhdfFixturePath(t, "input/container-scan.json")
	input, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("failed to read input fixture: %v", err)
	}

	output, err := conv.Convert(input)
	if err != nil {
		t.Errorf("Convert() error = %v", err)
		return
	}

	// Verify output is valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Errorf("Convert() output is not valid JSON: %v", err)
	}

	// Verify it has baselines with requirements
	baselines, ok := result["baselines"].([]interface{})
	if !ok || len(baselines) == 0 {
		t.Error("Convert() output has no baselines")
	}
}

func TestLegacyHDFConverter_Convert_InvalidJSON(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skipf("legacyhdf converter not registered: %v", err)
	}

	input := []byte("not valid json")
	_, err = conv.Convert(input)
	if err == nil {
		t.Error("Convert() expected error for invalid JSON, got nil")
	}
}

func TestLegacyHDFConverter_Convert_EmptyInput(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skipf("legacyhdf converter not registered: %v", err)
	}

	input := []byte("")
	_, err = conv.Convert(input)
	if err == nil {
		t.Error("Convert() expected error for empty input, got nil")
	}
}

func TestLegacyHDFConverter_Convert_NotV1Format(t *testing.T) {
	conv, err := GetConverter("legacyhdf", "hdf")
	if err != nil {
		t.Skipf("legacyhdf converter not registered: %v", err)
	}

	// Valid JSON but not v1.0 format (missing required fields)
	input := []byte(`{"baselines": [], "components": []}`)
	_, err = conv.Convert(input)
	if err == nil {
		t.Error("Convert() expected error for non-v1 JSON, got nil")
	}
}
