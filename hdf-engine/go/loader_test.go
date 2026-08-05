package hdfengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestLoad_Results_Valid(t *testing.T) {
	data := loadFixtureBytes(t, "query-fixture.json")
	res, err := Load(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Format != FormatJSON {
		t.Errorf("format = %q, want json", res.Format)
	}
	if res.DocType != "results" {
		t.Errorf("docType = %q, want results", res.DocType)
	}
	if !res.Valid || res.Results == nil {
		t.Fatalf("expected valid results, got valid=%v results=%v err=%q", res.Valid, res.Results != nil, res.ParseError)
	}
	if res.Baseline != nil {
		t.Error("baseline should be nil for a results document")
	}
}

func TestLoad_Baseline_Valid(t *testing.T) {
	data := loadFixtureBytes(t, "baseline-fixture.json")
	res, err := Load(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.DocType != "baseline" {
		t.Errorf("docType = %q, want baseline", res.DocType)
	}
	if !res.Valid || res.Baseline == nil {
		t.Fatalf("expected valid baseline, got valid=%v baseline=%v err=%q", res.Valid, res.Baseline != nil, res.ParseError)
	}
	if res.Results != nil {
		t.Error("results should be nil for a baseline document")
	}
}

func TestLoad_SizeGuardRunsFirst(t *testing.T) {
	// Oversized, non-JSON input with a tiny limit must fail with the SIZE error,
	// proving the size guard runs before any parse/detect.
	_, err := Load([]byte("this is not json and is over the tiny limit"), 4)
	if err == nil {
		t.Fatal("expected size error")
	}
	if got := err.Error(); !strings.Contains(got, "exceeds maximum") {
		t.Errorf("expected size error, got %q", got)
	}
}

func TestLoad_NDJSON_Detected(t *testing.T) {
	nd := []byte("{\"a\":1}\n{\"b\":2}\n")
	res, err := Load(nd, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Format != FormatNDJSON {
		t.Errorf("format = %q, want ndjson", res.Format)
	}
}

func TestLoad_PrettyPrintedSingleObject_IsJSON(t *testing.T) {
	// A pretty-printed single object spans many lines but is NOT NDJSON.
	pretty := loadFixtureBytes(t, "query-fixture.json")
	res, err := Load(pretty, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Format != FormatJSON {
		t.Errorf("pretty-printed object: format = %q, want json", res.Format)
	}
}

func TestLoad_InvalidResults_ReportsParseErrorNotHardFail(t *testing.T) {
	// Detected as results (has "baselines") but schema-invalid: the core returns
	// DocType + ParseError with Valid=false, and no Go error.
	bad := []byte(`{"baselines": "not an array", "components": [], "statistics": {}}`)
	res, err := Load(bad, 0)
	if err != nil {
		t.Fatalf("core should not hard-fail on invalid content: %v", err)
	}
	if res.DocType != "results" {
		t.Errorf("docType = %q, want results (detected by baselines key)", res.DocType)
	}
	if res.Valid {
		t.Error("invalid document should not be Valid")
	}
	if res.ParseError == "" {
		t.Error("expected a ParseError message for the invalid document")
	}
}

func TestLoad_UnknownType(t *testing.T) {
	res, err := Load([]byte(`{"unrecognized": true}`), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.DocType != "" {
		t.Errorf("docType = %q, want empty for unknown type", res.DocType)
	}
	if res.Valid {
		t.Error("unknown type should not be Valid")
	}
	if res.ParseError != "" {
		t.Errorf("unknown type should not carry a ParseError, got %q", res.ParseError)
	}
}

func TestLoad_NonJSON(t *testing.T) {
	res, err := Load([]byte("not json at all"), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.DocType != "" {
		t.Errorf("non-JSON docType = %q, want empty", res.DocType)
	}
	if res.Format != FormatJSON {
		t.Errorf("single-line non-JSON format = %q, want json (not ndjson)", res.Format)
	}
}
