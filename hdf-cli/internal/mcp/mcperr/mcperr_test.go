package mcperr

import (
	"errors"
	"strings"
	"testing"
)

// The card's designated first-failing test: every code in the closed set must
// name a concrete recovery/next call.
func TestError_EachCodeNamesNextCall(t *testing.T) {
	for _, code := range Codes {
		e := New(code, "something went wrong", nil)
		if e.NextCall == "" {
			t.Errorf("code %s has an empty next-call — every error must name the next call", code)
		}
		if e.Code != code {
			t.Errorf("New(%s) set Code=%s", code, e.Code)
		}
	}
}

// The closed set is exactly these nine — no more, no fewer.
func TestClosedSet_Exhaustive(t *testing.T) {
	want := map[Code]bool{
		DocumentNotFound: true,
		PathDenied:       true,
		TooLarge:         true,
		WrongDocType:     true,
		SchemaInvalid:    true,
		HandleStale:      true,
		NoConverter:      true,
		Truncated:        true,
		AmbiguousFormat:  true,
		OutputExists:     true,
		WriteFailed:      true,
		CacheMiss:        true,
	}
	if len(Codes) != len(want) {
		t.Fatalf("Codes has %d entries, want %d", len(Codes), len(want))
	}
	seen := map[Code]bool{}
	for _, c := range Codes {
		if !want[c] {
			t.Errorf("unexpected code in closed set: %s", c)
		}
		if seen[c] {
			t.Errorf("duplicate code in closed set: %s", c)
		}
		seen[c] = true
		// Every code must have recovery guidance registered.
		if defaultNextCall[c] == "" {
			t.Errorf("code %s missing default next-call guidance", c)
		}
	}
	for c := range want {
		if !seen[c] {
			t.Errorf("missing expected code from closed set: %s", c)
		}
	}
}

func TestWrongDocType_PointsAtInspect(t *testing.T) {
	e := New(WrongDocType, "hdf_query needs a results or baseline document", nil)
	if !strings.Contains(e.NextCall, "hdf_inspect") {
		t.Errorf("WRONG_DOC_TYPE should point at hdf_inspect, got %q", e.NextCall)
	}
}

func TestError_AsToolResult_IsError(t *testing.T) {
	for _, code := range Codes {
		tr := New(code, "msg", map[string]any{"k": "v"}).AsToolResult()
		if !tr.IsError {
			t.Errorf("taxonomy code %s must map to a tool result with isError=true", code)
		}
		if tr.Code != code || tr.NextCall == "" {
			t.Errorf("tool result for %s lost code/nextCall: %+v", code, tr)
		}
		if tr.Details["k"] != "v" {
			t.Errorf("tool result for %s dropped details", code)
		}
	}
}

func TestWritesDisabled_NotIsError(t *testing.T) {
	preview := map[string]any{"outputPath": "/root/out.json", "would": "write"}
	r := WritesDisabled(preview)
	if r.IsError {
		t.Fatal("WRITES_DISABLED must NOT be an isError — it is a successful preview")
	}
	if !r.WritesDisabled {
		t.Error("writesDisabled flag must be true")
	}
	if r.Preview == nil {
		t.Error("the would-write preview must be carried")
	}
	if r.Notice == "" {
		t.Error("a writes-disabled notice must be present")
	}
	// WRITES_DISABLED is not a member of the closed taxonomy.
	for _, c := range Codes {
		if string(c) == "WRITES_DISABLED" {
			t.Error("WRITES_DISABLED must not be in the closed isError taxonomy")
		}
	}
}

func TestError_ImplementsErrorAndUnwraps(t *testing.T) {
	e := New(HandleStale, "file changed on disk", nil)
	var asErr error = e
	if asErr.Error() == "" {
		t.Error("Error() must return a non-empty message")
	}
	if !strings.Contains(asErr.Error(), "HANDLE_STALE") {
		t.Errorf("Error() should include the code, got %q", asErr.Error())
	}
	// errors.As recovers the concrete type + code.
	var target *Error
	if !errors.As(asErr, &target) || target.Code != HandleStale {
		t.Error("errors.As should recover *Error with its Code")
	}
}

func TestNew_NextCallOverride(t *testing.T) {
	e := New(NoConverter, "no converter for gizmo→hdf", nil).WithNextCall("run `hdf convert --from nessus`")
	if !strings.Contains(e.NextCall, "hdf convert") {
		t.Errorf("WithNextCall should override the default guidance, got %q", e.NextCall)
	}
}
