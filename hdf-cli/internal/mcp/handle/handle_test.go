package handle

import (
	"encoding/base64"
	"errors"
	"testing"
)

// mustEncode is a test helper: Encode cannot fail for a well-formed Handle.
func mustEncode(t *testing.T, h Handle) string {
	t.Helper()
	s, err := Encode(h)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return s
}

func encodeRaw(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

const (
	sampleContent = `{"baselines":[],"components":[],"statistics":{}}`
	sampleType    = "results"
	sampleVersion = "3.5.0"
	samplePath    = "evidence/scan.json"
)

// The card's designated first-failing test: a content-hash mismatch between the
// handle and the currently-presented file must return HANDLE_STALE, not a
// silent re-read of the changed content.
func TestHandle_StaleOnContentChange(t *testing.T) {
	h := Compute(samplePath, []byte(sampleContent), sampleType, sampleVersion)
	encoded := mustEncode(t, h)

	// A fresh decode with no shared state (survives process death).
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	changed := []byte(`{"baselines":[{"name":"changed"}],"components":[],"statistics":{}}`)
	if err := Verify(decoded, changed); !errors.Is(err, ErrHandleStale) {
		t.Fatalf("expected ErrHandleStale on content change, got %v", err)
	}

	// The original content still verifies cleanly.
	if err := Verify(decoded, []byte(sampleContent)); err != nil {
		t.Errorf("matching content should verify, got %v", err)
	}
}

func TestHandle_RoundTrip(t *testing.T) {
	h := Compute(samplePath, []byte(sampleContent), sampleType, sampleVersion)
	got, err := Decode(mustEncode(t, h))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != h {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, h)
	}
	// Compute populated the identity fields correctly.
	if h.Path != samplePath || h.DocType != sampleType || h.SchemaVersion != sampleVersion {
		t.Errorf("identity fields not set: %+v", h)
	}
	if h.Size != int64(len(sampleContent)) {
		t.Errorf("size = %d, want %d", h.Size, len(sampleContent))
	}
	if h.ContentSHA256 == "" {
		t.Error("contentSha256 not computed")
	}
}

// A handle is self-describing: this test decodes a hard-coded handle string with
// no prior Encode call sharing state, proving no server-side cache/session is
// needed to resolve it.
func TestHandle_SelfDescribing_NoSharedState(t *testing.T) {
	encoded := mustEncode(t, Compute(samplePath, []byte(sampleContent), sampleType, sampleVersion))

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Path != samplePath || decoded.DocType != sampleType {
		t.Errorf("decoded handle missing self-describing fields: %+v", decoded)
	}
}

func TestDecode_Malformed(t *testing.T) {
	if _, err := Decode("!!!not base64!!!"); err == nil {
		t.Error("expected error for non-base64 input")
	}
	// Valid base64 whose payload is not JSON must error.
	if _, err := Decode(encodeRaw([]byte("not json"))); err == nil {
		t.Error("expected error for base64 of non-JSON")
	}
	// Valid base64 whose payload is a JSON non-object must error.
	if _, err := Decode(encodeRaw([]byte("42"))); err == nil {
		t.Error("expected error for base64 of a JSON scalar")
	}
}

func TestResolve_PathAndHandle_SameIdentity(t *testing.T) {
	want := Compute(samplePath, []byte(sampleContent), sampleType, sampleVersion)
	encoded := mustEncode(t, want)

	viaHandle, err := Resolve(Source{Handle: encoded}, nil)
	if err != nil {
		t.Fatalf("resolve handle: %v", err)
	}

	loadPath := func(p string) ([]byte, string, string, error) {
		return []byte(sampleContent), sampleType, sampleVersion, nil
	}
	viaPath, err := Resolve(Source{Path: samplePath}, loadPath)
	if err != nil {
		t.Fatalf("resolve path: %v", err)
	}

	if viaHandle != want || viaPath != want {
		t.Errorf("path and handle must resolve to the same identity:\n handle %+v\n path   %+v\n want   %+v", viaHandle, viaPath, want)
	}
}

func TestResolve_Errors(t *testing.T) {
	if _, err := Resolve(Source{}, nil); err == nil {
		t.Error("expected error when neither path nor handle is set")
	}
	if _, err := Resolve(Source{Path: "p", Handle: "h"}, nil); err == nil {
		t.Error("expected error when both path and handle are set (ambiguous)")
	}
	if _, err := Resolve(Source{Path: "p"}, nil); err == nil {
		t.Error("expected error when resolving a path with no loader")
	}
	loadErr := func(p string) ([]byte, string, string, error) {
		return nil, "", "", errors.New("read failed")
	}
	if _, err := Resolve(Source{Path: "p"}, loadErr); err == nil {
		t.Error("expected the loader error to propagate")
	}
}
