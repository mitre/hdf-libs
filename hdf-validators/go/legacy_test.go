package hdfvalidators

import (
	"os"
	"testing"
)

// A real HDF v2 (Heimdall/InSpec exec-json) document validates against the pinned
// legacy schema — the userbase's existing docs are validatable, not just
// convertible.
func TestValidateLegacyV2_ValidInSpecExecJSON(t *testing.T) {
	data, err := os.ReadFile("legacy/testdata/inspec-exec-json-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	res := ValidateLegacyV2(data)
	if !res.Valid {
		t.Fatalf("real InSpec exec-json should validate as v2; got errors: %v", res.Errors)
	}
}

// A malformed v2 doc is rejected at the same rigor as v3 — missing required
// top-level fields (platform/profiles/statistics/version) yields field-level
// errors, not a pass.
func TestValidateLegacyV2_RejectsMalformed(t *testing.T) {
	res := ValidateLegacyV2([]byte(`{"profiles": "not-an-array"}`))
	if res.Valid {
		t.Fatal("a malformed v2 doc must be rejected")
	}
	if len(res.Errors) == 0 {
		t.Error("expected field-level validation errors")
	}
}

// Real Heimdall/InSpec output diverges from the stale published schema in four
// documented ways; all four are accepted (see legacy/PROVENANCE.md). A control
// that omits impact, has an empty {} ref, a string source_location, and an
// object resource_id validates.
func TestValidateLegacyV2_AcceptsRealWorldDeviations(t *testing.T) {
	doc := []byte(`{
      "platform": {"name": "t", "release": "1"},
      "version": "5.22.0",
      "statistics": {"duration": 0.1},
      "profiles": [{
        "name": "p", "version": "1.0.0", "supports": [], "groups": [], "attributes": [], "sha256": "",
        "controls": [{
          "id": "c1", "tags": {}, "refs": [{}], "source_location": "/etc/passwd",
          "results": [{"status": "passed", "code_desc": "ok", "start_time": "2020-01-01T00:00:00Z",
                       "resource_id": {"minimum_password_length": 12}}]
        }]
      }]
    }`)
	res := ValidateLegacyV2(doc)
	if !res.Valid {
		t.Fatalf("real-world v2 deviations must validate; got: %v", res.Errors)
	}
}

// A v2 doc carrying top-level target/passthrough validates — the schema permits
// additional top-level properties, so attribution data rides through untouched.
func TestValidateLegacyV2_AcceptsTargetAndPassthrough(t *testing.T) {
	doc := []byte(`{
      "platform": {"name": "t", "release": "1"},
      "version": "5.22.0",
      "statistics": {"duration": 0.1},
      "target": {"id": "prod", "type": "cloudAccount"},
      "passthrough": {"audit": {"runId": "r1"}},
      "profiles": [{"name": "p", "version": "1.0.0", "supports": [], "controls": [], "groups": [], "attributes": [], "sha256": ""}]
    }`)
	res := ValidateLegacyV2(doc)
	if !res.Valid {
		t.Fatalf("top-level target/passthrough must validate; got: %v", res.Errors)
	}
}
