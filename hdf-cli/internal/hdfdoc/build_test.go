package hdfdoc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

func gen() *hdf.Generator {
	return &hdf.Generator{Name: "hdf-mcp", Version: "3.5.0"}
}

func decodeArray(t *testing.T, s string) []map[string]any {
	t.Helper()
	var a []map[string]any
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return a
}

func TestBuildSystem_ValidMinimal(t *testing.T) {
	out, err := BuildSystem("Portal", decodeArray(t, `[{"type":"host","name":"web-1"}]`), gen())
	if err != nil {
		t.Fatal(err)
	}
	if vr := validators.Validate(out, validators.TypeSystem); !vr.Valid {
		t.Fatalf("built system must validate: %s", vr.Error())
	}
}

func TestBuildPlan_ValidMinimal(t *testing.T) {
	out, err := BuildPlan("Q1 Plan", decodeArray(t, `[{"baselineRef":"RHEL9-STIG"}]`), gen())
	if err != nil {
		t.Fatal(err)
	}
	if vr := validators.Validate(out, validators.TypePlan); !vr.Valid {
		t.Fatalf("built plan must validate: %s", vr.Error())
	}
}

func TestBuildEvidencePackage_ValidMinimal(t *testing.T) {
	out, err := BuildEvidencePackage("Portal Q1 Evidence",
		decodeArray(t, `[{"type":"hdf-results","uri":"rhel9.json","checksum":{"algorithm":"sha256","value":"abcd"}}]`), gen())
	if err != nil {
		t.Fatal(err)
	}
	if vr := validators.Validate(out, validators.TypeEvidencePackage); !vr.Valid {
		t.Fatalf("built evidence package must validate: %s", vr.Error())
	}
}

// TestBuild_PreservesContentFieldsExactly is the data-preservation guarantee: a
// field-rich content array survives the build with every field intact (no drop,
// no re-typing), since the builder copies the content verbatim.
func TestBuild_PreservesContentFieldsExactly(t *testing.T) {
	in := decodeArray(t, `[
		{"type":"host","name":"web-1","componentId":"11111111-1111-1111-1111-111111111111",
		 "labels":{"env":"prod","tier":"web"},"description":"front-end host",
		 "boms":[{"bomType":"cyclonedx","boms":[]}]}
	]`)
	out, err := BuildSystem("Portal", in, gen())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(doc["components"])
	want, _ := json.Marshal(in)
	if !reflect.DeepEqual(json.RawMessage(got), json.RawMessage(want)) {
		// Compare as normalized values (field-for-field), not raw bytes.
		var gv, wv any
		_ = json.Unmarshal(got, &gv)
		_ = json.Unmarshal(want, &wv)
		if !reflect.DeepEqual(gv, wv) {
			t.Fatalf("content not preserved:\n got=%s\nwant=%s", got, want)
		}
	}
}

func TestBuildAmendments_ValidMinimal(t *testing.T) {
	out, err := BuildAmendments("Risk decisions", decodeArray(t, `[
		{"type":"riskAdjustment","requirementId":"V-1","reason":"compensating control",
		 "status":"notApplicable","appliedBy":{"identifier":"hdf-mcp","type":"agent"},
		 "appliedAt":"2026-01-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z"}
	]`), gen())
	if err != nil {
		t.Fatal(err)
	}
	if vr := validators.Validate(out, validators.TypeAmendments); !vr.Valid {
		t.Fatalf("built amendments must validate: %s", vr.Error())
	}
}

func TestBuild_NilGeneratorOmitted(t *testing.T) {
	out, err := BuildSystem("S", decodeArray(t, `[{"type":"host","name":"h1"}]`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "\"generator\"") {
		t.Fatalf("nil generator should be omitted: %s", out)
	}
	if vr := validators.Validate(out, validators.TypeSystem); !vr.Valid {
		t.Fatalf("must still validate: %s", vr.Error())
	}
}
