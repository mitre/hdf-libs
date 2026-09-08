package hdfdoc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-diff/go/v3/amend"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

func readVex(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("openvex fixture %s unavailable: %v", name, err)
	}
	return b
}

func TestAmendmentsFromVex_StampsSystemAndExpiry(t *testing.T) {
	exp := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	doc, err := AmendmentsFromVex(readVex(t, "multi-status.openvex.json"), exp, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Overrides) == 0 {
		t.Fatal("expected at least one derived override")
	}
	for _, o := range doc.Overrides {
		if o.AppliedBy.Type != hdf.IdentityTypeSystem {
			t.Fatalf("appliedBy.type must be system, got %s", o.AppliedBy.Type)
		}
		if !o.ExpiresAt.Equal(exp) {
			t.Fatalf("expiresAt must be the caller value, got %s", o.ExpiresAt)
		}
	}
}

func TestAmendmentsFromVex_NoActionableStatements(t *testing.T) {
	_, err := AmendmentsFromVex(readVex(t, "empty.openvex.json"), time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC), "test")
	if err == nil {
		t.Fatal("a VEX with no actionable statements must error, not emit an empty override set")
	}
}

func TestAmendmentsFromVex_Invalid(t *testing.T) {
	_, err := AmendmentsFromVex([]byte(`{"not":"vex"}`), time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC), "test")
	if err == nil {
		t.Fatal("a malformed VEX document must error")
	}
}

func TestAmendmentsFromVex_ValidatesAsAmendments(t *testing.T) {
	exp := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	doc, err := AmendmentsFromVex(readVex(t, "multi-status.openvex.json"), exp, "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if vr := validators.ValidateAmendments(b); !vr.Valid {
		t.Fatalf("derived amendments must validate: %s", vr.Error())
	}
}

// The VEX route is shared by `hdf amend create --from-vex` and the MCP
// hdf_author from_vex path, so chaining here covers both surfaces at once.
func TestAmendmentsFromVex_ChainsOverrides(t *testing.T) {
	exp := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	doc, err := AmendmentsFromVex(readVex(t, "multi-status.openvex.json"), exp, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Overrides) < 2 {
		t.Fatalf("fixture must have enough statements to form a chain, got %d", len(doc.Overrides))
	}

	if doc.Overrides[0].PreviousChecksum != nil {
		t.Fatal("the first override starts the chain and must not be linked")
	}
	for i := 1; i < len(doc.Overrides); i++ {
		prev := doc.Overrides[i].PreviousChecksum
		if prev == nil {
			t.Fatalf("override %d must be chained to the one before it", i)
		}
		if prev.Algorithm != hdf.Sha256 {
			t.Fatalf("override %d: chain algorithm must be sha256, got %s", i, prev.Algorithm)
		}
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	result, err := amend.VerifyAmendments(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Chain.Established {
		t.Fatal("a VEX-derived document must carry a chain")
	}
	if !result.Chain.Valid {
		t.Fatalf("the chain this route writes must verify: %v", result.Chain.Breaks)
	}

	// And it must actually catch an edit made after authoring.
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed["overrides"].([]interface{})[0].(map[string]interface{})["reason"] = "TAMPERED"
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	tamperedResult, err := amend.VerifyAmendments(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedResult.Chain.Valid {
		t.Fatal("an edit after authoring must break the chain")
	}
}
