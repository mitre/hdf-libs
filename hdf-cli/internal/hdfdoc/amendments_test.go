package hdfdoc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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
