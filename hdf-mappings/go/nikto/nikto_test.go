package nikto

import (
	"strings"
	"sync"
	"testing"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

func TestNISTControl_KnownID(t *testing.T) {
	// 600050 → SI-2 (Apache outdated)
	control := NISTControl("600050")
	if control != "SI-2" {
		t.Errorf("expected SI-2 for Nikto ID 600050, got %q", control)
	}
}

func TestNISTControl_KnownID_SI10(t *testing.T) {
	// 800132 → SI-10
	control := NISTControl("800132")
	if control != "SI-10" {
		t.Errorf("expected SI-10 for Nikto ID 800132, got %q", control)
	}
}

func TestNISTControl_UnknownID(t *testing.T) {
	control := NISTControl("999957")
	if control != "" {
		t.Errorf("expected empty string for unmapped Nikto ID 999957, got %q", control)
	}
}

func TestNISTControl_EmptyString(t *testing.T) {
	control := NISTControl("")
	if control != "" {
		t.Errorf("expected empty string for empty input, got %q", control)
	}
}

func TestNISTControlByInt(t *testing.T) {
	control := NISTControlByInt(600050)
	if control != "SI-2" {
		t.Errorf("expected SI-2 for Nikto ID 600050 (int), got %q", control)
	}
}

func TestNISTControlByInt_Unknown(t *testing.T) {
	control := NISTControlByInt(9999999)
	if control != "" {
		t.Errorf("expected empty string for unknown int ID 9999999, got %q", control)
	}
}

func TestExists_True(t *testing.T) {
	if !Exists("600050") {
		t.Error("expected Exists(600050) to be true")
	}
}

func TestExists_False(t *testing.T) {
	if Exists("999957") {
		t.Error("expected Exists(999957) to be false")
	}
}

func TestLoadData_InvalidJSON(t *testing.T) {
	origData := mappingsData
	origMap := niktoData
	defer func() {
		mappingsData = origData
		niktoData = origMap
		niktoDataOnce = sync.Once{} //nolint:govet // resetting Once for test
	}()

	mappingsData = []byte("not valid json")
	niktoData = nil
	niktoDataOnce = sync.Once{} //nolint:govet // resetting Once for test

	result := loadData()
	if result == nil {
		t.Error("expected non-nil empty map on JSON error, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected empty map on JSON error, got %d entries", len(result))
	}
}

func TestNISTControl_SI11(t *testing.T) {
	// 750500 → SI-11 (first entry in the mappings file)
	control := NISTControl("750500")
	if control != "SI-11" {
		t.Errorf("expected SI-11 for Nikto ID 750500, got %q", control)
	}
}

// The nikto table is treated as revision-neutral: NISTControl performs no
// useful translation only because every control it carries is identical at
// Rev 4 and Rev 5. If this guard fails, a newly added control diverges across
// revisions and the mapping's revision handling must be revisited.
func TestTableIsRevisionNeutral(t *testing.T) {
	for id, control := range loadData() {
		for _, c := range strings.Split(control, "|") {
			tr := nist.Translate(strings.TrimSpace(c), 4, 5)
			if tr.Relation != nist.RelationIdentity {
				t.Errorf("nikto %s: control %q is not revision-neutral (relation %s)", id, c, tr.Relation)
			}
		}
	}
}
