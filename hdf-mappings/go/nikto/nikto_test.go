package nikto

import (
	"sync"
	"testing"
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
