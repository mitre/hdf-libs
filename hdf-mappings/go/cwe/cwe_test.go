package cwe

import (
	"sync"
	"testing"
)

func TestNISTControls_KnownCWE_PrefixForm(t *testing.T) {
	controls := NISTControls("CWE-476")
	if len(controls) == 0 {
		t.Fatal("expected NIST controls for CWE-476, got none")
	}
	// CWE-476 (NULL Pointer Dereference) → SI-10
	found := false
	for _, c := range controls {
		if c == "SI-10" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SI-10 in controls for CWE-476, got %v", controls)
	}
}

func TestNISTControls_KnownCWE_NumericForm(t *testing.T) {
	controls := NISTControls("476")
	if len(controls) == 0 {
		t.Fatal("expected NIST controls for 476, got none")
	}
	found := false
	for _, c := range controls {
		if c == "SI-10" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SI-10 in controls for 476, got %v", controls)
	}
}

func TestNISTControls_BothFormsEquivalent(t *testing.T) {
	withPrefix := NISTControls("CWE-5")
	withoutPrefix := NISTControls("5")
	if len(withPrefix) != len(withoutPrefix) {
		t.Errorf("expected same results for CWE-5 and 5, got %v vs %v", withPrefix, withoutPrefix)
	}
	for i := range withPrefix {
		if withPrefix[i] != withoutPrefix[i] {
			t.Errorf("mismatch at index %d: %s vs %s", i, withPrefix[i], withoutPrefix[i])
		}
	}
}

func TestNISTControls_UnknownCWE(t *testing.T) {
	controls := NISTControls("CWE-999999")
	if controls != nil {
		t.Errorf("expected nil for unknown CWE, got %v", controls)
	}
}

func TestNISTControls_EmptyString(t *testing.T) {
	controls := NISTControls("")
	if controls != nil {
		t.Errorf("expected nil for empty string, got %v", controls)
	}
}

func TestNISTControls_InvalidFormat(t *testing.T) {
	controls := NISTControls("not-a-cwe")
	if controls != nil {
		t.Errorf("expected nil for non-numeric CWE, got %v", controls)
	}
}

func TestNISTControls_CWE79(t *testing.T) {
	// CWE-79 (Cross-site Scripting) → SI-10
	controls := NISTControls("CWE-79")
	if len(controls) == 0 {
		t.Fatal("expected NIST controls for CWE-79, got none")
	}
}

func TestNISTControls_CasePrefixHandling(t *testing.T) {
	// Should handle lowercase "cwe-" prefix too
	controls := NISTControls("cwe-476")
	if len(controls) == 0 {
		t.Fatal("expected NIST controls for cwe-476 (lowercase), got none")
	}
}

func TestLoadCWEData_InvalidJSON(t *testing.T) {
	// Exercise the json.Unmarshal error path in loadCWEData.
	// sync.Once is not copy-safe; reset in defer rather than save/restore
	// (loadCWEData is idempotent).
	origData := cweMappingsData
	origMap := cweData
	defer func() {
		cweMappingsData = origData
		cweData = origMap
		cweDataOnce = sync.Once{}
	}()

	cweMappingsData = []byte("not valid json")
	cweData = nil
	cweDataOnce = sync.Once{}

	result := loadCWEData()
	if result == nil {
		t.Error("expected non-nil empty map on JSON error, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected empty map on JSON error, got %d entries", len(result))
	}
}
