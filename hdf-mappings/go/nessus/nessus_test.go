package nessus

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestNISTControls_WildcardFamily(t *testing.T) {
	controls := NISTControls("AIX Local Security Checks", "12345")
	if len(controls) != 2 || controls[0] != "SI-2" || controls[1] != "RA-5" {
		t.Errorf("expected [SI-2 RA-5] for AIX wildcard, got %v", controls)
	}
}

func TestNISTControls_ExactPluginID(t *testing.T) {
	// Firewalls plugin 56310 → SC-7
	controls := NISTControls("Firewalls", "56310")
	if len(controls) != 1 || controls[0] != "SC-7" {
		t.Errorf("expected [SC-7] for Firewalls/56310, got %v", controls)
	}
}

func TestNISTControls_ExactMultipleControls(t *testing.T) {
	// General plugin 70544 → AC-17(2)|SC-13
	controls := NISTControls("General", "70544")
	if len(controls) != 2 || controls[0] != "AC-17(2)" || controls[1] != "SC-13" {
		t.Errorf("expected [AC-17(2) SC-13] for General/70544, got %v", controls)
	}
}

func TestNISTControls_NoMatch(t *testing.T) {
	controls := NISTControls("Nonexistent Family", "999")
	if controls != nil {
		t.Errorf("expected nil for unknown family, got %v", controls)
	}
}

func TestNISTControls_EmptyFamily(t *testing.T) {
	controls := NISTControls("", "12345")
	if controls != nil {
		t.Errorf("expected nil for empty family, got %v", controls)
	}
}

func TestNISTControls_WildcardFallback(t *testing.T) {
	// Ubuntu has only a wildcard entry — any pluginID should match
	controls := NISTControls("Ubuntu Local Security Checks", "99999")
	if len(controls) != 2 || controls[0] != "SI-2" || controls[1] != "RA-5" {
		t.Errorf("expected [SI-2 RA-5] for Ubuntu wildcard fallback, got %v", controls)
	}
}

func TestNISTControl_SingleString(t *testing.T) {
	result := NISTControl("Firewalls", "56310")
	if result != "SC-7" {
		t.Errorf("expected SC-7, got %q", result)
	}
}

func TestNISTControl_MultipleString(t *testing.T) {
	result := NISTControl("General", "70544")
	if result != "AC-17(2)|SC-13" {
		t.Errorf("expected AC-17(2)|SC-13, got %q", result)
	}
}

func TestNISTControl_NoMatch(t *testing.T) {
	result := NISTControl("Nonexistent", "1")
	if result != "" {
		t.Errorf("expected empty string for no match, got %q", result)
	}
}

func TestExists_WildcardFamily(t *testing.T) {
	if !Exists("Red Hat Local Security Checks") {
		t.Error("expected Exists to be true for Red Hat")
	}
}

func TestExists_ExactFamily(t *testing.T) {
	if !Exists("Firewalls") {
		t.Error("expected Exists to be true for Firewalls")
	}
}

func TestExists_Unknown(t *testing.T) {
	if Exists("Unknown Family") {
		t.Error("expected Exists to be false for Unknown Family")
	}
}

func TestNISTControls_ServiceDetection(t *testing.T) {
	// Service detection plugin 10884 → AU-8(1)
	controls := NISTControls("Service detection", "10884")
	if len(controls) != 1 || controls[0] != "AU-8(1)" {
		t.Errorf("expected [AU-8(1)] for Service detection/10884, got %v", controls)
	}
}

func TestNISTControls_WebServers(t *testing.T) {
	// Web Servers plugin 85805 → SC-8|SC-13
	controls := NISTControls("Web Servers", "85805")
	if len(controls) != 2 || controls[0] != "SC-8" || controls[1] != "SC-13" {
		t.Errorf("expected [SC-8 SC-13] for Web Servers/85805, got %v", controls)
	}
}

func TestLoadData_InvalidJSON(t *testing.T) {
	origData := mappingsData
	origExact := exactMap
	origWild := wildcardMap
	defer func() {
		mappingsData = origData
		exactMap = origExact
		wildcardMap = origWild
		dataOnce = sync.Once{} //nolint:govet // resetting Once for test
	}()

	mappingsData = []byte("not valid json")
	exactMap = nil
	wildcardMap = nil
	dataOnce = sync.Once{} //nolint:govet // resetting Once for test

	loadData()
	if exactMap == nil {
		t.Error("expected non-nil exactMap after invalid JSON")
	}
	if wildcardMap == nil {
		t.Error("expected non-nil wildcardMap after invalid JSON")
	}
}

func TestNormalizePluginID_String(t *testing.T) {
	raw := json.RawMessage(`"*"`)
	result := normalizePluginID(raw)
	if result != "*" {
		t.Errorf("expected *, got %q", result)
	}
}

func TestNormalizePluginID_Number(t *testing.T) {
	raw := json.RawMessage(`56310`)
	result := normalizePluginID(raw)
	if result != "56310" {
		t.Errorf("expected 56310, got %q", result)
	}
}

func TestNormalizePluginID_Invalid(t *testing.T) {
	raw := json.RawMessage(`null`)
	result := normalizePluginID(raw)
	if result != "" {
		t.Errorf("expected empty string for null, got %q", result)
	}
}
