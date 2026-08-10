package scoutsuite

import (
	"strings"
	"sync"
	"testing"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

func TestNISTControl_KnownRule(t *testing.T) {
	control := NISTControl("cloudtrail-not-configured")
	if control != "AU-12" {
		t.Errorf("expected AU-12 for cloudtrail-not-configured, got %q", control)
	}
}

func TestNISTControl_PipeDelimited(t *testing.T) {
	control := NISTControl("cloudtrail-no-cloudwatch-integration")
	if control != "AU-12|SI-4(2)" {
		t.Errorf("expected AU-12|SI-4(2) for cloudtrail-no-cloudwatch-integration, got %q", control)
	}
}

func TestNISTControl_UnknownRule(t *testing.T) {
	control := NISTControl("nonexistent-rule")
	if control != "" {
		t.Errorf("expected empty string for unmapped rule, got %q", control)
	}
}

func TestNISTControl_EmptyString(t *testing.T) {
	control := NISTControl("")
	if control != "" {
		t.Errorf("expected empty string for empty input, got %q", control)
	}
}

func TestNISTControls_Single(t *testing.T) {
	controls := NISTControls("cloudtrail-not-configured")
	if len(controls) != 1 || controls[0] != "AU-12" {
		t.Errorf("expected [AU-12], got %v", controls)
	}
}

func TestNISTControls_Multiple(t *testing.T) {
	controls := NISTControls("cloudtrail-no-cloudwatch-integration")
	if len(controls) != 2 || controls[0] != "AU-12" || controls[1] != "SI-4(2)" {
		t.Errorf("expected [AU-12 SI-4(2)], got %v", controls)
	}
}

func TestNISTControls_Unknown(t *testing.T) {
	controls := NISTControls("nonexistent-rule")
	if controls != nil {
		t.Errorf("expected nil for unmapped rule, got %v", controls)
	}
}

func TestExists_True(t *testing.T) {
	if !Exists("cloudtrail-not-configured") {
		t.Error("expected Exists(cloudtrail-not-configured) to be true")
	}
}

func TestExists_False(t *testing.T) {
	if Exists("nonexistent-rule") {
		t.Error("expected Exists(nonexistent-rule) to be false")
	}
}

func TestLoadData_InvalidJSON(t *testing.T) {
	origData := mappingsData
	origMap := scoutsuiteData
	defer func() {
		mappingsData = origData
		scoutsuiteData = origMap
		scoutsuiteDataOnce = sync.Once{} //nolint:govet // resetting Once for test
	}()

	mappingsData = []byte("not valid json")
	scoutsuiteData = nil
	scoutsuiteDataOnce = sync.Once{} //nolint:govet // resetting Once for test

	result := loadData()
	if result == nil {
		t.Error("expected non-nil empty map on JSON error, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected empty map on JSON error, got %d entries", len(result))
	}
}

// See the nikto equivalent: this guard fails when a control in the table stops
// being identical across revisions, signalling the mapping needs real handling.
func TestTableIsRevisionNeutral(t *testing.T) {
	for rule, control := range loadData() {
		for _, c := range strings.Split(control, "|") {
			tr := nist.Translate(strings.TrimSpace(c), 4, 5)
			if tr.Relation != nist.RelationIdentity {
				t.Errorf("scoutsuite %s: control %q is not revision-neutral (relation %s)", rule, c, tr.Relation)
			}
		}
	}
}
