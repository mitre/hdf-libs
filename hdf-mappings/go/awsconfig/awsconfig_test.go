package awsconfig

import (
	"sync"
	"testing"
)

// TestGetByRuleName tests the GetByRuleName function.
func TestGetByRuleName(t *testing.T) {
	t.Run("known rule name returns non-nil mapping with expected fields", func(t *testing.T) {
		m := GetByRuleName("iam-password-policy")
		if m == nil {
			t.Fatal("Expected non-nil mapping for 'iam-password-policy'")
		}
		if m.AwsConfigRuleName != "iam-password-policy" {
			t.Errorf("Expected AwsConfigRuleName='iam-password-policy', got '%s'", m.AwsConfigRuleName)
		}
		if m.AwsConfigRuleSourceIdentifier != "IAM_PASSWORD_POLICY" {
			t.Errorf("Expected AwsConfigRuleSourceIdentifier='IAM_PASSWORD_POLICY', got '%s'", m.AwsConfigRuleSourceIdentifier)
		}
		if m.NISTID == "" {
			t.Error("Expected non-empty NIST-ID for 'iam-password-policy'")
		}
		if m.Rev != 4 {
			t.Errorf("Expected Rev=4, got %d", m.Rev)
		}
	})

	t.Run("another known rule name returns non-nil mapping", func(t *testing.T) {
		m := GetByRuleName("access-keys-rotated")
		if m == nil {
			t.Fatal("Expected non-nil mapping for 'access-keys-rotated'")
		}
		if m.AwsConfigRuleSourceIdentifier != "ACCESS_KEYS_ROTATED" {
			t.Errorf("Expected AwsConfigRuleSourceIdentifier='ACCESS_KEYS_ROTATED', got '%s'", m.AwsConfigRuleSourceIdentifier)
		}
	})

	t.Run("unknown rule name returns nil", func(t *testing.T) {
		m := GetByRuleName("this-rule-does-not-exist")
		if m != nil {
			t.Errorf("Expected nil for unknown rule, got %+v", m)
		}
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		m := GetByRuleName("")
		if m != nil {
			t.Errorf("Expected nil for empty string, got %+v", m)
		}
	})
}

// TestGetByIdentifier tests the GetByIdentifier function.
func TestGetByIdentifier(t *testing.T) {
	t.Run("known uppercase identifier returns non-nil mapping", func(t *testing.T) {
		m := GetByIdentifier("IAM_PASSWORD_POLICY")
		if m == nil {
			t.Fatal("Expected non-nil mapping for 'IAM_PASSWORD_POLICY'")
		}
		if m.AwsConfigRuleSourceIdentifier != "IAM_PASSWORD_POLICY" {
			t.Errorf("Expected AwsConfigRuleSourceIdentifier='IAM_PASSWORD_POLICY', got '%s'", m.AwsConfigRuleSourceIdentifier)
		}
		if m.AwsConfigRuleName != "iam-password-policy" {
			t.Errorf("Expected AwsConfigRuleName='iam-password-policy', got '%s'", m.AwsConfigRuleName)
		}
	})

	t.Run("another known identifier returns non-nil mapping", func(t *testing.T) {
		m := GetByIdentifier("SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK")
		if m == nil {
			t.Fatal("Expected non-nil mapping for 'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK'")
		}
		if m.AwsConfigRuleName != "secretsmanager-scheduled-rotation-success-check" {
			t.Errorf("Unexpected rule name: %s", m.AwsConfigRuleName)
		}
	})

	t.Run("unknown identifier returns nil", func(t *testing.T) {
		m := GetByIdentifier("UNKNOWN_IDENTIFIER_XYZ")
		if m != nil {
			t.Errorf("Expected nil for unknown identifier, got %+v", m)
		}
	})

	t.Run("lowercase identifier returns nil (keys are UPPERCASE)", func(t *testing.T) {
		m := GetByIdentifier("iam_password_policy")
		if m != nil {
			t.Errorf("Expected nil for lowercase identifier, got %+v", m)
		}
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		m := GetByIdentifier("")
		if m != nil {
			t.Errorf("Expected nil for empty string, got %+v", m)
		}
	})
}

// TestNISTControls tests the NISTControls function.
func TestNISTControls(t *testing.T) {
	t.Run("known rule returns non-empty slice", func(t *testing.T) {
		controls := NISTControls("access-keys-rotated")
		if len(controls) == 0 {
			t.Fatal("Expected non-empty controls for 'access-keys-rotated'")
		}
	})

	t.Run("known rule with two pipe-separated controls returns correct slice", func(t *testing.T) {
		// secretsmanager-scheduled-rotation-success-check has "AC-2(1)|AC-2(j)"
		controls := NISTControls("secretsmanager-scheduled-rotation-success-check")
		if len(controls) != 2 {
			t.Fatalf("Expected 2 controls, got %d: %v", len(controls), controls)
		}
		if controls[0] != "AC-2(1)" {
			t.Errorf("Expected controls[0]='AC-2(1)', got '%s'", controls[0])
		}
		if controls[1] != "AC-2(j)" {
			t.Errorf("Expected controls[1]='AC-2(j)', got '%s'", controls[1])
		}
	})

	t.Run("known rule with many pipe-separated controls returns all entries", func(t *testing.T) {
		// iam-password-policy has 6 pipe-separated controls
		controls := NISTControls("iam-password-policy")
		if len(controls) < 2 {
			t.Fatalf("Expected multiple controls for 'iam-password-policy', got %d: %v", len(controls), controls)
		}
		// Verify a subset of the expected controls
		wantFirst := "AC-2(1)"
		if controls[0] != wantFirst {
			t.Errorf("Expected controls[0]='%s', got '%s'", wantFirst, controls[0])
		}
	})

	t.Run("known rule with four controls splits correctly", func(t *testing.T) {
		// iam-user-group-membership-check has "AC-2(1)|AC-2(j)|AC-3|AC-6"
		controls := NISTControls("iam-user-group-membership-check")
		if len(controls) != 4 {
			t.Fatalf("Expected 4 controls, got %d: %v", len(controls), controls)
		}
		expected := []string{"AC-2(1)", "AC-2(j)", "AC-3", "AC-6"}
		for i, want := range expected {
			if controls[i] != want {
				t.Errorf("controls[%d]: expected '%s', got '%s'", i, want, controls[i])
			}
		}
	})

	t.Run("unknown rule returns nil", func(t *testing.T) {
		controls := NISTControls("no-such-rule")
		if controls != nil {
			t.Errorf("Expected nil for unknown rule, got %v", controls)
		}
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		controls := NISTControls("")
		if controls != nil {
			t.Errorf("Expected nil for empty string, got %v", controls)
		}
	})
}

// TestLazyLoading verifies that calling GetByRuleName after resetting state
// causes load() to repopulate the maps.
func TestLazyLoading(t *testing.T) {
	// Save original state.
	origByRuleName := byRuleName
	origByIdentifier := byIdentifier
	origLoadOnce := loadOnce

	defer func() {
		byRuleName = origByRuleName
		byIdentifier = origByIdentifier
		loadOnce = origLoadOnce
	}()

	// Reset to unloaded state.
	byRuleName = nil
	byIdentifier = nil
	loadOnce = sync.Once{}

	// A call to GetByRuleName must trigger load and return a valid result.
	m := GetByRuleName("cloudtrail-enabled")
	if m == nil {
		t.Fatal("Expected non-nil mapping after lazy load for 'cloudtrail-enabled'")
	}
	if byRuleName == nil {
		t.Error("Expected byRuleName to be populated after lazy load")
	}
	if byIdentifier == nil {
		t.Error("Expected byIdentifier to be populated after lazy load")
	}
	if len(byRuleName) == 0 {
		t.Error("Expected byRuleName to have entries after lazy load")
	}
}

// TestLoadWithCorruptJSON exercises the JSON unmarshal error path in load().
// When mappingsData contains invalid JSON, load() must set empty maps rather
// than panic, and all public functions must return nil/nil gracefully.
func TestLoadWithCorruptJSON(t *testing.T) {
	// Save original state.
	origByRuleName := byRuleName
	origByIdentifier := byIdentifier
	origLoadOnce := loadOnce
	origMappingsData := mappingsData

	defer func() {
		byRuleName = origByRuleName
		byIdentifier = origByIdentifier
		loadOnce = origLoadOnce
		mappingsData = origMappingsData
	}()

	// Reset to unloaded state and inject invalid JSON.
	byRuleName = nil
	byIdentifier = nil
	loadOnce = sync.Once{}
	mappingsData = []byte("NOT VALID JSON {{{")

	// GetByRuleName must not panic and must return nil.
	m := GetByRuleName("iam-password-policy")
	if m != nil {
		t.Errorf("Expected nil from GetByRuleName with corrupt JSON, got %+v", m)
	}

	// Maps must be initialised (not nil) — load() creates them even on error.
	if byRuleName == nil {
		t.Error("Expected byRuleName to be non-nil (empty map) after unmarshal error")
	}
	if byIdentifier == nil {
		t.Error("Expected byIdentifier to be non-nil (empty map) after unmarshal error")
	}

	// GetByIdentifier must also not panic and return nil.
	id := GetByIdentifier("IAM_PASSWORD_POLICY")
	if id != nil {
		t.Errorf("Expected nil from GetByIdentifier with corrupt JSON, got %+v", id)
	}

	// NISTControls must also not panic and return nil.
	controls := NISTControls("iam-password-policy")
	if controls != nil {
		t.Errorf("Expected nil from NISTControls with corrupt JSON, got %v", controls)
	}
}
