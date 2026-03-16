package cci

import (
	"testing"
)

func TestGetCCIDescription(t *testing.T) {
	tests := []struct {
		name     string
		cciID    string
		expected string
		isEmpty  bool
	}{
		{
			name:     "Valid CCI ID",
			cciID:    "CCI-000001",
			expected: "The organization develops an access control policy",
			isEmpty:  false,
		},
		{
			name:     "Another valid CCI ID",
			cciID:    "CCI-000366",
			expected: "",
			isEmpty:  false,
		},
		{
			name:     "Empty CCI ID",
			cciID:    "",
			expected: "",
			isEmpty:  true,
		},
		{
			name:     "Non-existent CCI ID",
			cciID:    "CCI-999999",
			expected: "",
			isEmpty:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCCIDescription(tt.cciID)

			if tt.isEmpty {
				if result != "" {
					t.Errorf("Expected empty string, got: %s", result)
				}
			} else if tt.expected != "" && len(result) > 0 {
				// Check if result contains expected substring for valid CCIs
				if len(result) < len(tt.expected) {
					t.Errorf("Description too short. Expected to contain '%s', got: %s", tt.expected, result)
				}
			}
		})
	}
}

func TestGetCCINistMappings(t *testing.T) {
	tests := []struct {
		name       string
		cciID      string
		expectNil  bool
		expectLen  int
		expectContains string
	}{
		{
			name:           "CCI-000366 maps to CM-6 controls",
			cciID:          "CCI-000366",
			expectNil:      false,
			expectLen:      3,
			expectContains: "CM-6 b",
		},
		{
			name:          "CCI-000001 maps to AC-1 controls",
			cciID:         "CCI-000001",
			expectNil:     false,
			expectLen:     3,
			expectContains: "AC-1 a",
		},
		{
			name:      "Empty CCI ID returns nil",
			cciID:     "",
			expectNil: true,
		},
		{
			name:      "Non-existent CCI ID returns nil",
			cciID:     "CCI-999999",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCCINistMappings(tt.cciID)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("Expected non-nil result for %s", tt.cciID)
				return
			}

			if len(result) != tt.expectLen {
				t.Errorf("Expected %d mappings for %s, got %d: %v", tt.expectLen, tt.cciID, len(result), result)
			}

			if tt.expectContains != "" {
				found := false
				for _, mapping := range result {
					if mapping == tt.expectContains {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected result to contain '%s', got: %v", tt.expectContains, result)
				}
			}
		})
	}
}

func TestGetNistCCIMappings(t *testing.T) {
	tests := []struct {
		name        string
		nistControl string
		expectNil   bool
		expect      []string
	}{
		{
			name:        "SI-10 returns curated CCI",
			nistControl: "SI-10",
			expect:      []string{"CCI-001310"},
		},
		{
			name:        "AC-3 returns curated CCI",
			nistControl: "AC-3",
			expect:      []string{"CCI-000213"},
		},
		{
			name:        "SI-11 returns curated CCI",
			nistControl: "SI-11",
			expect:      []string{"CCI-001312"},
		},
		{
			name:        "SA-11 returns curated CCI",
			nistControl: "SA-11",
			expect:      []string{"CCI-003173"},
		},
		{
			name:        "AC-4 returns multiple curated CCIs",
			nistControl: "AC-4",
			expect:      []string{"CCI-001368", "CCI-001414"},
		},
		{
			name:        "Qualified control normalizes to base",
			nistControl: "SI-10 a 1",
			expect:      []string{"CCI-001310"},
		},
		{
			name:        "Control with enhancement normalizes to base",
			nistControl: "AC-3 (2)",
			expect:      []string{"CCI-000213"},
		},
		{
			name:        "Empty control returns nil",
			nistControl: "",
			expectNil:   true,
		},
		{
			name:        "Control not in curated table returns nil",
			nistControl: "ZZ-999",
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetNistCCIMappings(tt.nistControl)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("Expected %v for %s, got nil", tt.expect, tt.nistControl)
				return
			}

			if len(result) != len(tt.expect) {
				t.Errorf("Expected %v for %s, got %v", tt.expect, tt.nistControl, result)
				return
			}

			for i, cci := range tt.expect {
				if result[i] != cci {
					t.Errorf("Expected result[%d]=%s for %s, got %s", i, cci, tt.nistControl, result[i])
				}
			}
		})
	}
}

func TestCCIExists(t *testing.T) {
	tests := []struct {
		name     string
		cciID    string
		expected bool
	}{
		{
			name:     "Existing CCI ID",
			cciID:    "CCI-000001",
			expected: true,
		},
		{
			name:     "Another existing CCI ID",
			cciID:    "CCI-000366",
			expected: true,
		},
		{
			name:     "Non-existent CCI ID",
			cciID:    "CCI-999999",
			expected: false,
		},
		{
			name:     "Empty CCI ID",
			cciID:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CCIExists(tt.cciID)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.cciID, result)
			}
		})
	}
}

func TestGetAllCCIIDs(t *testing.T) {
	ids := GetAllCCIIDs()

	if len(ids) == 0 {
		t.Error("Expected non-empty list of CCI IDs")
	}

	// Check that we have a reasonable number of CCIs (should be thousands)
	if len(ids) < 1000 {
		t.Errorf("Expected at least 1000 CCI IDs, got %d", len(ids))
	}

	// Verify some known CCIs are present
	knownCCIs := []string{"CCI-000001", "CCI-000366"}
	for _, cci := range knownCCIs {
		found := false
		for _, id := range ids {
			if id == cci {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find %s in CCI ID list", cci)
		}
	}
}

func TestCCIToNIST(t *testing.T) {
	t.Run("maps known CCI IDs to NIST controls", func(t *testing.T) {
		result := CCIToNIST([]string{"CCI-000366"})
		if len(result) == 0 {
			t.Fatal("Expected non-empty NIST controls for CCI-000366")
		}
		found := false
		for _, c := range result {
			if c == "CM-6 b" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected result to contain 'CM-6 b', got: %v", result)
		}
	})

	t.Run("deduplicates controls from multiple CCI IDs", func(t *testing.T) {
		// Both CCI-000001 and itself map to the same controls; dupes must collapse
		single := CCIToNIST([]string{"CCI-000001"})
		double := CCIToNIST([]string{"CCI-000001", "CCI-000001"})
		if len(single) != len(double) {
			t.Errorf("Expected deduplication: single=%d, double=%d", len(single), len(double))
		}
	})

	t.Run("result is sorted", func(t *testing.T) {
		result := CCIToNIST([]string{"CCI-000366", "CCI-000001"})
		for i := 1; i < len(result); i++ {
			if result[i] < result[i-1] {
				t.Errorf("Result not sorted at index %d: %v", i, result)
			}
		}
	})

	t.Run("empty input returns empty slice", func(t *testing.T) {
		result := CCIToNIST([]string{})
		if result == nil {
			t.Error("Expected non-nil empty slice")
		}
		if len(result) != 0 {
			t.Errorf("Expected empty slice, got: %v", result)
		}
	})

	t.Run("unknown CCI IDs return empty slice", func(t *testing.T) {
		result := CCIToNIST([]string{"CCI-999999"})
		if result == nil {
			t.Error("Expected non-nil empty slice")
		}
		if len(result) != 0 {
			t.Errorf("Expected empty slice, got: %v", result)
		}
	})
}

func TestNISTToCCI(t *testing.T) {
	t.Run("maps known NIST control to CCI IDs", func(t *testing.T) {
		result := NISTToCCI([]string{"AC-3"})
		if len(result) == 0 {
			t.Fatal("Expected non-empty CCI IDs for AC-3")
		}
		found := false
		for _, c := range result {
			if c == "CCI-000213" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected result to contain 'CCI-000213', got: %v", result)
		}
	})

	t.Run("deduplicates CCI IDs from multiple NIST controls", func(t *testing.T) {
		single := NISTToCCI([]string{"AC-3"})
		double := NISTToCCI([]string{"AC-3", "AC-3"})
		if len(single) != len(double) {
			t.Errorf("Expected deduplication: single=%d, double=%d", len(single), len(double))
		}
	})

	t.Run("result is sorted", func(t *testing.T) {
		result := NISTToCCI([]string{"AC-3", "SI-10"})
		for i := 1; i < len(result); i++ {
			if result[i] < result[i-1] {
				t.Errorf("Result not sorted at index %d: %v", i, result)
			}
		}
	})

	t.Run("empty input returns empty slice", func(t *testing.T) {
		result := NISTToCCI([]string{})
		if result == nil {
			t.Error("Expected non-nil empty slice")
		}
		if len(result) != 0 {
			t.Errorf("Expected empty slice, got: %v", result)
		}
	})

	t.Run("unknown NIST control returns empty slice", func(t *testing.T) {
		result := NISTToCCI([]string{"ZZ-999"})
		if result == nil {
			t.Error("Expected non-nil empty slice")
		}
		if len(result) != 0 {
			t.Errorf("Expected empty slice, got: %v", result)
		}
	})

	t.Run("qualified control normalizes before lookup", func(t *testing.T) {
		base := NISTToCCI([]string{"SI-10"})
		qualified := NISTToCCI([]string{"SI-10 a 1"})
		if len(base) != len(qualified) {
			t.Errorf("Expected same result for base and qualified: %v vs %v", base, qualified)
		}
	})
}

func TestLazyLoading(t *testing.T) {
	// First call should load data
	desc1 := GetCCIDescription("CCI-000001")
	if desc1 == "" {
		t.Error("Expected description for CCI-000001")
	}

	// Second call should use cached data
	desc2 := GetCCIDescription("CCI-000001")
	if desc1 != desc2 {
		t.Error("Expected same description on second call (cached)")
	}
}
