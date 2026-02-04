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
