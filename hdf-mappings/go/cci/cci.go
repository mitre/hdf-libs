package cci

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// CCIItem represents a CCI (Control Correlation Identifier) with its definition and NIST mappings
type CCIItem struct {
	// Definition/description of the CCI
	Def string `json:"def"`
	// Array of NIST control references this CCI maps to
	Nist []string `json:"nist"`
}

// CCIMappings represents the complete CCI to NIST mapping database
type CCIMappings map[string]CCIItem

//go:embed cci-mappings.json
var cciMappingsData []byte

var (
	cciData     CCIMappings
	cciDataOnce sync.Once
)

// loadCCIData lazily loads and parses the CCI mappings data
func loadCCIData() CCIMappings {
	cciDataOnce.Do(func() {
		if err := json.Unmarshal(cciMappingsData, &cciData); err != nil {
			// This should never happen with embedded data, but handle gracefully
			cciData = make(CCIMappings)
		}
	})
	return cciData
}

// GetCCIDescription returns the definition/description for a CCI ID.
// Returns empty string if the CCI ID is not found.
//
// Example:
//
//	def := GetCCIDescription("CCI-000001")
//	// Returns: "The organization develops an access control policy..."
func GetCCIDescription(cciID string) string {
	if cciID == "" {
		return ""
	}

	data := loadCCIData()
	if item, exists := data[cciID]; exists {
		return item.Def
	}
	return ""
}

// GetCCINistMappings returns the NIST control mappings for a CCI ID.
// Returns nil if the CCI ID is not found.
//
// Example:
//
//	mappings := GetCCINistMappings("CCI-000001")
//	// Returns: []string{"AC-1 a", "AC-1.1 (i and ii)", "AC-1 a 1"}
func GetCCINistMappings(cciID string) []string {
	if cciID == "" {
		return nil
	}

	data := loadCCIData()
	if item, exists := data[cciID]; exists {
		return item.Nist
	}
	return nil
}

// GetAllCCIIDs returns all CCI IDs available in the database.
//
// Example:
//
//	ids := GetAllCCIIDs()
//	// Returns: []string{"CCI-000001", "CCI-000002", ...}
func GetAllCCIIDs() []string {
	data := loadCCIData()
	ids := make([]string, 0, len(data))
	for id := range data {
		ids = append(ids, id)
	}
	return ids
}

// CCIExists checks if a CCI ID exists in the database.
//
// Example:
//
//	if CCIExists("CCI-000001") {
//	    fmt.Println("CCI found")
//	}
func CCIExists(cciID string) bool {
	if cciID == "" {
		return false
	}

	data := loadCCIData()
	_, exists := data[cciID]
	return exists
}
