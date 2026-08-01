package cci

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
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

// NativeRevision is the NIST 800-53 revision the DISA CCI list's NIST
// references were authored against (Rev 4-era list: it references Appendix J
// privacy controls and SA-12/SA-19, all withdrawn or relocated in Rev 5).
// GetCCINistMappings (and CCIToNIST atop it) translate to the process-global
// revision via the NIST crosswalk.
const NativeRevision = 4

// GetCCINistMappings returns the NIST control mappings for a CCI ID at the
// process-global NIST revision. Returns nil if the CCI ID is not found.
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
		return nist.AtRevision(item.Nist, NativeRevision, nist.Revision())
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

// NistCCIMappings is the curated NIST control → CCI mapping table.
type NistCCIMappings map[string][]string

//go:embed nist-cci-mappings.json
var nistCCIMappingsData []byte

var (
	nistCCIData     NistCCIMappings
	nistCCIDataOnce sync.Once
)

func loadNistCCIData() NistCCIMappings {
	nistCCIDataOnce.Do(func() {
		if err := json.Unmarshal(nistCCIMappingsData, &nistCCIData); err != nil {
			nistCCIData = make(NistCCIMappings)
		}
	})
	return nistCCIData
}

// GetNistCCIMappings returns the CCI IDs for a given NIST control using the curated
// mapping table sourced from heimdall2's NistCciMappingData. The input is normalized
// to its base control (e.g. "SI-10 a 1" → "SI-10") before lookup.
// Returns nil if the control is empty or not in the curated table.
//
// Example:
//
//	ids := GetNistCCIMappings("SI-10")
//	// Returns: []string{"CCI-001310"}
func GetNistCCIMappings(nistControl string) []string {
	if nistControl == "" {
		return nil
	}
	base := baseNistControl(nistControl)
	data := loadNistCCIData()
	if ccis, ok := data[base]; ok {
		return ccis
	}
	return nil
}

// baseNistControl extracts the base control identifier from a potentially qualified
// NIST control string (e.g. "SI-10 a 1" → "SI-10", "AC-3 (2)" → "AC-3").
func baseNistControl(control string) string {
	idx := strings.IndexAny(control, " (.")
	if idx == -1 {
		return control
	}
	return control[:idx]
}

// CCIToNIST maps a list of CCI IDs to their NIST 800-53 controls.
// Results are deduplicated and sorted. Returns an empty (non-nil) slice if no
// mappings are found.
//
// Example:
//
//	controls := CCIToNIST([]string{"CCI-000366", "CCI-000001"})
//	// Returns: []string{"AC-1 a", ..., "CM-6 b", ...}
func CCIToNIST(cciIDs []string) []string {
	seen := make(map[string]bool)
	for _, cciID := range cciIDs {
		for _, control := range GetCCINistMappings(cciID) {
			seen[control] = true
		}
	}
	result := make([]string, 0, len(seen))
	for control := range seen {
		result = append(result, control)
	}
	sort.Strings(result)
	return result
}

// NISTToCCI maps a list of NIST 800-53 controls to their CCI IDs using the
// curated mapping table. Results are deduplicated and sorted. Returns an empty
// (non-nil) slice if no mappings are found.
//
// Example:
//
//	ccis := NISTToCCI([]string{"AC-3", "SI-10"})
//	// Returns: []string{"CCI-000213", "CCI-001310"}
func NISTToCCI(nistControls []string) []string {
	seen := make(map[string]bool)
	for _, control := range nistControls {
		for _, cciID := range GetNistCCIMappings(control) {
			seen[cciID] = true
		}
	}
	result := make([]string, 0, len(seen))
	for cciID := range seen {
		result = append(result, cciID)
	}
	sort.Strings(result)
	return result
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
