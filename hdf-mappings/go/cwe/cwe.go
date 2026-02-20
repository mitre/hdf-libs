// Package cwe provides lookup functions for CWE to NIST 800-53 control mappings.
package cwe

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

// cweMapping represents one row in the CWE→NIST mapping table.
type cweMapping struct {
	CWEID   int    `json:"CWE-ID"`
	NISTID  string `json:"NIST-ID"`
}

//go:embed cwe-nist-mappings.json
var cweMappingsData []byte

var (
	cweData     map[int][]string // CWE numeric ID → NIST controls
	cweDataOnce sync.Once
)

func loadCWEData() map[int][]string {
	cweDataOnce.Do(func() {
		var list []cweMapping
		if err := json.Unmarshal(cweMappingsData, &list); err != nil {
			cweData = make(map[int][]string)
			return
		}
		cweData = make(map[int][]string, len(list))
		for _, m := range list {
			if m.NISTID != "" {
				cweData[m.CWEID] = append(cweData[m.CWEID], m.NISTID)
			}
		}
	})
	return cweData
}

// NISTControls returns NIST 800-53 controls for a CWE ID.
// Accepts "CWE-476" or "476" — both forms are handled.
// Returns nil if the CWE ID is unknown or the input is empty.
func NISTControls(cweID string) []string {
	if cweID == "" {
		return nil
	}

	// Normalize: strip "CWE-" prefix if present
	normalized := cweID
	if strings.HasPrefix(strings.ToUpper(normalized), "CWE-") {
		normalized = normalized[4:]
	}

	id, err := strconv.Atoi(normalized)
	if err != nil {
		return nil
	}

	data := loadCWEData()
	controls, ok := data[id]
	if !ok {
		return nil
	}
	return controls
}
