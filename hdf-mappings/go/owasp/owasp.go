// Package owasp provides lookup functions for OWASP Top 10 to NIST 800-53 control mappings.
package owasp

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// owaspMapping represents one row in the OWASP→NIST mapping table.
type owaspMapping struct {
	OwaspID  string `json:"OWASP-ID"`
	NistID   string `json:"NIST-ID"`
}

//go:embed owasp-nist-mappings.json
var owaspMappingsData []byte

var (
	owaspData     map[string]string // OWASP ID → NIST control
	owaspDataOnce sync.Once
)

func loadOwaspData() map[string]string {
	owaspDataOnce.Do(func() {
		var list []owaspMapping
		if err := json.Unmarshal(owaspMappingsData, &list); err != nil {
			owaspData = make(map[string]string)
			return
		}
		owaspData = make(map[string]string, len(list))
		for _, m := range list {
			if m.NistID != "" {
				owaspData[m.OwaspID] = m.NistID
			}
		}
	})
	return owaspData
}

// NISTControl returns the NIST 800-53 control for an OWASP Top 10 ID.
// Accepts IDs like "A1", "A6", "A10".
// Returns an empty string if the OWASP ID is unknown or the input is empty.
func NISTControl(owaspID string) string {
	if owaspID == "" {
		return ""
	}
	data := loadOwaspData()
	return data[owaspID]
}
