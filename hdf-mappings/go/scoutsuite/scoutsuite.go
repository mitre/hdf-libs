// Package scoutsuite provides lookup functions for ScoutSuite rule to NIST 800-53 control mappings.
package scoutsuite

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed scoutsuite-nist-mappings.json
var mappingsData []byte

type mapping struct {
	Rule   string `json:"RULE"`
	NistID string `json:"NIST-ID"`
}

var (
	scoutsuiteData     map[string]string // rule name → NIST control(s)
	scoutsuiteDataOnce sync.Once
)

func loadData() map[string]string {
	scoutsuiteDataOnce.Do(func() {
		var raw []mapping
		if err := json.Unmarshal(mappingsData, &raw); err != nil {
			scoutsuiteData = make(map[string]string)
			return
		}
		scoutsuiteData = make(map[string]string, len(raw))
		for _, m := range raw {
			scoutsuiteData[m.Rule] = m.NistID
		}
	})
	return scoutsuiteData
}

// NISTControl returns the NIST 800-53 control(s) for a ScoutSuite rule name.
// Some rules map to multiple controls separated by "|" (e.g., "AU-12|SI-4(2)").
// Returns "" if the rule is not in the mapping.
func NISTControl(rule string) string {
	if rule == "" {
		return ""
	}
	data := loadData()
	if control, ok := data[rule]; ok {
		return control
	}
	return ""
}

// NISTControls returns the NIST 800-53 controls for a ScoutSuite rule name
// as a string slice. Multi-control mappings (separated by "|") are split
// into individual entries.
// Returns nil if the rule is not in the mapping.
func NISTControls(rule string) []string {
	ctrl := NISTControl(rule)
	if ctrl == "" {
		return nil
	}
	return strings.Split(ctrl, "|")
}

// Exists returns true if the ScoutSuite rule has a NIST mapping.
func Exists(rule string) bool {
	data := loadData()
	_, ok := data[rule]
	return ok
}
