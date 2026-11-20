// Package scoutsuite provides lookup functions for ScoutSuite rule to NIST 800-53 control mappings.
package scoutsuite

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/datasets"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

type mapping struct {
	Rule   string `json:"RULE"`
	NistID string `json:"NIST-ID"`
}

var (
	scoutsuiteData     map[string]string // rule name → NIST control(s)
	scoutsuiteDataOnce sync.Once
)

// parseData keeps the JSON shape testable without a mutable package var: the
// dataset is read inside the loader so the linker can drop it from a consumer
// that never looks a ScoutSuite rule up.
func parseData(data []byte) map[string]string {
	var raw []mapping
	if err := json.Unmarshal(data, &raw); err != nil {
		return make(map[string]string)
	}
	parsed := make(map[string]string, len(raw))
	for _, m := range raw {
		parsed[m.Rule] = m.NistID
	}
	return parsed
}

func loadData() map[string]string {
	scoutsuiteDataOnce.Do(func() {
		scoutsuiteData = parseData(datasets.ScoutSuiteNIST)
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
		return strings.Join(nist.AtRevision(strings.Split(control, "|"), NativeRevision, nist.Revision()), "|")
	}
	return ""
}

// NativeRevision is the NIST 800-53 revision this table was authored against
// (heimdall2's Rev 4-era mapping; every control it carries is identical at
// both revisions today). Lookups translate to the process-global revision.
const NativeRevision = 4

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
