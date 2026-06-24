// Package cwe provides lookup functions for CWE to NIST 800-53 control mappings.
package cwe

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

// cweMapping represents one row in the CWE→NIST mapping table.
type cweMapping struct {
	CWEID  int    `json:"CWE-ID"`
	NISTID string `json:"NIST-ID"`
	Rev    int    `json:"Rev"`
}

//go:embed cwe-nist-mappings.json
var cweMappingsData []byte

var (
	cweData     map[int]map[int][]string // revision → CWE numeric ID → NIST controls
	cweDataOnce sync.Once
)

func loadCWEData() map[int]map[int][]string {
	cweDataOnce.Do(func() {
		cweData = make(map[int]map[int][]string)
		var list []cweMapping
		if err := json.Unmarshal(cweMappingsData, &list); err != nil {
			return
		}
		for _, m := range list {
			if m.NISTID == "" {
				continue
			}
			if cweData[m.Rev] == nil {
				cweData[m.Rev] = make(map[int][]string)
			}
			cweData[m.Rev][m.CWEID] = append(cweData[m.Rev][m.CWEID], m.NISTID)
		}
	})
	return cweData
}

// NISTControls returns NIST 800-53 controls for a CWE ID at the default NIST
// revision. Accepts "CWE-476" or "476". Returns nil if unknown or empty.
func NISTControls(cweID string) []string {
	return NISTControlsForRevision(cweID, nist.Revision())
}

// NISTControlsForRevision returns NIST 800-53 controls for a CWE ID at the
// requested NIST revision. Accepts "CWE-476" or "476". Returns nil if unknown.
func NISTControlsForRevision(cweID string, rev int) []string {
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

	controls, ok := loadCWEData()[rev][id]
	if !ok {
		return nil
	}
	return controls
}
