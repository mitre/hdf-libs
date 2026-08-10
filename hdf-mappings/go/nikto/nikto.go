// Package nikto provides lookup functions for Nikto test ID to NIST 800-53 control mappings.
package nikto

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

//go:embed nikto-nist-mappings.json
var mappingsData []byte

var (
	niktoData     map[string]string // Nikto test ID → NIST control
	niktoDataOnce sync.Once
)

func loadData() map[string]string {
	niktoDataOnce.Do(func() {
		if err := json.Unmarshal(mappingsData, &niktoData); err != nil {
			niktoData = make(map[string]string)
		}
	})
	return niktoData
}

// NativeRevision is the NIST 800-53 revision this table was authored against
// (heimdall2's Rev 4-era mapping; every control it carries is identical at
// both revisions today). Lookups translate to the process-global revision.
const NativeRevision = 4

// NISTControl returns the NIST 800-53 control for a Nikto test ID.
// Accepts string ("600050") or numeric string forms.
// Returns "" if the Nikto test ID is not in the mapping.
func NISTControl(niktoID string) string {
	if niktoID == "" {
		return ""
	}

	data := loadData()
	if control, ok := data[niktoID]; ok {
		return strings.Join(nist.AtRevision(strings.Split(control, "|"), NativeRevision, nist.Revision()), "|")
	}
	return ""
}

// NISTControlByInt returns the NIST 800-53 control for a numeric Nikto test ID.
func NISTControlByInt(niktoID int) string {
	return NISTControl(strconv.Itoa(niktoID))
}

// Exists returns true if the Nikto test ID has a NIST mapping.
func Exists(niktoID string) bool {
	data := loadData()
	_, ok := data[niktoID]
	return ok
}
