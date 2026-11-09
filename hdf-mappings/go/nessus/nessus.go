// Package nessus provides lookup functions for Nessus plugin family/ID to NIST 800-53 control mappings.
package nessus

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/datasets"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

// nessusMapping represents a single entry in the Nessus-NIST mapping data.
// pluginID may be a number or "*" (wildcard) in the JSON, so we unmarshal it as json.RawMessage.
type nessusMapping struct {
	PluginFamily string          `json:"pluginFamily"`
	PluginIDRaw  json.RawMessage `json:"pluginID"`
	NISTID       string          `json:"NIST-ID"`
}

// lookupKey is a composite key for exact and wildcard lookups.
type lookupKey struct {
	family   string
	pluginID string
}

var (
	exactMap    map[lookupKey]string // family+pluginID → NIST-ID
	wildcardMap map[string]string    // family → NIST-ID (for pluginID="*")
	dataOnce    sync.Once
)

// parseData keeps the JSON shape testable without a mutable package var: the
// dataset is read inside the loader so the linker can drop it from a consumer
// that never looks a Nessus plugin up.
func parseData(data []byte) (exact map[lookupKey]string, wildcard map[string]string) {
	exact = make(map[lookupKey]string)
	wildcard = make(map[string]string)

	var mappings []nessusMapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		return exact, wildcard
	}

	for _, m := range mappings {
		pluginID := normalizePluginID(m.PluginIDRaw)
		if pluginID == "*" {
			wildcard[m.PluginFamily] = m.NISTID
		} else {
			exact[lookupKey{family: m.PluginFamily, pluginID: pluginID}] = m.NISTID
		}
	}
	return exact, wildcard
}

func loadData() {
	dataOnce.Do(func() { exactMap, wildcardMap = parseData(datasets.NessusNIST) })
}

// normalizePluginID extracts the plugin ID as a string from the raw JSON value.
// The JSON may contain a string ("*") or an integer (56310).
func normalizePluginID(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return fmt.Sprintf("%d", n)
	}
	return ""
}

// NativeRevision is the NIST 800-53 revision this table was authored against
// (heimdall2's Rev 4-era mapping; it carries AU-8(1), withdrawn in Rev 5).
// Lookups translate to the process-global revision via the NIST crosswalk.
const NativeRevision = 4

// NISTControls returns the NIST 800-53 controls for a Nessus plugin family and plugin ID.
// It first tries an exact match on family+pluginID, then falls back to a wildcard match on family alone.
// The NIST-ID field may contain multiple controls separated by "|" — these are split into a slice.
// Returns nil if no mapping is found.
func NISTControls(pluginFamily, pluginID string) []string {
	if pluginFamily == "" {
		return nil
	}

	loadData()

	// Exact match: family + specific pluginID
	if pluginID != "" && pluginID != "*" {
		if nistID, ok := exactMap[lookupKey{family: pluginFamily, pluginID: pluginID}]; ok {
			return nist.AtRevision(splitNIST(nistID), NativeRevision, nist.Revision())
		}
	}

	// Wildcard match: family with pluginID="*"
	if nistID, ok := wildcardMap[pluginFamily]; ok {
		return nist.AtRevision(splitNIST(nistID), NativeRevision, nist.Revision())
	}

	return nil
}

// NISTControl returns a single pipe-delimited NIST control string for a plugin family and ID.
// Returns "" if no mapping is found.
func NISTControl(pluginFamily, pluginID string) string {
	controls := NISTControls(pluginFamily, pluginID)
	if len(controls) == 0 {
		return ""
	}
	return strings.Join(controls, "|")
}

// Exists returns true if a mapping exists for the given plugin family (with any plugin ID).
func Exists(pluginFamily string) bool {
	loadData()
	if _, ok := wildcardMap[pluginFamily]; ok {
		return true
	}
	for k := range exactMap {
		if k.family == pluginFamily {
			return true
		}
	}
	return false
}

func splitNIST(nistID string) []string {
	parts := strings.Split(nistID, "|")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
