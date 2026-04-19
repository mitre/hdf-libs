// Package nessus provides lookup functions for Nessus plugin family/ID to NIST 800-53 control mappings.
package nessus

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed nessus-nist-mappings.json
var mappingsData []byte

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

func loadData() {
	dataOnce.Do(func() {
		exactMap = make(map[lookupKey]string)
		wildcardMap = make(map[string]string)

		var mappings []nessusMapping
		if err := json.Unmarshal(mappingsData, &mappings); err != nil {
			return
		}

		for _, m := range mappings {
			pluginID := normalizePluginID(m.PluginIDRaw)
			if pluginID == "*" {
				wildcardMap[m.PluginFamily] = m.NISTID
			} else {
				exactMap[lookupKey{family: m.PluginFamily, pluginID: pluginID}] = m.NISTID
			}
		}
	})
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
			return splitNIST(nistID)
		}
	}

	// Wildcard match: family with pluginID="*"
	if nistID, ok := wildcardMap[pluginFamily]; ok {
		return splitNIST(nistID)
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
