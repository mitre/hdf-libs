// Package hipcheck provides lookup functions for Hipcheck analysis names to
// NIST 800-53 Rev 5 control mappings.
//
// The mapping is a hand-curated, RMF-reviewed table: Hipcheck publishes no
// analysis-to-controls crosswalk, so no authoritative source exists to derive
// it from. Each entry carries a Rationale. The data file is byte-identical to
// its TypeScript peer at hdf-mappings/src/data/hipcheck-nist-mappings.json.
package hipcheck

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

//go:embed hipcheck-nist-mappings.json
var mappingsData []byte

// Mapping is one row of the Hipcheck analysis → NIST control table.
type Mapping struct {
	Analysis  string `json:"Analysis"`
	NISTID    string `json:"NIST-ID"`
	Rev       int    `json:"Rev"`
	Rationale string `json:"Rationale"`
}

var (
	byAnalysis map[string]*Mapping
	loadOnce   sync.Once
)

func load() map[string]*Mapping {
	loadOnce.Do(func() {
		byAnalysis = make(map[string]*Mapping)
		var list []Mapping
		if err := json.Unmarshal(mappingsData, &list); err != nil {
			return
		}
		for i := range list {
			byAnalysis[list[i].Analysis] = &list[i]
		}
	})
	return byAnalysis
}

// bareName strips a plugin publisher prefix ("mitre/binary" → "binary") so the
// mapping keys on the analysis name regardless of who published the plugin.
func bareName(analysis string) string {
	if i := strings.LastIndex(analysis, "/"); i >= 0 {
		return analysis[i+1:]
	}
	return analysis
}

// NativeRevision is the NIST 800-53 revision this table was authored against
// (declared Rev: 5 in the data; it carries SR-family controls that do not
// exist at Rev 4). Lookups translate to the process-global revision.
const NativeRevision = 5

// NISTControls returns the NIST 800-53 controls for a Hipcheck analysis name.
// Accepts bare ("binary") or publisher-prefixed ("mitre/binary") names.
// Returns nil if the analysis has no mapping.
func NISTControls(analysis string) []string {
	m := load()[bareName(analysis)]
	if m == nil {
		return nil
	}
	parts := strings.Split(m.NISTID, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return nist.AtRevision(out, NativeRevision, nist.Revision())
}

// Exists reports whether the given Hipcheck analysis name has a NIST mapping.
func Exists(analysis string) bool {
	_, ok := load()[bareName(analysis)]
	return ok
}

// AllAnalyses returns the mapped analysis names, sorted.
func AllAnalyses() []string {
	data := load()
	names := make([]string, 0, len(data))
	for k := range data {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
