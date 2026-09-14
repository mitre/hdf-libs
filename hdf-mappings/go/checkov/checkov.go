// Package checkov provides lookup functions for Checkov check IDs to DISA CCI
// and NIST 800-53 control mappings.
//
// The dataset is ported verbatim from the published @mitre/hdf-converters
// 2.14.0 package. Its provenance, the Checkov version it was generated against,
// and the re-port procedure are recorded in the JSON file itself. The
// TypeScript loader imports this same file, so the two languages cannot drift.
package checkov

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

//go:embed checkov-cci-nist-mappings.json
var datasetData []byte

// Mapping is the CCI and NIST control lists for one Checkov check.
type Mapping struct {
	CCI  []string `json:"cci"`
	NIST []string `json:"nist"`
}

// Source identifies the published package the dataset was ported from.
type Source struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	Integrity string `json:"integrity"`
}

// Provenance records where the dataset came from and what it was generated against.
type Provenance struct {
	Source         Source `json:"source"`
	CheckovVersion string `json:"checkovVersion"`
	Updated        string `json:"updated"`
	NISTRevision   int    `json:"nistRevision"`
}

type dataset struct {
	Provenance
	Mappings map[string]Mapping `json:"mappings"`
}

var (
	loaded   dataset
	checkIDs []string
	loadOnce sync.Once
)

func load() *dataset {
	loadOnce.Do(func() {
		if err := json.Unmarshal(datasetData, &loaded); err != nil {
			return
		}
		checkIDs = make([]string, 0, len(loaded.Mappings))
		for id := range loaded.Mappings {
			checkIDs = append(checkIDs, id)
		}
		sort.Strings(checkIDs)
	})
	return &loaded
}

// Lookup returns the CCI and NIST controls for a Checkov check ID, with NIST
// controls translated to the process-global NIST revision. The returned slices
// are copies. ok is false when the check is not in the dataset.
func Lookup(checkID string) (Mapping, bool) {
	return LookupForRevision(checkID, nist.Revision())
}

// LookupForRevision is Lookup at an explicit NIST revision. CCIs are
// revision-independent identifiers and are returned unchanged.
func LookupForRevision(checkID string, rev int) (Mapping, bool) {
	ds := load()
	m, ok := ds.Mappings[checkID]
	if !ok {
		return Mapping{}, false
	}
	return Mapping{
		CCI:  append([]string(nil), m.CCI...),
		NIST: nist.AtRevision(append([]string(nil), m.NIST...), ds.NISTRevision, rev),
	}, true
}

// Exists reports whether a Checkov check ID has a mapping.
func Exists(checkID string) bool {
	_, ok := load().Mappings[checkID]
	return ok
}

// AllCheckIDs returns every mapped Checkov check ID, sorted.
func AllCheckIDs() []string {
	load()
	return append([]string(nil), checkIDs...)
}

// GetProvenance returns the dataset's source package, Checkov version and
// native NIST revision.
func GetProvenance() Provenance {
	return load().Provenance
}
