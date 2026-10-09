// Package hadolint provides lookup functions for hadolint rule codes to NIST
// 800-53 control mappings.
//
// One table covers both hadolint's own DL rules and the SC rules it surfaces
// from its embedded shellcheck, because both arrive in the same report. The
// dataset is ported from mitre/heimdall2; its source commit, the NIST revision
// it was authored against, and the re-port procedure are recorded in the JSON
// file itself. The TypeScript loader imports that same file, so the two
// languages cannot drift.
package hadolint

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

//go:embed hadolint-nist-mappings.json
var datasetData []byte

// Mapping is the NIST control list for one hadolint rule.
type Mapping struct {
	NIST []string `json:"nist"`
}

// Source identifies the upstream file the dataset was ported from.
type Source struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Commit     string `json:"commit"`
	SHA256     string `json:"sha256"`
}

// Provenance records where the dataset came from and what it was authored against.
type Provenance struct {
	Source       Source `json:"source"`
	Updated      string `json:"updated"`
	NISTRevision int    `json:"nistRevision"`
}

type dataset struct {
	Provenance
	Mappings map[string]Mapping `json:"mappings"`
}

var (
	loaded   dataset
	ruleIDs  []string
	loadOnce sync.Once
)

func load() *dataset {
	loadOnce.Do(func() {
		if err := json.Unmarshal(datasetData, &loaded); err != nil {
			return
		}
		ruleIDs = make([]string, 0, len(loaded.Mappings))
		for id := range loaded.Mappings {
			ruleIDs = append(ruleIDs, id)
		}
		sort.Strings(ruleIDs)
	})
	return &loaded
}

// Lookup returns the NIST controls for a hadolint rule code, translated to the
// process-global NIST revision. The returned slice is a copy. ok is false when
// the rule is not in the dataset.
//
// A rule whose controls do not survive translation comes back mapped but empty
// — SR-4 has no Rev 4 equivalent — so a caller must treat an empty list the
// same as an absent mapping and apply its own fallback.
func Lookup(ruleID string) (Mapping, bool) {
	return LookupForRevision(ruleID, nist.Revision())
}

// LookupForRevision is Lookup at an explicit NIST revision.
func LookupForRevision(ruleID string, rev int) (Mapping, bool) {
	ds := load()
	m, ok := ds.Mappings[ruleID]
	if !ok {
		return Mapping{}, false
	}
	return Mapping{NIST: nist.AtRevision(append([]string(nil), m.NIST...), ds.NISTRevision, rev)}, true
}

// Exists reports whether a hadolint rule code has a mapping.
func Exists(ruleID string) bool {
	_, ok := load().Mappings[ruleID]
	return ok
}

// AllRuleIDs returns every mapped hadolint rule code, sorted.
func AllRuleIDs() []string {
	load()
	return append([]string(nil), ruleIDs...)
}

// GetProvenance returns the dataset's upstream source and native NIST revision.
func GetProvenance() Provenance {
	return load().Provenance
}
