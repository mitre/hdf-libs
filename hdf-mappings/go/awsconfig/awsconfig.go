// Package awsconfig provides lookup functions for AWS Config rule to NIST control mappings.
package awsconfig

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

// Mapping represents a single AWS Config rule to NIST control mapping.
type Mapping struct {
	AwsConfigRuleSourceIdentifier string `json:"AwsConfigRuleSourceIdentifier"`
	AwsConfigRuleName             string `json:"AwsConfigRuleName"`
	NISTID                        string `json:"NIST-ID"`
	Rev                           int    `json:"Rev"`
}

//go:embed awsconfig-mappings.json
var mappingsData []byte

var (
	// keyed by revision → name/identifier → mapping
	byRuleName   map[int]map[string]*Mapping
	byIdentifier map[int]map[string]*Mapping
	loadOnce     sync.Once
)

func load() {
	loadOnce.Do(func() {
		byRuleName = make(map[int]map[string]*Mapping)
		byIdentifier = make(map[int]map[string]*Mapping)
		var list []Mapping
		if err := json.Unmarshal(mappingsData, &list); err != nil {
			return
		}
		for i := range list {
			m := &list[i]
			if byRuleName[m.Rev] == nil {
				byRuleName[m.Rev] = make(map[string]*Mapping)
				byIdentifier[m.Rev] = make(map[string]*Mapping)
			}
			byRuleName[m.Rev][m.AwsConfigRuleName] = m
			byIdentifier[m.Rev][m.AwsConfigRuleSourceIdentifier] = m
		}
	})
}

// GetByRuleName returns the mapping for the given kebab-case rule name at the
// default NIST revision, or nil if not found.
func GetByRuleName(name string) *Mapping {
	return GetByRuleNameForRevision(name, nist.CurrentRevision)
}

// GetByRuleNameForRevision returns the mapping for the given rule name at the
// requested NIST revision, or nil if not found.
func GetByRuleNameForRevision(name string, rev int) *Mapping {
	load()
	return byRuleName[rev][name]
}

// GetByIdentifier returns the mapping for the given UPPERCASE source identifier
// at the default NIST revision, or nil if not found.
func GetByIdentifier(id string) *Mapping {
	return GetByIdentifierForRevision(id, nist.CurrentRevision)
}

// GetByIdentifierForRevision returns the mapping for the given source identifier
// at the requested NIST revision, or nil if not found.
func GetByIdentifierForRevision(id string, rev int) *Mapping {
	load()
	return byIdentifier[rev][id]
}

// NISTControls returns the NIST control IDs for the given rule name at the
// default NIST revision. Returns nil if the rule is not in the mapping.
func NISTControls(ruleName string) []string {
	return NISTControlsForRevision(ruleName, nist.CurrentRevision)
}

// NISTControlsForRevision returns the NIST control IDs for the given rule name
// at the requested NIST revision. Returns nil if the rule is not mapped.
func NISTControlsForRevision(ruleName string, rev int) []string {
	m := GetByRuleNameForRevision(ruleName, rev)
	if m == nil || m.NISTID == "" {
		return nil
	}
	parts := strings.Split(m.NISTID, "|")
	controls := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			controls = append(controls, p)
		}
	}
	return controls
}
