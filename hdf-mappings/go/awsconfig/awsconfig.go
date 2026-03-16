// Package awsconfig provides lookup functions for AWS Config rule to NIST control mappings.
package awsconfig

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
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
	byRuleName   map[string]*Mapping
	byIdentifier map[string]*Mapping
	loadOnce     sync.Once
)

func load() {
	loadOnce.Do(func() {
		var list []Mapping
		if err := json.Unmarshal(mappingsData, &list); err != nil {
			byRuleName = make(map[string]*Mapping)
			byIdentifier = make(map[string]*Mapping)
			return
		}
		byRuleName = make(map[string]*Mapping, len(list))
		byIdentifier = make(map[string]*Mapping, len(list))
		for i := range list {
			m := &list[i]
			byRuleName[m.AwsConfigRuleName] = m
			byIdentifier[m.AwsConfigRuleSourceIdentifier] = m
		}
	})
}

// GetByRuleName returns the mapping for the given kebab-case rule name, or nil if not found.
func GetByRuleName(name string) *Mapping {
	load()
	return byRuleName[name]
}

// GetByIdentifier returns the mapping for the given UPPERCASE source identifier, or nil if not found.
func GetByIdentifier(id string) *Mapping {
	load()
	return byIdentifier[id]
}

// NISTControls returns the pipe-separated NIST-ID string split into individual control IDs
// for the given rule name. Returns nil if the rule is not in the mapping.
func NISTControls(ruleName string) []string {
	m := GetByRuleName(ruleName)
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
