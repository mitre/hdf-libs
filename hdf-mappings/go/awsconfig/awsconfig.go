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
	// Source is the generator tier the row came from: config-pack,
	// security-hub, derived-theme, or crosswalk (rev-translated from the rule's
	// native revision; empty NIST-ID means no equivalent exists at this Rev).
	Source string `json:"Source"`
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
	return GetByRuleNameForRevision(name, nist.Revision())
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
	return GetByIdentifierForRevision(id, nist.Revision())
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
	return NISTControlsForRevision(ruleName, nist.Revision())
}

// NISTControlsForRevision returns the NIST control IDs for the given rule name
// at the requested NIST revision. Returns nil if the rule is not mapped.
func NISTControlsForRevision(ruleName string, rev int) []string {
	return controlsFromMapping(GetByRuleNameForRevision(ruleName, rev))
}

// NISTControlsByIdentifier returns the NIST control IDs for the given source
// identifier at the default NIST revision. Returns nil if not mapped.
func NISTControlsByIdentifier(identifier string) []string {
	return NISTControlsByIdentifierForRevision(identifier, nist.Revision())
}

// NISTControlsByIdentifierForRevision returns the NIST control IDs for the given
// source identifier at the requested NIST revision. Returns nil if not mapped.
func NISTControlsByIdentifierForRevision(identifier string, rev int) []string {
	return controlsFromMapping(GetByIdentifierForRevision(identifier, rev))
}

// NISTControlsBySubstring resolves NIST controls for a decorated rule name such
// as Security Hub's "securityhub-<canonical-name>-<hash>", where an exact lookup
// fails. It returns the controls of the canonical rule whose name is contained
// in the given name; the longest such match wins. Returns nil if none match.
func NISTControlsBySubstring(name string) []string {
	return NISTControlsBySubstringForRevision(name, nist.Revision())
}

// NISTControlsBySubstringForRevision is NISTControlsBySubstring at a specific
// NIST revision.
func NISTControlsBySubstringForRevision(name string, rev int) []string {
	load()
	if name == "" {
		return nil
	}
	lower := strings.ToLower(name)
	var best *Mapping
	bestLen := 0
	for key, m := range byRuleName[rev] {
		if key != "" && len(key) > bestLen && strings.Contains(lower, strings.ToLower(key)) {
			best = m
			bestLen = len(key)
		}
	}
	return controlsFromMapping(best)
}

func controlsFromMapping(m *Mapping) []string {
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

// MappedRevisions returns the supported NIST revisions at which the rule
// resolves to a non-empty control list, sorted ascending. It mirrors the
// resolution buildNISTTags performs (source identifier first, then rule name),
// so a revision is included exactly when a conversion at that revision would
// emit NIST tags for the rule. An empty result means the rule is unmapped at
// every revision (not a revision mismatch).
func MappedRevisions(sourceIdentifier, ruleName string) []int {
	load()
	var revs []int
	for _, rev := range nist.SupportedRevisions() {
		if mappedInIndex(byIdentifier[rev], sourceIdentifier) || mappedInIndex(byRuleName[rev], ruleName) {
			revs = append(revs, rev)
		}
	}
	return revs
}

func mappedInIndex(index map[string]*Mapping, key string) bool {
	if key == "" {
		return false
	}
	m := index[key]
	return m != nil && m.NISTID != ""
}
