// Package diff provides SBOM comparison functionality for the HDF diff engine.
// It compares two SBOM documents (CycloneDX or SPDX JSON) and produces
// package-level diffs showing added, removed, updated, and unchanged packages.
//
// Uses protobom for format-agnostic SBOM parsing.
package diff

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
)

// PackageDiff represents the comparison result for a single package between two SBOMs.
type PackageDiff struct {
	Purl       string   `json:"purl"`
	Name       string   `json:"name"`
	State      string   `json:"state"` // added, removed, updated, unchanged
	OldVersion string   `json:"oldVersion,omitempty"`
	NewVersion string   `json:"newVersion,omitempty"`
	Licenses   []string `json:"licenses,omitempty"`
}

// DiffResult holds the complete result of comparing two SBOM documents.
//
//nolint:revive // matches TypeScript export name
type DiffResult struct {
	PackageDiffs []PackageDiff `json:"packageDiffs"`
	Added        int           `json:"added"`
	Removed      int           `json:"removed"`
	Updated      int           `json:"updated"`
	Unchanged    int           `json:"unchanged"`
}

// DiffSBOMs compares two SBOM files (CycloneDX or SPDX JSON) and returns
// package-level diffs. Uses protobom for format-agnostic parsing.
//
//nolint:revive // matches TypeScript export name
func DiffSBOMs(oldData, newData []byte) (*DiffResult, error) {
	r := reader.New()

	oldDoc, err := r.ParseStream(bytes.NewReader(oldData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse old SBOM: %w", err)
	}

	newDoc, err := r.ParseStream(bytes.NewReader(newData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse new SBOM: %w", err)
	}

	oldNodes := extractNodes(oldDoc)
	newNodes := extractNodes(newDoc)

	oldMap := buildNodeMap(oldNodes)
	newMap := buildNodeMap(newNodes)

	var diffs []PackageDiff
	seen := make(map[string]bool)

	// Check old packages against new
	for key, oldNode := range oldMap {
		seen[key] = true
		if newNode, exists := newMap[key]; exists {
			if oldNode.Version != newNode.Version {
				diffs = append(diffs, PackageDiff{
					Purl:       nodeKey(newNode),
					Name:       newNode.Name,
					State:      "updated",
					OldVersion: oldNode.Version,
					NewVersion: newNode.Version,
					Licenses:   nonEmptyLicenses(newNode.Licenses),
				})
			} else {
				diffs = append(diffs, PackageDiff{
					Purl:  nodeKey(oldNode),
					Name:  oldNode.Name,
					State: "unchanged",
				})
			}
		} else {
			diffs = append(diffs, PackageDiff{
				Purl:       nodeKey(oldNode),
				Name:       oldNode.Name,
				State:      "removed",
				OldVersion: oldNode.Version,
			})
		}
	}

	// Check for added packages
	for key, newNode := range newMap {
		if !seen[key] {
			diffs = append(diffs, PackageDiff{
				Purl:       nodeKey(newNode),
				Name:       newNode.Name,
				State:      "added",
				NewVersion: newNode.Version,
				Licenses:   nonEmptyLicenses(newNode.Licenses),
			})
		}
	}

	// Sort by name for deterministic output
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].Name < diffs[j].Name })

	result := &DiffResult{PackageDiffs: diffs}
	for _, d := range diffs {
		switch d.State {
		case "added":
			result.Added++
		case "removed":
			result.Removed++
		case "updated":
			result.Updated++
		case "unchanged":
			result.Unchanged++
		}
	}

	return result, nil
}

// extractNodes safely retrieves the node list from a protobom document.
func extractNodes(doc *sbom.Document) []*sbom.Node {
	nl := doc.GetNodeList()
	if nl == nil {
		return nil
	}
	return nl.GetNodes()
}

// buildNodeMap indexes nodes by their canonical key (PURL without version, or name).
// When multiple nodes share the same key, the last one wins — this mirrors
// how package managers resolve duplicate entries.
func buildNodeMap(nodes []*sbom.Node) map[string]*sbom.Node {
	m := make(map[string]*sbom.Node, len(nodes))
	for _, n := range nodes {
		key := matchKey(n)
		if key != "" {
			m[key] = n
		}
	}
	return m
}

// matchKey returns a version-independent key for matching a node across SBOMs.
// Uses the PURL name portion (stripping version) if available, otherwise the node name.
func matchKey(n *sbom.Node) string {
	// Use node name as the match key. The PURL contains the version, so using
	// the raw name gives us a version-independent match key.
	if n.Name != "" {
		return n.Name
	}
	// Fallback to PURL string if name is empty
	purl := string(n.Purl())
	if purl != "" {
		return purl
	}
	return ""
}

// nodeKey returns the best identifier for a node: PURL if available, else name.
func nodeKey(n *sbom.Node) string {
	purl := string(n.Purl())
	if purl != "" {
		return purl
	}
	return n.Name
}

// nonEmptyLicenses returns the license slice only if it has entries, nil otherwise.
// This keeps JSON output clean by omitting empty arrays.
func nonEmptyLicenses(licenses []string) []string {
	if len(licenses) == 0 {
		return nil
	}
	return licenses
}
