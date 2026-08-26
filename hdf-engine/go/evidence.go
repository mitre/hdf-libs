// Evidence-verify engine — the pure, filesystem-agnostic core of `hdf evidence
// verify` (ADR-0007 §11), shared by the CLI and the MCP so exactly one
// implementation exists. It classifies content-checksum matches and computes
// plan/results completeness; all filesystem IO and path confinement stay in the
// caller, injected as a FetchFunc. Kept at behavioural parity with the TS peer
// (hdf-engine/src/evidence.ts); see evidence_parity_test.go.
package hdfengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// ChecksumStatus classifies a single content entry's checksum verification.
type ChecksumStatus string

const (
	ChecksumMatch    ChecksumStatus = "match"
	ChecksumMismatch ChecksumStatus = "mismatch"
	ChecksumSkipped  ChecksumStatus = "skipped"
	ChecksumError    ChecksumStatus = "error"
)

// EvidenceContent is one content entry of an evidence package: a referenced
// document and its recorded checksum (empty when the entry carries none).
type EvidenceContent struct {
	URI      string `json:"uri"`
	Type     string `json:"type"`
	Checksum string `json:"checksum"`
}

// ChecksumResult is the verification outcome for one content entry.
type ChecksumResult struct {
	URI      string         `json:"uri"`
	Type     string         `json:"type"`
	Status   ChecksumStatus `json:"status"`
	Expected string         `json:"expected,omitempty"`
	Actual   string         `json:"actual,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// CompletenessResult reports which planned baselines are covered by results.
type CompletenessResult struct {
	Planned  []string `json:"planned"`
	Covered  []string `json:"covered"`
	Missing  []string `json:"missing"`
	Complete bool     `json:"complete"`
}

// FetchFunc resolves a content URI to its bytes. The caller owns path
// confinement (HDF_MCP_ROOT for the MCP, the package directory for the CLI).
type FetchFunc func(uri string) ([]byte, error)

// ParseEvidencePackage extracts the planRef and content entries from an
// evidence-package document.
func ParseEvidencePackage(pkg []byte) (string, []EvidenceContent, error) {
	var doc struct {
		PlanRef  string `json:"planRef"`
		Contents []struct {
			URI      string `json:"uri"`
			Type     string `json:"type"`
			Checksum *struct {
				Value string `json:"value"`
			} `json:"checksum"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(pkg, &doc); err != nil {
		return "", nil, fmt.Errorf("parse evidence package: %w", err)
	}
	contents := make([]EvidenceContent, 0, len(doc.Contents))
	for _, c := range doc.Contents {
		ec := EvidenceContent{URI: c.URI, Type: c.Type}
		if c.Checksum != nil {
			ec.Checksum = c.Checksum.Value
		}
		contents = append(contents, ec)
	}
	return doc.PlanRef, contents, nil
}

// VerifyChecksums verifies each content entry's sha256 against fetch(uri),
// preserving entry order. No checksum → skipped; a fetch error → error; hash
// mismatch → mismatch (carrying expected+actual).
func VerifyChecksums(contents []EvidenceContent, fetch FetchFunc) []ChecksumResult {
	out := make([]ChecksumResult, 0, len(contents))
	for _, c := range contents {
		r := ChecksumResult{URI: c.URI, Type: c.Type}
		if c.Checksum == "" {
			r.Status = ChecksumSkipped
		} else if data, err := fetch(c.URI); err != nil {
			r.Status = ChecksumError
			r.Error = err.Error()
		} else if actual := sha256HexOf(data); actual == c.Checksum {
			r.Status = ChecksumMatch
		} else {
			r.Status = ChecksumMismatch
			r.Expected = c.Checksum
			r.Actual = actual
		}
		out = append(out, r)
	}
	return out
}

// PlannedBaselineRefs extracts assessment baselineRefs from a plan document,
// deduped in first-seen order.
func PlannedBaselineRefs(plan []byte) ([]string, error) {
	var doc struct {
		Assessments []struct {
			BaselineRef string `json:"baselineRef"`
		} `json:"assessments"`
	}
	if err := json.Unmarshal(plan, &doc); err != nil {
		return nil, fmt.Errorf("parse plan: %w", err)
	}
	refs := make([]string, 0, len(doc.Assessments))
	for _, a := range doc.Assessments {
		if a.BaselineRef != "" {
			refs = append(refs, a.BaselineRef)
		}
	}
	return dedupe(refs), nil
}

// CoveredBaselineNames extracts baseline names from a results document, deduped
// in first-seen order.
func CoveredBaselineNames(results []byte) ([]string, error) {
	var doc struct {
		Baselines []struct {
			Name string `json:"name"`
		} `json:"baselines"`
	}
	if err := json.Unmarshal(results, &doc); err != nil {
		return nil, fmt.Errorf("parse results: %w", err)
	}
	names := make([]string, 0, len(doc.Baselines))
	for _, b := range doc.Baselines {
		if b.Name != "" {
			names = append(names, b.Name)
		}
	}
	return dedupe(names), nil
}

// Completeness diffs planned baseline refs against covered baseline names. A
// planned ref is covered when some results baseline shares its name. Missing is
// sorted so the outcome is deterministic across languages and runs.
func Completeness(planned, covered []string) CompletenessResult {
	coveredSet := make(map[string]bool, len(covered))
	for _, c := range covered {
		coveredSet[c] = true
	}
	missing := []string{}
	for _, p := range planned {
		if !coveredSet[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	return CompletenessResult{
		Planned:  planned,
		Covered:  covered,
		Missing:  missing,
		Complete: len(missing) == 0,
	}
}

func sha256HexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
