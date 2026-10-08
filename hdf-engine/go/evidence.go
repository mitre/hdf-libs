// Evidence-verify engine — the pure, filesystem-agnostic core of `hdf evidence
// verify` (ADR-0007 §11), shared by the CLI and the MCP so exactly one
// implementation exists. It classifies content-checksum matches and computes
// plan/results completeness; all filesystem IO and path confinement stay in the
// caller, injected as a FetchFunc. Kept at behavioural parity with the TS peer
// (hdf-engine/src/evidence.ts); see evidence_parity_test.go.
package hdfengine

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"lukechampine.com/blake3"
)

// ChecksumStatus classifies a single content entry's checksum verification.
type ChecksumStatus string

const (
	ChecksumMatch    ChecksumStatus = "match"
	ChecksumMismatch ChecksumStatus = "mismatch"
	ChecksumSkipped  ChecksumStatus = "skipped"
	ChecksumError    ChecksumStatus = "error"
	// ChecksumUnsupported is a recorded algorithm this build cannot compute. It is
	// deliberately NOT an error: the bytes may be intact and the package valid, and a
	// document recording a digest we cannot compute is the same shape as one
	// referencing an artifact we cannot reach. Every caller switching on this type
	// must handle it — leaving it to a default reports an unverified entry as verified.
	ChecksumUnsupported ChecksumStatus = "unsupported"
)

// EvidenceContent is one content entry of an evidence package: a referenced
// document and its recorded checksum (empty when the entry carries none).
type EvidenceContent struct {
	URI      string `json:"uri"`
	Type     string `json:"type"`
	Checksum string `json:"checksum"`
	// ChecksumAlgorithm is the algorithm the package recorded, empty when it
	// stated none. The sha256 default belongs to verification, not to the parse,
	// so an unstated algorithm is not invented here.
	ChecksumAlgorithm string `json:"checksumAlgorithm"`
	// ChecksumRecorded distinguishes an entry carrying no checksum object from one
	// carrying a checksum whose value is empty. Checksum alone conflates them, and
	// the difference matters: a recorded-but-blank value is unverifiable, whereas an
	// absent checksum is simply not a claim.
	ChecksumRecorded bool `json:"checksumRecorded"`
}

// ChecksumResult is the verification outcome for one content entry.
type ChecksumResult struct {
	URI  string `json:"uri"`
	Type string `json:"type"`
	// Algorithm is the algorithm this entry's checksum is recorded under, with an
	// unstated one reported as the sha256 it defaults to. It is EMPTY for a skipped
	// entry — one with no checksum VALUE to verify, whether it carries no checksum at
	// all or one whose value is blank (Checksum.value has no minLength, so a blank
	// value is schema-valid and may still name an algorithm). Nothing was hashed in
	// either case, and naming an algorithm would imply a computation that never ran.
	Algorithm string         `json:"algorithm,omitempty"`
	Status    ChecksumStatus `json:"status"`
	Expected  string         `json:"expected,omitempty"`
	Actual    string         `json:"actual,omitempty"`
	Error     string         `json:"error,omitempty"`
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
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
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
			ec.ChecksumAlgorithm = c.Checksum.Algorithm
			ec.ChecksumRecorded = true
		}
		contents = append(contents, ec)
	}
	return doc.PlanRef, contents, nil
}

// VerifyChecksums verifies each content entry against fetch(uri) using the
// algorithm the entry recorded, preserving entry order. No checksum → skipped;
// an algorithm this build cannot compute → unsupported, never mismatch (that would
// say their evidence changed when it did not) and never error (the bytes may be
// intact); a fetch error → error; hash mismatch → mismatch (carrying
// expected+actual).
func VerifyChecksums(contents []EvidenceContent, fetch FetchFunc) []ChecksumResult {
	out := make([]ChecksumResult, 0, len(contents))
	for _, c := range contents {
		r := ChecksumResult{URI: c.URI, Type: c.Type}
		if c.Checksum == "" {
			r.Status = ChecksumSkipped
			out = append(out, r)
			continue
		}
		r.Algorithm = effectiveAlgorithm(c.ChecksumAlgorithm)
		// The algorithm is checked before any IO: whether this build can compute
		// it is a property of the package, not of the filesystem.
		if _, hashErr := ChecksumHex(c.ChecksumAlgorithm, nil); hashErr != nil {
			r.Status = ChecksumUnsupported
			r.Error = hashErr.Error()
		} else if data, err := fetch(c.URI); err != nil {
			r.Status = ChecksumError
			r.Error = err.Error()
		} else if actual, _ := ChecksumHex(c.ChecksumAlgorithm, data); actual == c.Checksum {
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

// CoveredBaselinesInPackage concatenates the covered baseline names of every
// hdf-results document the package references, in entry order. An entry that
// cannot be fetched or parsed is skipped: checksum verification is what reports
// a read failure, and a partial coverage list is what the completeness diff
// needs to name the missing baselines.
func CoveredBaselinesInPackage(contents []EvidenceContent, fetch FetchFunc) []string {
	var covered []string
	forEachResultsDocument(contents, fetch, func(data []byte) {
		if names, err := CoveredBaselineNames(data); err == nil {
			covered = append(covered, names...)
		}
	})
	return covered
}

// AgentOverridesInPackage sums the agent-attributed override count across every
// hdf-results document the package references — the detective surface at the
// evidence-package level. Unreadable or unparseable entries are skipped, but
// schema validity is deliberately not required: an agent's judgment is worth
// reporting even in a document that fails validation elsewhere.
func AgentOverridesInPackage(contents []EvidenceContent, fetch FetchFunc) int {
	total := 0
	forEachResultsDocument(contents, fetch, func(data []byte) {
		var r hdf.HDFResults
		// Normalize first: real HDF carries zone-less result timestamps, which
		// the generated time.Time fields reject, and a typed decode would drop
		// the whole document rather than miscount it.
		if json.Unmarshal(hdfutil.NormalizeHDFTimestamps(data), &r) == nil {
			total += AgentOverrideCount(r)
		}
	})
	return total
}

// forEachResultsDocument fetches each referenced hdf-results document in entry
// order, skipping entries that carry no URI or cannot be read.
func forEachResultsDocument(contents []EvidenceContent, fetch FetchFunc, visit func(data []byte)) {
	for _, c := range contents {
		if c.Type != "hdf-results" || c.URI == "" {
			continue
		}
		data, err := fetch(c.URI)
		if err != nil {
			continue
		}
		visit(data)
	}
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

// effectiveAlgorithm names the algorithm an entry's checksum is verified under:
// an unstated algorithm means sha256, so reporting "" would understate it.
func effectiveAlgorithm(recorded string) string {
	if recorded == "" {
		return "sha256"
	}
	return recorded
}

// ChecksumHex hashes data with the named Hash_Algorithm, hex-encoded. An empty
// algorithm means sha256, so a package that records only a value keeps its meaning.
// Every algorithm the enum admits is computed here; one from outside it is refused by
// name rather than silently treated as something else. This is the single definition
// of which algorithms this codebase can verify — the CLI reads it rather than keeping
// its own copy.
func ChecksumHex(algorithm string, data []byte) (string, error) {
	switch algorithm {
	case "", "sha256":
		return hdfutil.SHA256Hex(data), nil
	case "sha384":
		sum := sha512.Sum384(data)
		return hex.EncodeToString(sum[:]), nil
	case "sha512":
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:]), nil
	case "blake3":
		// The 32-byte default-length digest, which is what the BLAKE3 reference vectors
		// direct implementations to compare against; the function's extended output has no
		// meaning for a recorded Checksum.
		sum := blake3.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported checksum algorithm %q: this build computes sha256, sha384, sha512 and blake3", algorithm)
	}
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
