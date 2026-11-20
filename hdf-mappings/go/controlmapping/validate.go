// Package controlmapping validates externally-produced scanner-to-NIST
// candidate corpora on their way into this repo. A candidate is a scored
// suggestion for a human to adjudicate, never a mapping: nothing here resolves
// a scanner check into a tags.nist value.
package controlmapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

// CandidateSchema is the only schema literal ValidateCandidates accepts.
const CandidateSchema = "control-mapping-candidates/v1"

// Refusal codes. The TypeScript twin uses the same literals, and the shared
// table go/controlmapping/testdata/candidate-validation-cases.json pins them.
const (
	FaultDocumentUnparseable    = "document_unparseable"
	FaultSchemaUnknown          = "schema_unknown"
	FaultFieldTypeInvalid       = "field_type_invalid"
	FaultCatalogRevisionMissing = "catalog_revision_missing"
	FaultCatalogRevisionUnsup   = "catalog_revision_unsupported"
	FaultCatalogRevisionMixed   = "catalog_revision_inconsistent"
	FaultCatalogCommitMissing   = "catalog_commit_missing"
	FaultScannerNameMissing     = "scanner_name_missing"
	FaultScannerVersionMissing  = "scanner_version_missing"
	FaultScannerVersionFloating = "scanner_version_floating"
	FaultChecksEmpty            = "checks_empty"
	FaultCheckIDEmpty           = "check_id_empty"
	FaultCheckIDInvalid         = "check_id_invalid"
	FaultCandidatesEmpty        = "candidates_empty"
	FaultControlMissing         = "candidate_control_missing"
	FaultControlUnspellable     = "candidate_control_unspellable"
	FaultControlWrongRevision   = "candidate_control_wrong_revision"
	FaultControlUnknown         = "candidate_control_unknown"
	FaultScoreMissing           = "candidate_score_missing"
	FaultScoreRange             = "candidate_score_range"
)

// ErrUnadjudicated is what every candidate lookup for NIST controls returns.
// Candidates order a review queue; only the adjudicated artifact maps.
var ErrUnadjudicated = errors.New("controlmapping: candidates are unadjudicated and resolve to no NIST controls")

// Fault is one reason a corpus was refused. Path is a JSON Pointer into the
// document, so a refusal names the record at fault.
type Fault struct {
	Code   string
	Path   string
	Detail string
}

// String renders a fault for a refusal message. A Fault is a finding, not an
// error value: refusals are returned as a slice so the whole corpus is
// accounted for in one pass.
func (f Fault) String() string { return fmt.Sprintf("%s at %s: %s", f.Code, f.Path, f.Detail) }

// Catalog is the NIST catalog the scores were computed against. Revision is
// what every candidate id is checked for existence at; PinnedCommit is what
// makes the scores reproducible.
type Catalog struct {
	Source       string
	Revision     int
	PinnedCommit string
}

// Scanner is the tool whose check catalog the corpus maps. Version must be
// concrete: a floating tag leaves the set of checks scored unknowable.
type Scanner struct {
	Name    string
	Version string
	Checks  int
}

// Candidate is one scored suggestion. Control is upstream's spelling;
// NormalizedControl is this repo's canonical spelling of the same id, so
// consumers join against the catalog without re-deriving the translation.
type Candidate struct {
	Control           string
	NormalizedControl string
	ControlTitle      string
	Score             float64
	MatchedOn         []string
}

// Check is one scanner check and its ranked candidates.
type Check struct {
	QueryName  string
	Platform   string
	CWE        string
	Category   string
	Candidates []Candidate
}

// Corpus is an accepted candidate corpus.
type Corpus struct {
	Catalog Catalog
	Scanner Scanner
	// Method is upstream's description of how the scores were produced,
	// carried verbatim because this repo does not interpret it.
	Method any

	checks map[string]Check
}

// CheckIDs returns every check id in the corpus, sorted.
func (c *Corpus) CheckIDs() []string {
	ids := make([]string, 0, len(c.checks))
	for id := range c.checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Check returns one check and whether the corpus carries it.
func (c *Corpus) Check(checkID string) (Check, bool) {
	ch, ok := c.checks[checkID]
	return ch, ok
}

// Candidates returns a check's ranked candidates and whether the corpus
// carries that check.
func (c *Corpus) Candidates(checkID string) ([]Candidate, bool) {
	ch, ok := c.checks[checkID]
	if !ok {
		return nil, false
	}
	return ch.Candidates, true
}

// ResolveNIST always refuses. It exists so a caller reaching for a mapping
// gets ErrUnadjudicated rather than an empty slice that reads as "no controls
// apply".
func (c *Corpus) ResolveNIST(string) ([]string, error) {
	return nil, ErrUnadjudicated
}

// Upstream writes enhancements with a dot ("SA-10.4"); NIST writes them
// parenthesised ("SA-10 (4)"). NIST uses no dots in control numbers, so the
// substitution is unambiguous.
var dotEnhancement = regexp.MustCompile(`\.(\d+)`)

// maxCheckCount bounds the scanner's catalog size to what both languages carry
// identically. Go's float-to-int conversion is implementation-defined beyond
// int range, and JavaScript has no integer type at all, so an unbounded count
// could mean two different things in one accepted document.
const maxCheckCount = 1<<31 - 1

// trimBlank strips leading and trailing blanks, where "blank" is the union of
// Go's unicode.IsSpace and JavaScript's String.prototype.trim. The two stdlib
// sets are not the same — Go trims U+0085 and not U+FEFF, JavaScript the
// reverse — so the contract defines its own set rather than inheriting either,
// and the twin implements this exact union.
func trimBlank(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == '\uFEFF'
	})
}

// floatingTags are version values that name no specific release.
var floatingTags = map[string]bool{
	"latest": true, "main": true, "master": true, "head": true,
	"edge": true, "nightly": true, "dev": true, "stable": true,
}

// validator walks a decoded document. It decodes into map[string]any rather
// than into typed structs so that a field of the wrong JSON type is reported
// against that field, the way the TypeScript twin reports it. Typed decoding
// aborts the whole document on the first mismatch, which would make the two
// languages refuse the same input for different reasons.
type validator struct {
	faults []Fault
}

func (v *validator) add(code, path, detail string) {
	v.faults = append(v.faults, Fault{code, path, detail})
}

// field returns a document member, whether it is present, and whether it has
// the wanted JSON type. A present member of the wrong type is reported here, so
// each caller only has to handle present-and-valid or absent.
func (v *validator) field(parent map[string]any, key, path, want string) (any, bool) {
	raw, present := parent[key]
	if !present {
		return nil, false
	}
	// An explicit null is a JSON type like any other, and never the wanted one.
	// Reading it as absence would let a null suppress the member's own
	// "missing" fault and admit a corpus with nothing declared.
	if jsonType(raw) != want {
		v.add(FaultFieldTypeInvalid, path, fmt.Sprintf("want a JSON %s, got %s", want, jsonType(raw)))
		return nil, false
	}
	return raw, true
}

func (v *validator) object(parent map[string]any, key, path string) map[string]any {
	raw, ok := v.field(parent, key, path, "object")
	if !ok {
		return map[string]any{}
	}
	return raw.(map[string]any)
}

func (v *validator) str(parent map[string]any, key, path string) (string, bool) {
	raw, ok := v.field(parent, key, path, "string")
	if !ok {
		return "", false
	}
	return raw.(string), true
}

func (v *validator) number(parent map[string]any, key, path string) (float64, bool) {
	raw, ok := v.field(parent, key, path, "number")
	if !ok {
		return 0, false
	}
	return raw.(float64), true
}

func (v *validator) array(parent map[string]any, key, path string) ([]any, bool) {
	raw, ok := v.field(parent, key, path, "array")
	if !ok {
		return nil, false
	}
	return raw.([]any), true
}

func jsonType(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// ValidateCandidates checks raw against the candidate-corpus contract.
// Acceptance is all-or-nothing: on any fault it returns a nil corpus and every
// fault it found, because a partially-imported corpus leaves adjudication
// running against an unknown subset.
func ValidateCandidates(raw []byte) (*Corpus, []Fault) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, []Fault{{FaultDocumentUnparseable, "", err.Error()}}
	}
	root, ok := document.(map[string]any)
	if !ok {
		return nil, []Fault{{FaultDocumentUnparseable, "", "the document is not a JSON object"}}
	}

	if schema, _ := root["schema"].(string); schema != CandidateSchema {
		return nil, []Fault{{
			FaultSchemaUnknown, "/schema",
			fmt.Sprintf("schema is %v, want %q", root["schema"], CandidateSchema),
		}}
	}

	v := &validator{}
	catalog, revisionUsable := v.validateCatalog(v.object(root, "catalog", "/catalog"))
	scanner := v.validateScanner(v.object(root, "scanner", "/scanner"))
	revision := catalog.Revision

	checksRaw := v.object(root, "checks", "/checks")
	if len(checksRaw) == 0 {
		v.add(FaultChecksEmpty, "/checks", "a corpus with no checks is an upstream build failure, not an empty import")
		return nil, v.faults
	}

	checks := make(map[string]Check, len(checksRaw))
	for _, id := range sortedKeys(checksRaw) {
		base := "/checks/" + escapePointer(id)
		if strings.ContainsRune(id, '\uFFFD') {
			v.add(FaultCheckIDInvalid, base,
				"a check id carrying U+FFFD came from text that did not survive decoding, and would key the mapping differently in each language")
		}
		if trimBlank(id) == "" {
			v.add(FaultCheckIDEmpty, base, "a check id keys the published mapping and cannot be blank")
		}
		checkRaw := v.object(checksRaw, id, base)
		candidatesRaw, present := v.array(checkRaw, "candidates", base+"/candidates")
		if !present || len(candidatesRaw) == 0 {
			v.add(FaultCandidatesEmpty, base+"/candidates",
				"a check with no candidates must be absent, so adjudication cannot read it as reviewed-and-rejected")
		}
		queryName, _ := v.str(checkRaw, "query_name", base+"/query_name")
		platform, _ := v.str(checkRaw, "platform", base+"/platform")
		cwe, _ := v.str(checkRaw, "cwe", base+"/cwe")
		category, _ := v.str(checkRaw, "category", base+"/category")
		checks[id] = Check{
			QueryName:  queryName,
			Platform:   platform,
			CWE:        cwe,
			Category:   category,
			Candidates: v.validateCandidates(candidatesRaw, base, revision, revisionUsable),
		}
	}

	v.validateRevisionConsistency(checks)

	if len(v.faults) > 0 {
		return nil, v.faults
	}
	return &Corpus{
		Catalog: catalog,
		Scanner: scanner,
		Method:  root["method"],
		checks:  checks,
	}, nil
}

// validateCatalog reports the declared revision and whether it can be used for
// catalog lookups. An unusable revision suppresses per-candidate existence
// checks, so one missing declaration does not also report every candidate as
// unknown.
func (v *validator) validateCatalog(catalog map[string]any) (Catalog, bool) {
	source, _ := v.str(catalog, "source", "/catalog/source")
	commit, ok := v.str(catalog, "pinned_commit", "/catalog/pinned_commit")
	if !ok || commit == "" {
		v.add(FaultCatalogCommitMissing, "/catalog/pinned_commit",
			"an unpinned catalog cannot be re-derived, so the scores are unreproducible")
	}
	out := Catalog{Source: source, PinnedCommit: commit}

	raw, present := v.number(catalog, "revision", "/catalog/revision")
	if !present {
		if _, declared := catalog["revision"]; !declared {
			v.add(FaultCatalogRevisionMissing, "/catalog/revision",
				fmt.Sprintf("declare the NIST SP 800-53 revision the corpus was indexed against, one of %v", nist.SupportedRevisions()))
		}
		return out, false
	}
	// JSON has one number type, so a revision written 5.0 is the integer the
	// contract asks for; 5.5 is not.
	if raw != math.Trunc(raw) {
		v.add(FaultFieldTypeInvalid, "/catalog/revision",
			fmt.Sprintf("want a JSON integer, got the fractional number %v", raw))
		return out, false
	}
	out.Revision = int(raw)
	for _, supported := range nist.SupportedRevisions() {
		if out.Revision == supported {
			return out, true
		}
	}
	v.add(FaultCatalogRevisionUnsup, "/catalog/revision",
		fmt.Sprintf("revision %d is not one this repo carries a catalog for %v", out.Revision, nist.SupportedRevisions()))
	return out, false
}

func (v *validator) validateScanner(scanner map[string]any) Scanner {
	name, ok := v.str(scanner, "name", "/scanner/name")
	if !ok || trimBlank(name) == "" {
		v.add(FaultScannerNameMissing, "/scanner/name", "the scanner name keys the published mapping")
	}
	raw, versionOK := v.str(scanner, "version", "/scanner/version")
	version := trimBlank(raw)
	out := Scanner{Name: name, Version: raw, Checks: v.checkCount(scanner)}
	if !versionOK || version == "" {
		v.add(FaultScannerVersionMissing, "/scanner/version",
			"the scanner stamps its version into its own reports, so a corpus must name the one it scored")
		return out
	}
	// Accept an image reference and judge its tag, since that is how upstream
	// records the scanner it ran.
	tag := version
	if i := strings.LastIndex(version, ":"); i >= 0 {
		tag = version[i+1:]
	}
	if floatingTags[strings.ToLower(tag)] {
		v.add(FaultScannerVersionFloating, "/scanner/version",
			fmt.Sprintf("%q names no specific release, leaving the set of checks scored unknowable", version))
	}
	return out
}

// checkCount reads the scanner's catalog size, which the contract declares a
// non-negative integer. Truncating a fractional value instead would let an
// accepted document mean different things in the two languages.
func (v *validator) checkCount(scanner map[string]any) int {
	count, present := v.number(scanner, "checks", "/scanner/checks")
	if !present {
		return 0
	}
	if count != math.Trunc(count) || count < 0 || count > maxCheckCount {
		v.add(FaultFieldTypeInvalid, "/scanner/checks",
			fmt.Sprintf("want a JSON integer in 0..%d, got %v", maxCheckCount, count))
		return 0
	}
	return int(count)
}

func (v *validator) validateCandidates(list []any, base string, revision int, revisionUsable bool) []Candidate {
	out := make([]Candidate, 0, len(list))
	for i, entry := range list {
		path := fmt.Sprintf("%s/candidates/%d", base, i)
		raw := v.object(map[string]any{"candidate": entry}, "candidate", path)
		cand := Candidate{}
		if title, ok := v.str(raw, "control_title", path+"/control_title"); ok {
			cand.ControlTitle = title
		}
		if matched, ok := v.array(raw, "matched_on", path+"/matched_on"); ok {
			for j, m := range matched {
				if text, present := v.field(map[string]any{"m": m}, "m", fmt.Sprintf("%s/matched_on/%d", path, j), "string"); present {
					cand.MatchedOn = append(cand.MatchedOn, text.(string))
				}
			}
		}

		// Declared a number by the contract and carried upstream for
		// provenance. Read so a mistyped one is refused, not for its value.
		v.number(raw, "raw", path+"/raw")

		control, ok := v.str(raw, "control", path+"/control")
		if !ok || trimBlank(control) == "" {
			v.add(FaultControlMissing, path+"/control", "a candidate without a control id suggests nothing")
		} else {
			cand.Control = control
			cand.NormalizedControl = v.validateControl(control, path+"/control", revision, revisionUsable)
		}

		score, present := v.number(raw, "score", path+"/score")
		switch {
		case !present:
			if _, declared := raw["score"]; !declared {
				v.add(FaultScoreMissing, path+"/score", "an unscored candidate cannot be ranked, and absent must not read as 0.0")
			}
		case score < 0 || score > 1:
			v.add(FaultScoreRange, path+"/score",
				fmt.Sprintf("score %v is outside the normalised 0..1 range the method declares", score))
		default:
			cand.Score = score
		}
		out = append(out, cand)
	}
	return out
}

// validateControl reports the canonical spelling of control, or "" when the id
// is not usable. A control absent at the declared revision but present at
// another is named distinctly, because the remedy is a revision declaration or
// a crosswalk translation rather than a data correction.
func (v *validator) validateControl(control, path string, revision int, revisionUsable bool) string {
	normalized, ok := nist.NormalizeID(dotEnhancement.ReplaceAllString(control, " ($1)"))
	if !ok {
		v.add(FaultControlUnspellable, path, fmt.Sprintf("%q is not a NIST SP 800-53 id spelling", control))
		return ""
	}
	if !revisionUsable {
		return normalized
	}
	if nist.NistExistsForRevision(normalized, revision) {
		return normalized
	}
	for _, other := range nist.SupportedRevisions() {
		if other != revision && nist.NistExistsForRevision(normalized, other) {
			v.add(FaultControlWrongRevision, path, fmt.Sprintf(
				"%q is defined at revision %d, not the declared revision %d; declare the revision the corpus was indexed against or translate it through the Rev 4 to Rev 5 crosswalk",
				control, other, revision))
			return normalized
		}
	}
	v.add(FaultControlUnknown, path, fmt.Sprintf("NIST defines no control %q at any supported revision %v", control, nist.SupportedRevisions()))
	return normalized
}

// validateRevisionConsistency reports when no single supported revision defines
// every candidate id. It runs whether or not a revision was declared, because
// a corpus that declares none is exactly the one whose catalog needs checking:
// a mixed catalog is a defect in how the corpus was indexed, not in the
// declaration, and it silently skews every score computed over it.
func (v *validator) validateRevisionConsistency(checks map[string]Check) {
	// An id no revision defines is reported as unknown and says nothing about
	// which catalog was indexed, so it is left out of the analysis.
	ids := make([]string, 0, len(checks))
	seen := map[string]bool{}
	for _, id := range sortedKeys(checks) {
		for _, cand := range checks[id].Candidates {
			norm := cand.NormalizedControl
			if norm == "" || seen[norm] || !existsAtAnyRevision(norm) {
				continue
			}
			seen[norm] = true
			ids = append(ids, norm)
		}
	}
	if len(ids) == 0 {
		return
	}

	revisions := nist.SupportedRevisions()
	misses := make(map[int][]string, len(revisions))
	for _, rev := range revisions {
		for _, id := range ids {
			if !nist.NistExistsForRevision(id, rev) {
				misses[rev] = append(misses[rev], id)
			}
		}
		if len(misses[rev]) == 0 {
			return
		}
	}

	parts := make([]string, 0, len(revisions))
	for _, rev := range revisions {
		parts = append(parts, fmt.Sprintf("revision %d does not define %d of them (e.g. %s)",
			rev, len(misses[rev]), misses[rev][0]))
	}
	v.add(FaultCatalogRevisionMixed, "/catalog/revision", fmt.Sprintf(
		"no supported revision defines all %d candidate control ids, so the corpus was indexed against a mixed catalog: %s",
		len(ids), strings.Join(parts, "; ")))
}

func existsAtAnyRevision(normalized string) bool {
	for _, rev := range nist.SupportedRevisions() {
		if nist.NistExistsForRevision(normalized, rev) {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// escapePointer escapes a JSON Pointer reference token (RFC 6901 §3).
func escapePointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}
