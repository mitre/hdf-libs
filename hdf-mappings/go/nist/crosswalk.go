package nist

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/datasets"
)

// Relations a Translation can carry. Identity means the control exists at both
// revisions under the same ID. Moved/incorporated/pointer/family come from
// NIST's own comparison workbooks; none means NIST names no successor; unknown
// means the control is not part of the source revision's catalog (or the
// revision pair is unsupported).
const (
	RelationIdentity     = "identity"
	RelationMoved        = "moved"
	RelationIncorporated = "incorporated"
	RelationPointer      = "pointer"
	RelationFamily       = "family"
	RelationNone         = "none"
	RelationUnknown      = "unknown"
)

// Translation is the outcome of mapping one control ID across revisions.
type Translation struct {
	Control  string
	Targets  []string
	Relation string
	// Family is set only for RelationFamily ("incorporated into <XX> family"):
	// a marker, deliberately never expanded into member controls.
	Family string
	// Detail preserves NIST's raw comparison text for redirects.
	Detail string
}

type crosswalkEdge struct {
	From     int      `json:"from"`
	Control  string   `json:"control"`
	Targets  []string `json:"targets"`
	Relation string   `json:"relation"`
	Family   string   `json:"family,omitempty"`
	Detail   string   `json:"detail"`
}

// Set by TestCrosswalkParseFailure in a child process to drive the parse-failure
// path; nil means the embedded dataset. Declared without an initialiser so the
// linker can still drop the dataset from a consumer that never translates.
var crosswalkData []byte

func crosswalkBytes() []byte {
	if crosswalkData != nil {
		return crosswalkData
	}
	return datasets.NISTRevisionCrosswalk
}

var (
	xwRosters    map[int]map[string]bool
	xwEdges      map[int]map[string]*crosswalkEdge
	xwOnce       sync.Once
	errCrosswalk error
)

func loadCrosswalk() {
	xwOnce.Do(func() {
		var file struct {
			Rosters map[string][]string `json:"rosters"`
			Edges   []crosswalkEdge     `json:"edges"`
		}
		if err := json.Unmarshal(crosswalkBytes(), &file); err != nil {
			errCrosswalk = fmt.Errorf("parse embedded nist-revision-crosswalk.json: %w", err)
			return
		}
		xwRosters = make(map[int]map[string]bool)
		xwEdges = make(map[int]map[string]*crosswalkEdge)
		for revStr, ids := range file.Rosters {
			rev, err := strconv.Atoi(revStr)
			if err != nil {
				continue
			}
			xwRosters[rev] = make(map[string]bool, len(ids))
			for _, id := range ids {
				xwRosters[rev][id] = true
			}
		}
		for i := range file.Edges {
			e := &file.Edges[i]
			if xwEdges[e.From] == nil {
				xwEdges[e.From] = make(map[string]*crosswalkEdge)
			}
			xwEdges[e.From][e.Control] = e
		}
	})
	// Keep failed initialization visible even if a caller recovers the panic.
	if errCrosswalk != nil {
		panic(errCrosswalk)
	}
}

// A trailing single-letter statement part, e.g. "AC-2(j)".
var statementLetter = regexp.MustCompile(`^(.*)\(([a-z])\)$`)

// Translate maps one NIST control ID between 800-53 revisions 4 and 5. A
// control present in both revisions translates to itself (identity); withdrawn,
// moved, incorporated, and Appendix J controls follow NIST's published
// successors; a control with no equivalent at the target revision gets
// RelationNone and no targets. Statement-letter suffixes ("AC-2(j)") survive
// identity translation and are dropped on redirects.
func Translate(control string, from, to int) Translation {
	loadCrosswalk()
	tr := Translation{Control: control, Relation: RelationUnknown}
	if control == "" || !supportedRevision(from) || !supportedRevision(to) {
		return tr
	}
	if from == to {
		tr.Relation = RelationIdentity
		tr.Targets = []string{control}
		return tr
	}
	if e := xwEdges[from][control]; e != nil {
		return translationFromEdge(control, e)
	}
	if xwRosters[from][control] && xwRosters[to][control] {
		tr.Relation = RelationIdentity
		tr.Targets = []string{control}
		return tr
	}
	if m := statementLetter.FindStringSubmatch(control); m != nil {
		base := m[1]
		if e := xwEdges[from][base]; e != nil {
			return translationFromEdge(control, e)
		}
		if xwRosters[from][base] && xwRosters[to][base] {
			tr.Relation = RelationIdentity
			tr.Targets = []string{control}
			return tr
		}
	}
	return tr
}

func translationFromEdge(control string, e *crosswalkEdge) Translation {
	targets := make([]string, len(e.Targets))
	copy(targets, e.Targets)
	return Translation{
		Control:  control,
		Targets:  targets,
		Relation: e.Relation,
		Family:   e.Family,
		Detail:   e.Detail,
	}
}

// TranslateControls maps a list of control IDs between revisions, flattening
// redirect targets and deduplicating while preserving first-seen order.
// Controls with no target at the destination revision (withdrawn without
// successor, family-level, or unknown) are returned in unmapped, in input
// order, so callers can surface them instead of silently dropping.
func TranslateControls(controls []string, from, to int) (translated []string, unmapped []Translation) {
	seen := make(map[string]bool)
	for _, c := range controls {
		tr := Translate(c, from, to)
		if len(tr.Targets) == 0 {
			unmapped = append(unmapped, tr)
			continue
		}
		for _, t := range tr.Targets {
			if !seen[t] {
				seen[t] = true
				translated = append(translated, t)
			}
		}
	}
	return translated, unmapped
}

// A NIST-shaped base at the start of a longer reference, e.g. "AC-1 a",
// "AC-1.2 (i)", "SA-12 b 1", "AU-8 (1) (a)" — DISA-CCI statement-reference
// styles, which write an enhancement with a space before its parenthesis.
var baseControl = regexp.MustCompile(`^([A-Z]{2}-\d+)(?:( ?)\((\d+)\))?`)

// spacedEnhancement matches a crosswalk target's enhancement, "SC-45(1)".
var spacedEnhancement = regexp.MustCompile(`^([A-Z]{2}-\d+)\((\d+)\)`)

// AtRevision translates a control list authored against nativeRev into rev.
// Identity when the revisions are equal (or either is unsupported). Per token:
// the crosswalk redirect is followed when one exists; statement-style suffixes
// ("AC-1 a", "AC-1.2 (i)") are kept on identity and dropped on redirects;
// tokens with no equivalent at the target revision are dropped (the analog of
// the awsconfig empty-NIST-ID marker); tokens outside both NIST catalogs
// (tool placeholders like "UM-1") pass through unchanged — they are not ours
// to drop. Output is deduplicated preserving first-seen order.
func AtRevision(controls []string, nativeRev, rev int) []string {
	if nativeRev == rev || !supportedRevision(nativeRev) || !supportedRevision(rev) {
		return controls
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(controls))
	add := func(c string) {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, c := range controls {
		tr := Translate(c, nativeRev, rev)
		if tr.Relation != RelationUnknown {
			for _, t := range tr.Targets {
				add(t)
			}
			continue
		}
		if targets, ok := translateBase(c, nativeRev, rev); ok {
			for _, t := range targets {
				add(t)
			}
			continue
		}
		add(c)
	}
	return out
}

// translateBase translates the control a longer reference starts with. A
// spaced enhancement ("AU-8 (1) (a)") is tried as "AU-8(1)" and, when the
// crosswalk does not list it, as its base control "AU-8"; redirect targets keep
// the reference's spacing. ok is false when no candidate is known, so the
// caller passes the reference through.
func translateBase(c string, nativeRev, rev int) (targets []string, ok bool) {
	m := baseControl.FindStringSubmatch(c)
	if m == nil {
		return nil, false
	}
	spaced := m[2] == " "
	var candidates []string
	if m[3] != "" {
		candidates = append(candidates, m[1]+"("+m[3]+")")
	}
	if m[3] == "" || spaced {
		candidates = append(candidates, m[1])
	}
	for _, base := range candidates {
		if base == c {
			continue
		}
		switch btr := Translate(base, nativeRev, rev); btr.Relation {
		case RelationIdentity:
			return []string{c}, true
		case RelationUnknown:
			continue
		default:
			for _, t := range btr.Targets {
				if spaced {
					t = spacedEnhancement.ReplaceAllString(t, "$1 ($2)")
				}
				targets = append(targets, t)
			}
			return targets, true
		}
	}
	return nil, false
}

// The control and optional spaced enhancement a Revision 3 reference starts
// with, and what may follow it: statement parts ("a", "1", "(a)"), the CCI
// table's grammar.
var (
	rev3Control    = regexp.MustCompile(`^([A-Z]{2}-\d+)(?: \((\d+)\))?`)
	statementParts = regexp.MustCompile(`^(?: (?:[a-z]{1,2}|\d+|\([a-z0-9]+\)))*$`)
)

// AtRevisionFromRev3 reads 800-53 Revision 3 references, in DISA's spacing, at
// rev, as a control or enhancement: a Revision 3 statement letter is not kept,
// because Revision 4 re-letters. Each is first placed at Revision 4 from NIST's
// Revision 4 catalog: redirected where that catalog lists it as withdrawn (an
// enhancement of a withdrawn control follows the control), kept where Revision
// 4 still has it. Then it is translated as any Revision 4 reference is. A
// reference Revision 4 does not know, or withdrew with no control successor, is
// dropped.
func AtRevisionFromRev3(controls []string, rev int) []string {
	if !supportedRevision(rev) {
		return []string{}
	}
	loadCrosswalk()
	withdrawn := loadRev4Withdrawn()
	seen := make(map[string]bool)
	atRev4 := make([]string, 0, len(controls))
	for _, c := range controls {
		for _, placed := range placeRev3AtRev4(c, withdrawn) {
			if !seen[placed] {
				seen[placed] = true
				atRev4 = append(atRev4, placed)
			}
		}
	}
	return AtRevision(atRev4, 4, rev)
}

// placeRev3AtRev4 is one Revision 3 reference as Revision 4 names it, in DISA's
// spacing. The withdrawn table is read before the roster: the crosswalk's
// Revision 4 roster lists a few identifiers Revision 4 withdrew.
func placeRev3AtRev4(c string, withdrawn map[string][]string) []string {
	m := rev3Control.FindStringSubmatch(c)
	if m == nil || !statementParts.MatchString(c[len(m[0]):]) {
		return nil
	}
	spaced := func(ids ...string) []string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = spacedEnhancement.ReplaceAllString(id, "$1 ($2)")
		}
		return out
	}
	key := m[1]
	if m[2] != "" {
		key = m[1] + "(" + m[2] + ")"
	}
	if targets, ok := withdrawn[key]; ok {
		return spaced(targets...)
	}
	if xwRosters[4][key] {
		return spaced(key)
	}
	if targets, ok := withdrawn[m[1]]; ok && key != m[1] {
		return spaced(targets...)
	}
	return nil
}

var (
	rev4Withdrawn     map[string][]string
	rev4WithdrawnOnce sync.Once
)

// loadRev4Withdrawn parses the embedded table once. A parse failure is a build
// defect in an embedded asset, handled as the crosswalk's is.
func loadRev4Withdrawn() map[string][]string {
	rev4WithdrawnOnce.Do(func() {
		var doc struct {
			Withdrawn map[string][]string `json:"withdrawn"`
		}
		if err := json.Unmarshal(datasets.NISTRev4Withdrawn, &doc); err != nil {
			panic(fmt.Errorf("embedded nist-rev4-withdrawn.json: %w", err))
		}
		rev4Withdrawn = doc.Withdrawn
	})
	return rev4Withdrawn
}

// RosterSize returns the number of control IDs in the crosswalk's catalog for
// the given revision, or 0 for unsupported revisions.
func RosterSize(rev int) int {
	loadCrosswalk()
	return len(xwRosters[rev])
}

func supportedRevision(rev int) bool {
	for _, r := range SupportedRevisions() {
		if r == rev {
			return true
		}
	}
	return false
}
