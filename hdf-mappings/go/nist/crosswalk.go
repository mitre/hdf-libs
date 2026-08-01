package nist

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"sync"
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

//go:embed nist-revision-crosswalk.json
var crosswalkData []byte

type crosswalkEdge struct {
	From     int      `json:"from"`
	Control  string   `json:"control"`
	Targets  []string `json:"targets"`
	Relation string   `json:"relation"`
	Family   string   `json:"family,omitempty"`
	Detail   string   `json:"detail"`
}

var (
	xwRosters map[int]map[string]bool
	xwEdges   map[int]map[string]*crosswalkEdge
	xwOnce    sync.Once
)

func loadCrosswalk() {
	xwOnce.Do(func() {
		var file struct {
			Rosters map[string][]string `json:"rosters"`
			Edges   []crosswalkEdge     `json:"edges"`
		}
		xwRosters = make(map[int]map[string]bool)
		xwEdges = make(map[int]map[string]*crosswalkEdge)
		if err := json.Unmarshal(crosswalkData, &file); err != nil {
			return
		}
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
