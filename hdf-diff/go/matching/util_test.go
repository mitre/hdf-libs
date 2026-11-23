package matching

import (
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func makeReq(id string) hdf.EvaluatedRequirement {
	return hdf.EvaluatedRequirement{ID: id}
}

func makeReqWithCode(id, code string) hdf.EvaluatedRequirement {
	return hdf.EvaluatedRequirement{ID: id, Code: &code}
}

// These once asserted the superseded rule: buildUniqueIDIndex DELETED an id on its second
// occurrence, leaving every occurrence unmatched. They now assert that a repeated id is
// kept and its occurrences paired among themselves.

func TestBuildIDIndex_NoDuplicates(t *testing.T) {
	reqs := []hdf.EvaluatedRequirement{makeReq("A"), makeReq("B"), makeReq("C")}

	byID := buildIDIndex(reqs)

	if len(byID) != 3 {
		t.Errorf("expected 3 ids, got %d", len(byID))
	}
	for i, id := range []string{"A", "B", "C"} {
		if got := byID[id]; len(got) != 1 || got[0] != i {
			t.Errorf("expected %q at [%d], got %v", id, i, got)
		}
	}
}

func TestBuildIDIndex_WithDuplicates(t *testing.T) {
	reqs := []hdf.EvaluatedRequirement{
		makeReq("A"), makeReq("B"), makeReq("A"), makeReq("C"), makeReq("C"), makeReq("C"),
	}

	byID := buildIDIndex(reqs)

	// Every id is kept, with every position it occupies, in document order.
	for id, want := range map[string][]int{"A": {0, 2}, "B": {1}, "C": {3, 4, 5}} {
		got := byID[id]
		if len(got) != len(want) {
			t.Errorf("%q: expected %v, got %v", id, want, got)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q: expected %v, got %v", id, want, got)
				break
			}
		}
	}
}

func TestBuildIDIndex_Empty(t *testing.T) {
	if byID := buildIDIndex(nil); len(byID) != 0 {
		t.Errorf("expected an empty index, got %d ids", len(byID))
	}
}

func TestContentKey_SeparatesOccurrencesThatDiffer(t *testing.T) {
	a := makeReqWithCode("X", "control 'X' do\n  describe file('/a') do\nend")
	b := makeReqWithCode("X", "control 'X' do\n  describe file('/b') do\nend")

	if contentKey(a) == contentKey(b) {
		t.Error("expected a different key for occurrences whose code differs")
	}
	if contentKey(a) != contentKey(makeReqWithCode("X", *a.Code)) {
		t.Error("expected equal content to produce one key")
	}
}

func TestContentKey_IgnoresPerRunResults(t *testing.T) {
	// results[] carries startTime and runTime, so including it would separate two runs of
	// the same occurrence and pair neither with the other.
	a := makeReqWithCode("X", "same")
	b := makeReqWithCode("X", "same")
	a.Results = []hdf.RequirementResult{{StartTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
	b.Results = []hdf.RequirementResult{{StartTime: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)}}

	if contentKey(a) != contentKey(b) {
		t.Error("expected results[] not to contribute to the key")
	}
}

func TestPairOccurrences_PairsByContentAcrossAReorder(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{makeReqWithCode("X", "a"), makeReqWithCode("X", "b")}
	newReqs := []hdf.EvaluatedRequirement{makeReqWithCode("X", "b"), makeReqWithCode("X", "a")}

	pairs, surplusOld, surplusNew := pairOccurrences([]int{0, 1}, []int{0, 1}, oldReqs, newReqs)

	if len(pairs) != 2 || len(surplusOld) != 0 || len(surplusNew) != 0 {
		t.Fatalf("expected 2 pairs and no surplus, got %v / %v / %v", pairs, surplusOld, surplusNew)
	}
	for _, p := range pairs {
		if *oldReqs[p[0]].Code != *newReqs[p[1]].Code {
			t.Errorf("paired %q with %q", *oldReqs[p[0]].Code, *newReqs[p[1]].Code)
		}
	}
}

func TestPairOccurrences_PairsIndistinguishableOccurrencesInOrder(t *testing.T) {
	// Equal content keys, so these pair through the key's queue in document order rather
	// than through the cross-key positional fallback, which only a partial content match
	// reaches.
	reqs := []hdf.EvaluatedRequirement{makeReq("X"), makeReq("X")}

	pairs, surplusOld, surplusNew := pairOccurrences([]int{0, 1}, []int{0, 1}, reqs, reqs)

	if len(pairs) != 2 || len(surplusOld) != 0 || len(surplusNew) != 0 {
		t.Fatalf("expected 2 pairs and no surplus, got %v / %v / %v", pairs, surplusOld, surplusNew)
	}
}

func TestPairOccurrences_ReportsSurplusOnEitherSide(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{makeReqWithCode("X", "a"), makeReqWithCode("X", "b")}
	newReqs := []hdf.EvaluatedRequirement{makeReqWithCode("X", "a")}

	pairs, surplusOld, surplusNew := pairOccurrences([]int{0, 1}, []int{0}, oldReqs, newReqs)
	if len(pairs) != 1 || len(surplusOld) != 1 || len(surplusNew) != 0 {
		t.Fatalf("old surplus: got %v / %v / %v", pairs, surplusOld, surplusNew)
	}
	if surplusOld[0] != 1 {
		t.Errorf("expected the unmatched old occurrence to be index 1, got %d", surplusOld[0])
	}

	pairs, surplusOld, surplusNew = pairOccurrences([]int{0}, []int{0, 1}, newReqs, oldReqs)
	if len(pairs) != 1 || len(surplusOld) != 0 || len(surplusNew) != 1 {
		t.Fatalf("new surplus: got %v / %v / %v", pairs, surplusOld, surplusNew)
	}
}
