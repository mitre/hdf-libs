package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func makeReq(id string) hdf.EvaluatedRequirement {
	return hdf.EvaluatedRequirement{ID: id}
}

func TestBuildUniqueIDIndex_NoDuplicates(t *testing.T) {
	reqs := []hdf.EvaluatedRequirement{
		makeReq("A"),
		makeReq("B"),
		makeReq("C"),
	}
	byID, duplicates := buildUniqueIDIndex(reqs)

	if len(duplicates) != 0 {
		t.Errorf("expected no duplicates, got %v", duplicates)
	}
	if len(byID) != 3 {
		t.Errorf("expected 3 entries in byID, got %d", len(byID))
	}
	for _, id := range []string{"A", "B", "C"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("expected %q in byID", id)
		}
	}
}

func TestBuildUniqueIDIndex_WithDuplicates(t *testing.T) {
	reqs := []hdf.EvaluatedRequirement{
		makeReq("A"),
		makeReq("B"),
		makeReq("A"),
		makeReq("C"),
		makeReq("C"),
		makeReq("C"),
	}
	byID, duplicates := buildUniqueIDIndex(reqs)

	if len(duplicates) != 2 {
		t.Errorf("expected 2 duplicate IDs, got %d: %v", len(duplicates), duplicates)
	}
	if !duplicates["A"] {
		t.Error("expected 'A' to be marked as duplicate")
	}
	if !duplicates["C"] {
		t.Error("expected 'C' to be marked as duplicate")
	}
	// Only B should remain in byID
	if len(byID) != 1 {
		t.Errorf("expected 1 entry in byID (only B), got %d", len(byID))
	}
	if _, ok := byID["B"]; !ok {
		t.Error("expected 'B' in byID")
	}
}

func TestBuildUniqueIDIndex_Empty(t *testing.T) {
	byID, duplicates := buildUniqueIDIndex(nil)

	if len(byID) != 0 {
		t.Errorf("expected empty byID, got %d entries", len(byID))
	}
	if len(duplicates) != 0 {
		t.Errorf("expected empty duplicates, got %d entries", len(duplicates))
	}
}

func TestBuildUniqueIDIndex_AllDuplicates(t *testing.T) {
	reqs := []hdf.EvaluatedRequirement{
		makeReq("X"),
		makeReq("X"),
	}
	byID, duplicates := buildUniqueIDIndex(reqs)

	if len(duplicates) != 1 {
		t.Errorf("expected 1 duplicate, got %d", len(duplicates))
	}
	if len(byID) != 0 {
		t.Errorf("expected empty byID, got %d entries", len(byID))
	}
}

func TestBuildUniqueIDIndex_PreservesFirstIndex(t *testing.T) {
	reqs := []hdf.EvaluatedRequirement{
		makeReq("A"),
		makeReq("B"),
		makeReq("C"),
	}
	byID, _ := buildUniqueIDIndex(reqs)

	if byID["A"] != 0 {
		t.Errorf("expected A at index 0, got %d", byID["A"])
	}
	if byID["B"] != 1 {
		t.Errorf("expected B at index 1, got %d", byID["B"])
	}
	if byID["C"] != 2 {
		t.Errorf("expected C at index 2, got %d", byID["C"])
	}
}
