package cci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/datasets"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

// An 800-53 control identifier as DISA's CCI list writes it: family-number, an
// optional enhancement, then statement parts. The TypeScript twin and the
// generator script carry the same pattern.
var controlIdentifier = regexp.MustCompile(`^[A-Z]{2}-\d+(?: \(\d+\))?(?: (?:[a-z]{1,2}|\d+|\([a-z0-9]+\)))*$`)

func TestCCIToNISTReturnsControlIdentifiersOnly(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader(datasets.CCIMappings))
	dec.DisallowUnknownFields()
	var table map[string]struct {
		Def  string              `json:"def"`
		Nist map[string][]string `json:"nist"`
	}
	require.NoError(t, dec.Decode(&table))
	require.Greater(t, len(table), 5000, "DISA's 2025-01-23 list has 5,137 items")

	for id, item := range table {
		for rev, refs := range item.Nist {
			assert.Contains(t, []string{"3", "4", "5"}, rev, "%s: revision key", id)
			if rev == "3" {
				assert.Len(t, item.Nist, 1, "%s: Rev 3 is kept only when DISA gives no later reference", id)
			}
			assert.NotEmpty(t, refs, "%s Rev %s: an empty list should be omitted", id, rev)
			seen := map[string]bool{}
			for _, ref := range refs {
				assert.Regexp(t, controlIdentifier, ref, "%s Rev %s", id, rev)
				assert.False(t, seen[ref], "%s Rev %s: duplicate %q", id, rev, ref)
				seen[ref] = true
			}
		}
	}
}

// Expected values are DISA's U_CCI_List.xml (version 2025-01-23) entries for
// each CCI, or NIST's crosswalk successor where DISA gives no reference.
func TestGetCCINistMappingsForRevision_FromDISA(t *testing.T) {
	tests := []struct {
		name string
		cci  string
		rev  int
		want []string
	}{
		{"Rev 5 reference", "CCI-000054", 5, []string{"AC-10"}},
		{"Rev 4 reference", "CCI-000054", 4, []string{"AC-10"}},
		{"Rev 5 reference", "CCI-001133", 5, []string{"SC-10"}},
		{"Rev 5 part kept as published", "CCI-004192", 5, []string{"MA-4 (4) (b) (2)"}},
		{"Rev 5 only, identity at Rev 4 keeps the part", "CCI-004192", 4, []string{"MA-4 (4) (b) (2)"}},
		{"two Rev 5 references", "CCI-002153", 5, []string{"AC-3 (3)", "AC-3 (15) (a)"}},
		{"Rev 4 only, withdrawn enhancement follows the crosswalk", "CCI-000262", 5, []string{"SC-7 (25)"}},
		{"Rev 4 only, withdrawn enhancement incorporated into its base", "CCI-000127", 5, []string{"AU-2"}},
		{"Rev 4 only, at Rev 4", "CCI-000262", 4, []string{"CA-3 (1)"}},
		{"deprecated item with a Rev 5 reference", "CCI-003658", 5, []string{"AC-3 (15) (a)"}},
		{"malformed Rev 4 reference rejected, Rev 5 translated", "CCI-000504", 4, []string{"CP-4 (4)"}},
		{"Rev 3 only, read as its control, without the Rev 3 statement letter", "CCI-000007", 5, []string{"AC-2"}},
		{"Rev 3 only, read as its control, without the Rev 3 statement letter", "CCI-000007", 4, []string{"AC-2"}},
		{"Rev 3 only, withdrawn by Rev 4, follows the crosswalk", "CCI-001435", 5, []string{"CM-7"}},
		{"Rev 3 only, withdrawn by Rev 4, follows the crosswalk", "CCI-001435", 4, []string{"CM-7"}},
		{"Rev 3 only, a Rev 4 control that Rev 5 moved", "CCI-000160", 4, []string{"AU-8 (1)"}},
		{"Rev 3 only, a Rev 4 control that Rev 5 moved", "CCI-000160", 5, []string{"SC-45 (1)"}},
		{"Rev 3 only, withdrawn with no successor", "CCI-000554", 5, []string{}},
		{"Rev 3 is not a revision to ask for: the stored reference is not handed back raw", "CCI-001435", 3, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name+" "+tt.cci, func(t *testing.T) {
			assert.Equal(t, tt.want, GetCCINistMappingsForRevision(tt.cci, tt.rev))
		})
	}
}

func TestGetCCINistMappings_UsesTheProcessRevision(t *testing.T) {
	assert.Equal(t, []string{"SC-7 (25)"}, GetCCINistMappings("CCI-000262"))
	require.NoError(t, nist.SetRevision(4))
	defer nist.ResetRevision()
	assert.Equal(t, []string{"CA-3 (1)"}, GetCCINistMappings("CCI-000262"))
}

// Every Rev 5 value resolves in NIST's Rev 5 catalog except these. The first
// eight keep a Rev 4 statement part on an identity translation that Rev 5 does
// not number; the last two are DISA's own Rev 5 references.
var knownRev5CatalogGaps = map[string]bool{
	"AU-1 b 1":     true,
	"AU-1 b 2":     true,
	"IA-4 e":       true,
	"IA-5 (2) (d)": true,
	"PE-20 b":      true,
	"PE-5 (2) (a)": true,
	"PE-5 (2) (b)": true,
	"PS-4 f":       true,
	"SI-18 b 1":    true,
	"SI-7 (13)":    true,
}

// A CCI that DISA references only at Revision 3 still maps to a control at both
// supported revisions, except where NIST names no single successor control.
var rev3NoSuccessor = map[string]string{
	"CCI-000554@4": "CP-10 (3): withdrawn before Rev 4, addressed through tailoring",
	"CCI-000554@5": "CP-10 (3): withdrawn before Rev 4, addressed through tailoring",
	"CCI-000555@4": "CP-10 (3): withdrawn before Rev 4, addressed through tailoring",
	"CCI-000555@5": "CP-10 (3): withdrawn before Rev 4, addressed through tailoring",
	"CCI-001302@5": "SI-7 (4): into SA-12 at Rev 4, which Rev 5 moved to the SR family",
	"CCI-001303@5": "SI-7 (4): into SA-12 at Rev 4, which Rev 5 moved to the SR family",
	"CCI-001304@5": "SI-7 (4): into SA-12 at Rev 4, which Rev 5 moved to the SR family",
}

func TestEveryRev3OnlyCCIMapsToAControl(t *testing.T) {
	var table map[string]struct {
		Nist map[string][]string `json:"nist"`
	}
	require.NoError(t, json.Unmarshal(datasets.CCIMappings, &table))
	seen := map[string]bool{}
	rev3Only := 0
	for id, item := range table {
		if len(item.Nist["3"]) == 0 {
			continue
		}
		rev3Only++
		for _, rev := range []int{4, 5} {
			if len(GetCCINistMappingsForRevision(id, rev)) > 0 {
				continue
			}
			key := fmt.Sprintf("%s@%d", id, rev)
			assert.Contains(t, rev3NoSuccessor, key, "%s maps to no control at Rev %d", id, rev)
			seen[key] = true
		}
	}
	assert.Equal(t, 551, rev3Only, "DISA's 2025-01-23 list has 551 items with only a Rev 3 reference")
	assert.Equal(t, []string{"MA-2 (1)"}, table["CCI-000863"].Nist["3"], "malformed statement parts keep the enhancement")
	for key := range rev3NoSuccessor {
		assert.True(t, seen[key], "%s now maps to a control; drop it from rev3NoSuccessor", key)
	}
}

func TestCCIRev5MappingsResolveInTheCatalog(t *testing.T) {
	seenGaps := map[string]bool{}
	for _, id := range GetAllCCIIDs() {
		for _, c := range GetCCINistMappingsForRevision(id, 5) {
			if nist.NistExistsForRevision(c, 5) {
				continue
			}
			assert.True(t, knownRev5CatalogGaps[c], "%s: %q is not in the Rev 5 catalog", id, c)
			seenGaps[c] = true
		}
	}
	for gap := range knownRev5CatalogGaps {
		assert.True(t, seenGaps[gap], "%q no longer occurs; drop it from knownRev5CatalogGaps", gap)
	}
}
