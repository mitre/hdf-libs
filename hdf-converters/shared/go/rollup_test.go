package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func strp(s string) *string { return &s }

// grypeDuplicatePair mirrors the two committed grype golden entries for
// Grype/CVE-2022-48174 (busybox@1.31.1-r9 and ssl_client@1.31.1-r9 in
// converters/grype-to-hdf/fixtures/expected/anchore_grype.json.hdf.json): one
// CVE reported against two packages, emitted today as two requirements.
func grypeDuplicatePair() []hdf.EvaluatedRequirement {
	mk := func(pkg, purl, codeDesc string) hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{
			ID:     "Grype/CVE-2022-48174",
			Impact: 0.9,
			Tags:   map[string]interface{}{},
			Descriptions: []hdf.Description{
				{Label: "default", Data: "There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35."},
			},
			AffectedPackages: []hdf.AffectedPackage{
				{Name: strp(pkg), Version: strp("1.31.1-r9"), Purl: strp(purl)},
			},
			Results: []hdf.RequirementResult{{CodeDesc: codeDesc, Status: hdf.ResultStatus("failed")}},
		}
	}
	return []hdf.EvaluatedRequirement{
		mk("busybox", "pkg:apk/alpine/busybox@1.31.1-r9?arch=aarch64&distro=alpine-3.11.3",
			"Package: busybox@1.31.1-r9 | Type: apk | Location: /lib/apk/db/installed | Match Type: cpe-match"),
		mk("ssl_client", "pkg:apk/alpine/ssl_client@1.31.1-r9?arch=aarch64&upstream=busybox&distro=alpine-3.11.3",
			"Package: ssl_client@1.31.1-r9 | Type: apk | Location: /lib/apk/db/installed | Match Type: cpe-match"),
	}
}

// ADR-0017 §6: results concatenate in source order; affectedPackages union,
// de-duplicated on purl where present.
func TestRollUpRequirements_ConcatenatesResultsAndUnionsAffectedPackages(t *testing.T) {
	got := RollUpRequirements(grypeDuplicatePair())

	require.Len(t, got, 1, "two entries sharing an id roll up into one requirement")
	require.Equal(t, "Grype/CVE-2022-48174", got[0].ID)

	require.Len(t, got[0].Results, 2, "results concatenate — one per source finding")
	require.Equal(t,
		"Package: busybox@1.31.1-r9 | Type: apk | Location: /lib/apk/db/installed | Match Type: cpe-match",
		got[0].Results[0].CodeDesc, "source order preserved")
	require.Equal(t,
		"Package: ssl_client@1.31.1-r9 | Type: apk | Location: /lib/apk/db/installed | Match Type: cpe-match",
		got[0].Results[1].CodeDesc)

	require.Len(t, got[0].AffectedPackages, 2, "both packages survive — first-wins would discard one")
	require.Equal(t, "busybox", *got[0].AffectedPackages[0].Name)
	require.Equal(t, "ssl_client", *got[0].AffectedPackages[1].Name)
}

// --------------------------------------------------------------------------
// The shared case table — the same file rollup.test.ts runs, so a rule cannot
// be implemented one way in Go and another in TypeScript.
// --------------------------------------------------------------------------

type rollupCase struct {
	Name     string                     `json:"name"`
	Source   string                     `json:"source"`
	ADRRules []string                   `json:"adrRules"`
	Note     string                     `json:"note"`
	Input    []hdf.EvaluatedRequirement `json:"input"`
	Expected json.RawMessage            `json:"expected"`
}

func loadRollupCases(t *testing.T) []rollupCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "rollup-cases.json"))
	require.NoError(t, err)
	var doc struct {
		Cases []rollupCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Cases)
	return doc.Cases
}

func TestRollUpRequirements_SharedCaseTable(t *testing.T) {
	for _, c := range loadRollupCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			got, err := json.Marshal(RollUpRequirements(c.Input))
			require.NoError(t, err)
			require.JSONEq(t, string(c.Expected), string(got), "%s\nsource: %s", c.Note, c.Source)
		})
	}
}

// Every rule in ADR-0017 §6 is exercised by at least one shared case, so the
// table cannot quietly stop covering a row of the ADR's table.
func TestRollUpRequirements_SharedCaseTableCoversEveryADRField(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range loadRollupCases(t) {
		for _, f := range c.ADRRules {
			covered[f] = true
		}
	}
	for _, f := range loadFieldRules(t) {
		require.True(t, covered[f.Field], "no shared case exercises ADR-0017 §6's rule for %q", f.Field)
	}
}

// --------------------------------------------------------------------------
// The ADR §6 table itself.
// --------------------------------------------------------------------------

type fieldRule struct {
	Field    string `json:"field"`
	Rule     string `json:"rule"`
	Identity string `json:"identity"`
	ADRRule  string `json:"adrRule"`
}

func loadFieldRules(t *testing.T) []fieldRule {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "rollup-field-rules.json"))
	require.NoError(t, err)
	var doc struct {
		Rules  map[string]string `json:"rules"`
		Fields []fieldRule       `json:"fields"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Fields)
	for _, f := range doc.Fields {
		require.Contains(t, doc.Rules, f.Rule, "field %q names an undefined rule", f.Field)
		require.NotEmpty(t, f.ADRRule, "field %q quotes no ADR-0017 §6 row", f.Field)
	}
	return doc.Fields
}

// rollup-field-rules.json must name every field of Evaluated_Requirement and no
// other, so a field added to the schema cannot reach the helper without a
// recorded merge rule. This reflection test is the ONLY load-bearing guard:
// the TypeScript twin's Record<keyof EvaluatedRequirement, RuleName> documents
// the same intent but is never type-checked, because hdf-converters/tsconfig.json
// excludes **/*.test.ts — so a new schema field fails here first.
func TestRollUpFieldRules_CoverEveryRequirementField(t *testing.T) {
	declared := map[string]bool{}
	for _, f := range loadFieldRules(t) {
		require.False(t, declared[f.Field], "field %q declared twice", f.Field)
		declared[f.Field] = true
	}

	typ := reflect.TypeOf(hdf.EvaluatedRequirement{})
	schemaFields := map[string]bool{}
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		require.NotEmpty(t, name, "%s has no json tag", typ.Field(i).Name)
		schemaFields[name] = true
		require.True(t, declared[name],
			"Evaluated_Requirement.%s has no rule in rollup-field-rules.json — ADR-0017 §6 must state one before it can be merged", name)
	}
	for f := range declared {
		require.True(t, schemaFields[f], "rollup-field-rules.json names %q, which is not a field of Evaluated_Requirement", f)
	}
}

// --------------------------------------------------------------------------
// Scope: one baseline's slice, never a document.
// --------------------------------------------------------------------------

// prisma's golden carries 16 baselines, 94 entries, 53 distinct ids and 92
// distinct (baseline, id) pairs. The id below really does appear in baselines 0,
// 1, 4 and 9 of converters/prisma-to-hdf/fixtures/expected/
// prismacloud_sample.csv.hdf.json — different hosts, same compliance check. A
// document-wide merge would collapse them; the helper takes one baseline's slice
// and so cannot be asked to.
func TestRollUpRequirements_NeverMergesAcrossBaselines(t *testing.T) {
	const id = "60522-redhat-RHEL7-high"
	entry := func(host string) hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{
			ID: id, Impact: 0.7, Tags: map[string]interface{}{},
			Descriptions: []hdf.Description{{Label: "default", Data: "(CIS_Linux_2.0.0 - 5.2.2) Ensure permissions on SSH private host key files are configured"}},
			Results:      []hdf.RequirementResult{{CodeDesc: "Configuration check for redhat-RHEL7", Status: hdf.ResultStatus("failed")}},
			Code:         strp(host),
		}
	}
	baselineZero := RollUpRequirements([]hdf.EvaluatedRequirement{entry("my-fake-host-1.somewhere.cloud")})
	baselineOne := RollUpRequirements([]hdf.EvaluatedRequirement{entry("my-fake-host-2.somewhere.cloud")})

	require.Len(t, baselineZero, 1, "the id survives in its own baseline")
	require.Len(t, baselineOne, 1, "and in the next one")
	require.Equal(t, id, baselineZero[0].ID)
	require.Equal(t, id, baselineOne[0].ID)
	require.NotEqual(t, *baselineZero[0].Code, *baselineOne[0].Code, "two hosts, two findings")
}

// --------------------------------------------------------------------------
// Ordering, identity and non-mutation.
// --------------------------------------------------------------------------

func TestRollUpRequirements_ReturnsNonDuplicateInputUnchanged(t *testing.T) {
	in := []hdf.EvaluatedRequirement{
		{ID: "V-1", Impact: 0.1, Tags: map[string]interface{}{"a": "1"}, Results: []hdf.RequirementResult{{CodeDesc: "one"}}},
		{ID: "V-2", Impact: 0.2, Tags: map[string]interface{}{"b": "2"}, Results: []hdf.RequirementResult{{CodeDesc: "two"}}},
		{ID: "V-3", Impact: 0.3, Tags: map[string]interface{}{"c": "3"}, Results: []hdf.RequirementResult{{CodeDesc: "three"}}},
	}
	require.Equal(t, in, RollUpRequirements(in), "same length, same order, same values")
}

func TestRollUpRequirements_SurvivorKeepsFirstMemberPosition(t *testing.T) {
	mk := func(id, code string) hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{ID: id, Results: []hdf.RequirementResult{{CodeDesc: code}}}
	}
	got := RollUpRequirements([]hdf.EvaluatedRequirement{
		mk("V-1", "a"), mk("V-2", "b"), mk("V-3", "c"), mk("V-2", "d"),
	})
	require.Len(t, got, 3)
	require.Equal(t, []string{"V-1", "V-2", "V-3"}, []string{got[0].ID, got[1].ID, got[2].ID},
		"the survivor sits where its first member was, not where its last member was")
	require.Equal(t, []string{"b", "d"}, []string{got[1].Results[0].CodeDesc, got[1].Results[1].CodeDesc},
		"results in first-seen order")
}

func TestRollUpRequirements_DoesNotMutateItsInput(t *testing.T) {
	in := grypeDuplicatePair()
	before, err := json.Marshal(in)
	require.NoError(t, err)

	got := RollUpRequirements(in)
	got[0].Results = append(got[0].Results, hdf.RequirementResult{CodeDesc: "appended by the caller"})
	got[0].AffectedPackages = append(got[0].AffectedPackages, hdf.AffectedPackage{Name: strp("late")})

	after, err := json.Marshal(in)
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after), "the caller's slice is untouched, before and after it edits the result")
}

// --------------------------------------------------------------------------
// The documented divergences from heimdall2's collapseDuplicates
// (libs/hdf-converters/src/base-converter.ts:111-160).
// --------------------------------------------------------------------------

// heimdall2 keeps the first control whole and discards every later control's
// requirement-level fields. ADR-0017 §6 deliberately diverges on
// affectedPackages and the array-valued tags, which conflict in 64 of our 68
// real groups.
func TestRollUpRequirements_DivergesFromHeimdall2_KeepsLaterMembersPackagesAndArrayTags(t *testing.T) {
	mk := func(pkg, nist string) hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{
			ID:               "CVE-2024-0001",
			Tags:             map[string]interface{}{"nist": []interface{}{nist}, "gid": "G-1"},
			AffectedPackages: []hdf.AffectedPackage{{Purl: strp("pkg:npm/" + pkg + "@1.0.0")}},
			Results:          []hdf.RequirementResult{{CodeDesc: pkg}},
		}
	}
	got := RollUpRequirements([]hdf.EvaluatedRequirement{mk("left", "AC-1"), mk("right", "AC-2")})

	require.Len(t, got, 1)
	require.Len(t, got[0].AffectedPackages, 2, "heimdall2 would have discarded the second package")
	require.Equal(t, []interface{}{"AC-1", "AC-2"}, got[0].Tags["nist"], "array-valued tags union")
	require.Equal(t, "G-1", got[0].Tags["gid"], "scalar-valued tags still first-win")
}

// base-converter.ts:120-123 drops an item outright when its key value is not a
// string, with no else branch. id is schema-required in HDF, so an entry without
// one is malformed input rather than a control to discard: it passes through, and
// two such entries are never fused with each other.
func TestRollUpRequirements_DivergesFromHeimdall2_KeepsEntriesWithoutAnID(t *testing.T) {
	blank := func(code string) hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{ID: "", Results: []hdf.RequirementResult{{CodeDesc: code}}}
	}
	in := []hdf.EvaluatedRequirement{blank("first"), {ID: "V-1"}, blank("second")}
	got := RollUpRequirements(in)

	require.Len(t, got, 3, "nothing is dropped and the two blank ids do not merge with each other")
	require.Equal(t, "first", got[0].Results[0].CodeDesc)
	require.Equal(t, "V-1", got[1].ID)
	require.Equal(t, "second", got[2].Results[0].CodeDesc)
}

// heimdall2's collapseResults flag (base-converter.ts:167, set by four upstream
// mappers) skips a later result whose first code_desc is already present.
// ADR-0017 §6 says concatenate, full stop: each result is one source finding, and
// dropping one is exactly the under-extraction the result-count anchor exists to
// catch.
func TestRollUpRequirements_DivergesFromHeimdall2_NeverDeduplicatesResults(t *testing.T) {
	same := hdf.RequirementResult{CodeDesc: "identical", Status: hdf.ResultStatus("failed")}
	got := RollUpRequirements([]hdf.EvaluatedRequirement{
		{ID: "V-1", Results: []hdf.RequirementResult{same}},
		{ID: "V-1", Results: []hdf.RequirementResult{same}},
	})
	require.Len(t, got, 1)
	require.Len(t, got[0].Results, 2, "two identical findings are still two findings")
}

// --------------------------------------------------------------------------
// Worst-wins, where the enum ladder has no case-table expression.
// --------------------------------------------------------------------------

func TestRollUpRequirements_WorstSeverityRanksTheWholeLadder(t *testing.T) {
	sev := func(s hdf.Severity) *hdf.Severity { return &s }
	ladder := []hdf.Severity{hdf.Informational, hdf.SeverityLow, hdf.SeverityMedium, hdf.SeverityHigh, hdf.SeverityCritical}
	for i, lower := range ladder {
		for _, higher := range ladder[i+1:] {
			got := RollUpRequirements([]hdf.EvaluatedRequirement{
				{ID: "V-1", Severity: sev(lower)}, {ID: "V-1", Severity: sev(higher)},
			})
			require.Equal(t, higher, *got[0].Severity, "%s is worse than %s", higher, lower)
		}
	}
}

func TestRollUpRequirements_WorstWinsTreatsAbsentAsLosing(t *testing.T) {
	sev := func(s hdf.Severity) *hdf.Severity { return &s }
	impact := func(f float64) *float64 { return &f }

	present := hdf.EvaluatedRequirement{ID: "V-1", Severity: sev(hdf.SeverityLow), EffectiveImpact: impact(0.2)}
	absent := hdf.EvaluatedRequirement{ID: "V-1"}

	first := RollUpRequirements([]hdf.EvaluatedRequirement{present, absent})
	require.Equal(t, hdf.SeverityLow, *first[0].Severity)
	require.InDelta(t, 0.2, *first[0].EffectiveImpact, 0)

	second := RollUpRequirements([]hdf.EvaluatedRequirement{absent, present})
	require.Equal(t, hdf.SeverityLow, *second[0].Severity, "a present value beats an absent one whichever comes first")
	require.InDelta(t, 0.2, *second[0].EffectiveImpact, 0)

	neither := RollUpRequirements([]hdf.EvaluatedRequirement{absent, absent})
	require.Nil(t, neither[0].Severity)
	require.Nil(t, neither[0].EffectiveImpact)
}

// An unrecognised severity string ranks below every enum member, so a known
// severity always wins; two unknowns fall back to first-wins.
func TestRollUpRequirements_WorstSeverityHandlesValuesOutsideTheEnum(t *testing.T) {
	sev := func(s hdf.Severity) *hdf.Severity { return &s }
	got := RollUpRequirements([]hdf.EvaluatedRequirement{
		{ID: "V-1", Severity: sev(hdf.Severity("bogus"))}, {ID: "V-1", Severity: sev(hdf.Informational)},
	})
	require.Equal(t, hdf.Informational, *got[0].Severity)

	both := RollUpRequirements([]hdf.EvaluatedRequirement{
		{ID: "V-1", Severity: sev(hdf.Severity("bogus"))}, {ID: "V-1", Severity: sev(hdf.Severity("other"))},
	})
	require.Equal(t, hdf.Severity("bogus"), *both[0].Severity, "two unrecognised values fall back to first-wins")
}

// The unrated-severity marker is derived, not a scalar tag: it survives only as
// an AND across the members, because it asserts the severity was defaulted
// rather than rated and that holds of the merge only if it held of every member.
func TestRollUpRequirements_UnratedMarkerSurvivesOnlyWhenEveryMemberIsUnrated(t *testing.T) {
	sev := func(s hdf.Severity) *hdf.Severity { return &s }
	unrated := func() hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{ID: "V-1", Impact: 0.5,
			Tags: map[string]interface{}{UnratedSeverityTag: UnratedSeverityValue}}
	}
	rated := func() hdf.EvaluatedRequirement {
		return hdf.EvaluatedRequirement{ID: "V-1", Impact: 0.7, Severity: sev(hdf.SeverityHigh),
			Tags: map[string]interface{}{}}
	}

	t.Run("every member unrated keeps the marker", func(t *testing.T) {
		got := RollUpRequirements([]hdf.EvaluatedRequirement{unrated(), unrated()})
		require.Equal(t, UnratedSeverityValue, got[0].Tags[UnratedSeverityTag])
	})

	// Kept from the first member it would claim no rating was made beside a
	// genuine worst-wins severity — a self-contradictory requirement.
	t.Run("a later rated member drops the marker", func(t *testing.T) {
		got := RollUpRequirements([]hdf.EvaluatedRequirement{unrated(), rated()})
		require.NotContains(t, got[0].Tags, UnratedSeverityTag)
		require.Equal(t, hdf.SeverityHigh, *got[0].Severity)
	})

	// The mirror: under the later-only-key rule a plain scalar tag would be
	// ADDED here, labelling a rated requirement unrated.
	t.Run("a marker on a later member alone is not added", func(t *testing.T) {
		got := RollUpRequirements([]hdf.EvaluatedRequirement{rated(), unrated()})
		require.NotContains(t, got[0].Tags, UnratedSeverityTag)
	})

	t.Run("three members drop the marker if any one is rated", func(t *testing.T) {
		got := RollUpRequirements([]hdf.EvaluatedRequirement{unrated(), unrated(), rated()})
		require.Len(t, got, 1)
		require.NotContains(t, got[0].Tags, UnratedSeverityTag)
	})
}

// Dropping the marker must not reach into the caller's tag map — mergeTags
// returns the caller's own map when the later member carries no tags.
func TestRollUpRequirements_DroppingTheUnratedMarkerDoesNotMutateTheInput(t *testing.T) {
	first := hdf.EvaluatedRequirement{ID: "V-1",
		Tags: map[string]interface{}{UnratedSeverityTag: UnratedSeverityValue, "nist": []interface{}{"AC-2"}}}
	second := hdf.EvaluatedRequirement{ID: "V-1"} // no tags at all
	in := []hdf.EvaluatedRequirement{first, second}

	got := RollUpRequirements(in)

	require.NotContains(t, got[0].Tags, UnratedSeverityTag, "a member without the marker drops it")
	require.Equal(t, UnratedSeverityValue, in[0].Tags[UnratedSeverityTag], "the caller's map is untouched")
}

// The marker is identified by its value, not just its key: severity_rating
// carrying anything else is an ordinary scalar tag and first-wins.
func TestRollUpRequirements_UnratedMarkerKeyWithAnotherValueFirstWins(t *testing.T) {
	first := hdf.EvaluatedRequirement{ID: "V-1",
		Tags: map[string]interface{}{UnratedSeverityTag: "vendor-specific"}}
	second := hdf.EvaluatedRequirement{ID: "V-1"}

	got := RollUpRequirements([]hdf.EvaluatedRequirement{first, second})

	require.Equal(t, "vendor-specific", got[0].Tags[UnratedSeverityTag],
		"only the marker value is derived; any other value is a plain scalar tag")
}
