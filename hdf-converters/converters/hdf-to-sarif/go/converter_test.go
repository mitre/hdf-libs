package hdftosarif

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// farFuture is the expiry every non-expired fixture uses, so no test starts
// failing on a date the wall clock passes.
var farFuture = time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)

// longPast is for the cases that assert EXPIRED behavior.
var longPast = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// convertDoc converts a builder-produced document and returns the parsed log.
func convertDoc(t *testing.T, doc hdf.HDFResults) map[string]interface{} {
	t.Helper()
	input, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := ConvertHDFToSARIF(input, testVersion)
	require.NoError(t, err)
	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &log))
	return log
}

func runs(t *testing.T, log map[string]interface{}) []interface{} {
	t.Helper()
	r, ok := log["runs"].([]interface{})
	require.True(t, ok, "runs is not an array")
	return r
}

func run0(t *testing.T, log map[string]interface{}) map[string]interface{} {
	t.Helper()
	all := runs(t, log)
	require.NotEmpty(t, all)
	r, ok := all[0].(map[string]interface{})
	require.True(t, ok)
	return r
}

func results0(t *testing.T, log map[string]interface{}) []interface{} {
	t.Helper()
	res, _ := run0(t, log)["results"].([]interface{})
	return res
}

func result0(t *testing.T, log map[string]interface{}) map[string]interface{} {
	t.Helper()
	res := results0(t, log)
	require.NotEmpty(t, res, "no results emitted")
	r, ok := res[0].(map[string]interface{})
	require.True(t, ok)
	return r
}

func rules0(t *testing.T, log map[string]interface{}) []interface{} {
	t.Helper()
	tool, _ := run0(t, log)["tool"].(map[string]interface{})
	driver, _ := tool["driver"].(map[string]interface{})
	rules, _ := driver["rules"].([]interface{})
	return rules
}

func rule0(t *testing.T, log map[string]interface{}) map[string]interface{} {
	t.Helper()
	all := rules0(t, log)
	require.NotEmpty(t, all, "no rules emitted")
	r, ok := all[0].(map[string]interface{})
	require.True(t, ok)
	return r
}

func TestConvertHDFToSARIF_DeclaresTheFormat(t *testing.T) {
	log := convertDoc(t, testhdf.Results(testhdf.Req("V-1")))
	assert.Equal(t, SARIFVersion, log["version"])
	assert.Equal(t, SARIFSchemaURI, log["$schema"])
}

// One run per baseline is the modelling decision; a document with several
// baselines must not collapse into one run, which would merge rules that were
// never evaluated together and lose every baseline's identity.
func TestConvertHDFToSARIF_OneRunPerBaseline(t *testing.T) {
	doc := testhdf.Doc(
		testhdf.Baseline("first", testhdf.Req("V-1")),
		testhdf.Baseline("second", testhdf.Req("V-2")),
	)
	log := convertDoc(t, doc)
	all := runs(t, log)
	require.Len(t, all, 2)
	for i, name := range []string{"first", "second"} {
		r, _ := all[i].(map[string]interface{})
		details, _ := r["automationDetails"].(map[string]interface{})
		assert.Equal(t, name, details["id"], "run %d identifies its baseline", i)
	}
}

// A document that evaluated nothing is legal HDF; SARIF models a log with no
// runs, so it converts rather than erroring or emitting nothing.
func TestConvertHDFToSARIF_ZeroBaselinesIsAnEmptyRunSet(t *testing.T) {
	out, err := ConvertHDFToSARIF([]byte(`{"baselines":[]}`), testVersion)
	require.NoError(t, err)
	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &log))
	assert.Equal(t, []interface{}{}, log["runs"])
}

// A clean scan — every requirement passing — is a run that found nothing, not an
// error and not an empty file.
func TestConvertHDFToSARIF_CleanDocumentStillProducesARun(t *testing.T) {
	doc := testhdf.Results(
		testhdf.Req("V-1", testhdf.Status(hdf.Passed)),
		testhdf.Req("V-2", testhdf.Status(hdf.Passed)),
	)
	log := convertDoc(t, doc)
	require.Len(t, runs(t, log), 1)
	res := results0(t, log)
	require.Len(t, res, 2)
	for _, raw := range res {
		r, _ := raw.(map[string]interface{})
		assert.Equal(t, "pass", r["kind"])
		assert.NotContains(t, r, "level", "level applies only to a failing result")
	}
}

func TestConvertHDFToSARIF_DriverNameFallsBackToADocumentedConstant(t *testing.T) {
	log := convertDoc(t, testhdf.Results(testhdf.Req("V-1")))
	tool, _ := run0(t, log)["tool"].(map[string]interface{})
	driver, _ := tool["driver"].(map[string]interface{})
	assert.Equal(t, unnamedTool, driver["name"])

	doc := testhdf.Results(testhdf.Req("V-1"))
	name, version := "Flawfinder", "2.0.15"
	doc.Tool = &hdf.Tool{Name: &name, Version: &version}
	log = convertDoc(t, doc)
	tool, _ = run0(t, log)["tool"].(map[string]interface{})
	driver, _ = tool["driver"].(map[string]interface{})
	assert.Equal(t, "Flawfinder", driver["name"])
	assert.Equal(t, "2.0.15", driver["version"])
}

// kind and level are orthogonal axes (§3.27.9/§3.27.10): every HDF status maps
// to its own kind, and the severity stays on the rule where a non-failing result
// cannot carry it.
func TestConvertHDFToSARIF_KindAndLevelAreOrthogonal(t *testing.T) {
	for status, wantKind := range map[hdf.ResultStatus]string{
		hdf.Passed:        "pass",
		hdf.Failed:        "fail",
		hdf.NotApplicable: "notApplicable",
		hdf.NotReviewed:   "review",
		hdf.Error:         "open",
	} {
		t.Run(string(status), func(t *testing.T) {
			doc := testhdf.Results(testhdf.Req("V-1",
				testhdf.Status(status), testhdf.Impact(0.7)))
			log := convertDoc(t, doc)
			res := result0(t, log)
			assert.Equal(t, wantKind, res["kind"])

			config, _ := rule0(t, log)["defaultConfiguration"].(map[string]interface{})
			assert.Equal(t, "error", config["level"], "the rule carries the severity whatever the kind")

			if wantKind == kindFail {
				assert.Equal(t, "error", res["level"])
			} else {
				assert.NotContains(t, res, "level",
					"for any kind but fail the spec admits only \"none\", which is the default when absent")
			}
		})
	}
}

func TestConvertHDFToSARIF_LevelDerivesFromImpactBands(t *testing.T) {
	for _, c := range []struct {
		impact float64
		level  string
	}{
		{0.9, "error"}, {0.7, "error"}, {0.5, "warning"}, {0.4, "warning"},
		{0.3, "note"}, {0.1, "note"}, {0, "none"},
	} {
		log := convertDoc(t, testhdf.Results(testhdf.Req("V-1", testhdf.Impact(c.impact))))
		config, _ := rule0(t, log)["defaultConfiguration"].(map[string]interface{})
		assert.Equal(t, c.level, config["level"], "impact %v", c.impact)
	}
}

// Impact 0.0 means no impact, not ungraded, so it cannot produce level "none" by
// itself — but a severity tag written by sarif-to-hdf holds the source level
// verbatim and is the one thing that can restore it.
func TestConvertHDFToSARIF_CarriedSeverityTagRestoresTheSourceLevel(t *testing.T) {
	log := convertDoc(t, testhdf.Results(testhdf.Req("V-1",
		testhdf.Impact(0.9), testhdf.Tag("severity", "none"))))
	config, _ := rule0(t, log)["defaultConfiguration"].(map[string]interface{})
	assert.Equal(t, "none", config["level"])

	// An HDF severity word is not a SARIF level and must not be mistaken for one.
	log = convertDoc(t, testhdf.Results(testhdf.Req("V-1",
		testhdf.Impact(0.9), testhdf.Tag("severity", "critical"))))
	config, _ = rule0(t, log)["defaultConfiguration"].(map[string]interface{})
	assert.Equal(t, "error", config["level"])
}

// Two SARIF kinds collapse onto one HDF status in each of two cases; the carried
// tag restores the distinction, but only where it agrees with the recorded status.
func TestConvertHDFToSARIF_CarriedKindTagRestoresCollapsedKinds(t *testing.T) {
	log := convertDoc(t, testhdf.Results(testhdf.Req("V-1",
		testhdf.Status(hdf.Failed), testhdf.Tag("kind", "open"))))
	assert.Equal(t, "open", result0(t, log)["kind"])

	log = convertDoc(t, testhdf.Results(testhdf.Req("V-1",
		testhdf.Status(hdf.NotApplicable), testhdf.Tag("kind", "informational"))))
	assert.Equal(t, "informational", result0(t, log)["kind"])

	// A tag that contradicts the status is ignored: the mapped field wins.
	log = convertDoc(t, testhdf.Results(testhdf.Req("V-1",
		testhdf.Status(hdf.Passed), testhdf.Tag("kind", "fail"))))
	assert.Equal(t, "pass", result0(t, log)["kind"])
}

func TestConvertHDFToSARIF_DescriptionsReachTheirInverseFields(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1",
		testhdf.Title("A title"),
		testhdf.Desc("the default text"),
		testhdf.AddDesc("check", "how to check it"),
		testhdf.AddDesc("rationale", "why it matters"),
		testhdf.AddDesc("fix", "how to fix it"),
	))
	rule := rule0(t, convertDoc(t, doc))
	short, _ := rule["shortDescription"].(map[string]interface{})
	full, _ := rule["fullDescription"].(map[string]interface{})
	help, _ := rule["help"].(map[string]interface{})
	assert.Equal(t, "A title", short["text"])
	assert.Equal(t, "why it matters", full["text"])
	assert.Equal(t, "how to check it", help["text"])

	// SARIF's fix object requires an artifactChange with a replacement region,
	// which HDF fix PROSE cannot supply, so the text is carried rather than
	// dressed up as a code change.
	assert.NotContains(t, rule, "fixes")
	props, _ := rule["properties"].(map[string]interface{})
	block, _ := props[hdfBagKey].(map[string]interface{})
	descs, _ := block["descriptions"].([]interface{})
	assert.Len(t, descs, 4, "every description survives verbatim in the HDF block")
}

func TestConvertHDFToSARIF_TagsAndHelpURI(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1",
		testhdf.CWE("CWE-120", "CWE-20"),
		testhdf.Tag("nist", []string{"SI-10"}),
		testhdf.Tag("cci", []string{"CCI-000366"}),
		testhdf.Tag("helpUri", "https://cwe.mitre.org/data/definitions/120.html"),
	))
	rule := rule0(t, convertDoc(t, doc))
	assert.Equal(t, "https://cwe.mitre.org/data/definitions/120.html", rule["helpUri"])
	props, _ := rule["properties"].(map[string]interface{})
	assert.Equal(t, []interface{}{
		"cci/CCI-000366", "external/cwe/cwe-120", "external/cwe/cwe-20", "nist/SI-10",
	}, props["tags"])
}

// security-severity is SARIF's CVSS convention, so it appears only where the
// requirement actually carries CVSS; labelling a STIG severity as a CVSS score
// would be asserting something untrue.
func TestConvertHDFToSARIF_SecuritySeverityOnlyWithCVSS(t *testing.T) {
	plain := testhdf.Results(testhdf.Req("V-1", testhdf.Impact(0.7)))
	props, _ := rule0(t, convertDoc(t, plain))["properties"].(map[string]interface{})
	assert.NotContains(t, props, "security-severity")

	scored := testhdf.Results(testhdf.Req("CVE-2024-1", testhdf.Impact(0.7)))
	score := 8.6
	scored.Baselines[0].Requirements[0].Cvss = []hdf.Cvss{{Version: "3.1", BaseScore: &score}}
	props, _ = rule0(t, convertDoc(t, scored))["properties"].(map[string]interface{})
	assert.Equal(t, "8.6", props["security-severity"])
}

// cvss, epss and kev have no SARIF field at all — 2.1.0 carries no CVSS — so
// they must survive in the HDF block or the export loses them silently.
func TestConvertHDFToSARIF_CarriesScoringDataSARIFCannotHold(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("CVE-2024-1"))
	req := &doc.Baselines[0].Requirements[0]
	score := 9.8
	req.Cvss = []hdf.Cvss{{Version: "3.1", BaseScore: &score}}
	req.Epss = &hdf.Epss{Date: "2026-01-01", Percentile: 0.99, Score: 0.97532}
	added, due := "2024-01-01", "2024-01-15"
	req.Kev = &hdf.Kev{InKev: true, DateAdded: &added, DueDate: &due}

	props, _ := rule0(t, convertDoc(t, doc))["properties"].(map[string]interface{})
	block, _ := props[hdfBagKey].(map[string]interface{})
	assert.NotEmpty(t, block["cvss"])
	assert.NotEmpty(t, block["epss"])
	assert.NotEmpty(t, block["kev"])
}

func withOverride(doc hdf.HDFResults, o hdf.StatusOverride) hdf.HDFResults {
	doc.Baselines[0].Requirements[0].StatusOverrides = []hdf.StatusOverride{o}
	return doc
}

func waiver(status hdf.ResultStatus, expires time.Time) hdf.StatusOverride {
	return hdf.StatusOverride{
		Type:      hdf.OverrideTypeWaiver,
		Status:    &status,
		Reason:    "accepted risk, documented in the SSP",
		AppliedAt: longPast,
		ExpiresAt: expires,
		AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "isso@example.gov"},
	}
}

// A suppressions array asserts the finding WAS suppressed, so it is emitted for
// an override that actually drove a failing verdict non-failing — and SARIF's
// definition of "external" is the only value an HDF override can honestly claim.
func TestConvertHDFToSARIF_SuppressionFromAGoverningOverride(t *testing.T) {
	doc := withOverride(
		testhdf.Results(testhdf.Req("V-1", testhdf.Status(hdf.Failed), testhdf.Impact(0.7))),
		waiver(hdf.NotApplicable, farFuture),
	)
	supps, _ := result0(t, convertDoc(t, doc))["suppressions"].([]interface{})
	require.Len(t, supps, 1)
	s, _ := supps[0].(map[string]interface{})
	assert.Equal(t, "external", s["kind"])
	assert.Equal(t, "accepted", s["status"])
	assert.Equal(t, "accepted risk, documented in the SSP", s["justification"])

	// The seven override members SARIF's suppression has no field for.
	props, _ := s["properties"].(map[string]interface{})
	block, _ := props[hdfBagKey].(map[string]interface{})
	for _, key := range []string{"appliedBy", "appliedAt", "expiresAt", "type"} {
		assert.Contains(t, block, key)
	}
}

// A riskAdjustment that leaves the requirement failing is still actionable; a
// suppression would tell a dashboard to hide it.
func TestConvertHDFToSARIF_NonSuppressingOverrideIsNotFaked(t *testing.T) {
	failed := hdf.Failed
	doc := withOverride(
		testhdf.Results(testhdf.Req("V-1", testhdf.Status(hdf.Failed), testhdf.Impact(0.7))),
		hdf.StatusOverride{
			Type:      hdf.RiskAdjustment,
			Status:    &failed,
			Reason:    "compensating control in place",
			AppliedAt: longPast,
			ExpiresAt: farFuture,
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "isso@example.gov"},
		},
	)
	res := result0(t, convertDoc(t, doc))
	assert.NotContains(t, res, "suppressions")
	assert.Equal(t, kindFail, res["kind"])
}

func TestConvertHDFToSARIF_ExpiredOverrideSuppressesNothing(t *testing.T) {
	doc := withOverride(
		testhdf.Results(testhdf.Req("V-1", testhdf.Status(hdf.Failed), testhdf.Impact(0.7))),
		waiver(hdf.NotApplicable, longPast.AddDate(1, 0, 0)),
	)
	assert.NotContains(t, result0(t, convertDoc(t, doc)), "suppressions")
}

// The tag sarif-to-hdf writes holds EVERY source suppression, including the
// rejected and under-review ones an HDF override cannot represent at all.
func TestConvertHDFToSARIF_CarriedSuppressionsTagTakesPriority(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1",
		testhdf.Status(hdf.Failed),
		testhdf.Tag("suppressions", []map[string]string{
			{"kind": "inSource", "status": "rejected", "justification": "reviewer disagreed"},
			{"kind": "external", "status": "underReview"},
			{"kind": "not-a-kind"},
		}),
	))
	supps, _ := result0(t, convertDoc(t, doc))["suppressions"].([]interface{})
	require.Len(t, supps, 2, "an entry outside SARIF's kind enum is dropped, not coerced")
	first, _ := supps[0].(map[string]interface{})
	assert.Equal(t, "inSource", first["kind"])
	assert.Equal(t, "rejected", first["status"])
	assert.Equal(t, "reviewer disagreed", first["justification"])
	second, _ := supps[1].(map[string]interface{})
	assert.Equal(t, "underReview", second["status"])
	assert.NotContains(t, second, "justification")
}

func TestConvertHDFToSARIF_LocationFromSourceLocation(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1"))
	ref, line := "test/test-patched.c", 36.0
	doc.Baselines[0].Requirements[0].SourceLocation = &hdf.SourceLocation{Ref: &ref, Line: &line}

	locs, _ := result0(t, convertDoc(t, doc))["locations"].([]interface{})
	require.Len(t, locs, 1)
	loc, _ := locs[0].(map[string]interface{})
	phys, _ := loc["physicalLocation"].(map[string]interface{})
	art, _ := phys["artifactLocation"].(map[string]interface{})
	region, _ := phys["region"].(map[string]interface{})
	assert.Equal(t, "test/test-patched.c", art["uri"])
	assert.InDelta(t, 36.0, region["startLine"], 0)
	assert.NotContains(t, region, "startColumn", "HDF Source_Location carries no column")
}

// The documented tag convention is where region precision lives: Source_Location
// is {ref, line} and closed, so column and end positions have no schema field.
func TestConvertHDFToSARIF_RegionTagSuppliesTheColumns(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1", testhdf.Tag(regionTag, map[string]interface{}{
		"startLine":      36,
		"startColumn":    2,
		"endColumn":      10,
		"endLine":        37,
		"charOffset":     1024,
		"sourceLanguage": "c",
		"snippet":        map[string]interface{}{"text": " gets(f);"},
		"startRow":       99, // not a SARIF region member
	})))
	ref := "test/test-patched.c"
	doc.Baselines[0].Requirements[0].SourceLocation = &hdf.SourceLocation{Ref: &ref}

	locs, _ := result0(t, convertDoc(t, doc))["locations"].([]interface{})
	require.Len(t, locs, 1)
	loc, _ := locs[0].(map[string]interface{})
	phys, _ := loc["physicalLocation"].(map[string]interface{})
	region, _ := phys["region"].(map[string]interface{})
	assert.InDelta(t, 36.0, region["startLine"], 0)
	assert.InDelta(t, 2.0, region["startColumn"], 0)
	assert.InDelta(t, 10.0, region["endColumn"], 0)
	assert.InDelta(t, 37.0, region["endLine"], 0)
	assert.InDelta(t, 1024.0, region["charOffset"], 0)
	assert.Equal(t, "c", region["sourceLanguage"])
	snippet, _ := region["snippet"].(map[string]interface{})
	assert.Equal(t, " gets(f);", snippet["text"])
	assert.NotContains(t, region, "startRow", "the region is closed; a foreign key is dropped")
}

func TestConvertHDFToSARIF_RegionTagRejectsValuesThatAreNotPositions(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1", testhdf.Tag(regionTag, map[string]interface{}{
		"startLine":   0,
		"startColumn": 2.5,
		"endLine":     -3,
		"endColumn":   4,
	})))
	ref := "a.c"
	doc.Baselines[0].Requirements[0].SourceLocation = &hdf.SourceLocation{Ref: &ref}
	locs, _ := result0(t, convertDoc(t, doc))["locations"].([]interface{})
	loc, _ := locs[0].(map[string]interface{})
	phys, _ := loc["physicalLocation"].(map[string]interface{})
	region, _ := phys["region"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"endColumn": 4.0}, region)
}

func TestConvertHDFToSARIF_FingerprintsTagIsRestored(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1", testhdf.Tag("fingerprints", map[string]interface{}{
		"fingerprints":        map[string]interface{}{"contextHash/v1": "6a5bb3"},
		"partialFingerprints": map[string]interface{}{"primaryLocationLineHash": "ab12", "bad": 7},
	})))
	res := result0(t, convertDoc(t, doc))
	assert.Equal(t, map[string]interface{}{"contextHash/v1": "6a5bb3"}, res["fingerprints"])
	assert.Equal(t, map[string]interface{}{"primaryLocationLineHash": "ab12"}, res["partialFingerprints"],
		"a non-string fingerprint value is not one SARIF admits")
}

// HDF re-reports a requirement id freely (overlay chains do it constantly) while
// the schema puts uniqueItems on the rules array, so rules dedupe and the later
// occurrence keeps its own data on its results.
func TestConvertHDFToSARIF_DuplicateRequirementIDsShareOneRule(t *testing.T) {
	doc := testhdf.Doc(testhdf.Baseline("b",
		testhdf.Req("V-1", testhdf.Title("first layer"), testhdf.Impact(0.7)),
		testhdf.Req("V-1", testhdf.Title("second layer"), testhdf.Impact(0.3)),
	))
	log := convertDoc(t, doc)
	require.Len(t, rules0(t, log), 1, "one rule per id")
	res := results0(t, log)
	require.Len(t, res, 2)

	second, _ := res[1].(map[string]interface{})
	assert.InDelta(t, 0.0, second["ruleIndex"], 0)
	props, _ := second["properties"].(map[string]interface{})
	block, _ := props[hdfBagKey].(map[string]interface{})
	requirement, _ := block["requirement"].(map[string]interface{})
	require.NotNil(t, requirement, "the second occurrence's requirement data is not dropped")
	assert.InDelta(t, 0.3, requirement["impact"], 0)

	// The owner of the rule does not repeat its requirement block on the result.
	first, _ := res[0].(map[string]interface{})
	props, _ = first["properties"].(map[string]interface{})
	block, _ = props[hdfBagKey].(map[string]interface{})
	assert.NotContains(t, block, "requirement")
}

// A requirement with no results is a rule that reported nothing — SARIF's own
// representation — rather than a fabricated finding.
func TestConvertHDFToSARIF_RequirementWithoutResultsEmitsOnlyARule(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1"))
	doc.Baselines[0].Requirements[0].Results = []hdf.RequirementResult{}
	log := convertDoc(t, doc)
	require.Len(t, rules0(t, log), 1)
	assert.Empty(t, results0(t, log))
	props, _ := rule0(t, log)["properties"].(map[string]interface{})
	assert.Contains(t, props, hdfBagKey, "the requirement's data survives on its rule")
}

func TestConvertHDFToSARIF_ConversionNamesThisExporter(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1"))
	doc.Generator = &hdf.Generator{Name: "sarif-to-hdf", Version: "3.7.2"}
	log := convertDoc(t, doc)
	conv, _ := run0(t, log)["conversion"].(map[string]interface{})
	tool, _ := conv["tool"].(map[string]interface{})
	driver, _ := tool["driver"].(map[string]interface{})
	assert.Equal(t, converterName, driver["name"])
	assert.Equal(t, testVersion, driver["version"])

	props, _ := run0(t, log)["properties"].(map[string]interface{})
	block, _ := props[hdfBagKey].(map[string]interface{})
	gen, _ := block["generator"].(map[string]interface{})
	assert.Equal(t, "sarif-to-hdf", gen["name"], "the upstream converter is carried, not overwritten")
}

func TestConvertHDFToSARIF_RejectsMalformedInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":           "",
		"not json":        "not json",
		"top-level array": "[]",
		"no baselines":    `{"generator":{"name":"t","version":"1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := ConvertHDFToSARIF([]byte(input), testVersion)
			require.Error(t, err)
			assert.Nil(t, out)
			assert.Contains(t, err.Error(), converterName)
		})
	}
}

// The schema URI embeds the version three times in a path that is NOT derivable from
// the version string (v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json), so the two
// constants cannot be generated from one another and would otherwise drift apart in
// silence when the version is repointed. Asserting containment is what makes the
// deferral of --to sarif@<version> safe: repointing is two edits, and this fails if
// only one is made.
func TestSARIFSchemaURIContainsTheVersion(t *testing.T) {
	assert.Contains(t, SARIFSchemaURI, SARIFVersion,
		"the schema URI must name the version the converter emits")
	assert.NotEqual(t, "", SARIFVersion)
	assert.True(t, strings.HasPrefix(SARIFSchemaURI, "https://"),
		"the schema URI must be the canonical OASIS https location")
}
