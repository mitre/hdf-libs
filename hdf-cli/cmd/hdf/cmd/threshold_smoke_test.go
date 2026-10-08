package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end threshold smoke tests: real policies an operator would write, run
// against real converter output through the real command, asserting the verdict
// a CI log would show.
//
// This sits ABOVE the shared case tables rather than repeating them. Those pin
// each predicate field-by-field in both languages; what nothing else covers is
// the INTERACTION — a policy combining several predicates over a document
// carrying several amendment types, and whether the surfaces agree about the
// same document. Every individual piece has a green test, which is exactly why
// an inconsistency between them can hide.
//
// WHAT THE CONSISTENCY ASSERTION CAN AND CANNOT CATCH, stated because the
// distinction is not obvious and overstating it would be worse than omitting it.
// It compares `hdf query` against a threshold rule, and BOTH call the same
// hdfengine.Filter. A semantic bug inside that shared filter moves both sides
// identically and the comparison stays green by construction. What it does catch
// is a divergence in how the two surfaces CONSTRUCT their filter options — a
// predicate field that reaches one and not the other — and any divergence in
// counting or rendering between the message and the findings under it. Semantics
// inside the filter are the shared case tables' job, and they are pinned there in
// both languages.
//
// Go-only, deliberately. The consistency assertion needs both `hdf query` and
// `hdf validate threshold`, exit codes and rendered verdicts exist nowhere else,
// and there is no TypeScript CLI — a TS twin would test the same engine twice
// through a surface that does not exist. The cross-language contract is the
// engine's shared tables.
//
// RECORDED COVERAGE GAP: no committed document carries a KEV-positive
// requirement, so the `kev` predicate is not exercised here. The reason is not
// laziness — hdf.Kev conditionally requires the CISA catalog's dateAdded and
// dueDate, only grype-to-hdf emits it, Grype's own published snapshots carry no
// KEV hit, and Grype publishes no output schema against which a constructed
// input could be confirmed. Tracked as hdf-libs-016cx. EPSS by contrast IS
// exercised below, from real FIRST.org scores in real Grype output.

// smokeDoc materialises an embedded real fixture on disk under its own name, so
// a verdict line names something a reader can recognise.
func smokeDoc(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	require.NotEmpty(t, body, "embedded fixture %s must not be empty", name)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, body, 0o644))
	return path
}

// convertToHDF runs the real converter, because a smoke test over hand-made HDF
// would not be testing what an operator actually gates on.
func convertToHDF(t *testing.T, dir, from, name string, source []byte) string {
	t.Helper()
	in := smokeDoc(t, dir, "src-"+name, source)
	out := filepath.Join(dir, name)
	_, _, err := executeCommand("convert", "--from", from, in, "-o", out)
	require.NoError(t, err, "converting the %s fixture must succeed", from)
	return out
}

var smokeIDLine = regexp.MustCompile(`(?m)^(\S+)\s`)

// queryIDs returns the requirement ids `hdf query` selects, so a rule's findings
// can be compared against the other surface asking the same question.
func queryIDs(t *testing.T, doc string, args ...string) []string {
	t.Helper()
	full := append([]string{"query", doc, "--limit", "0"}, args...)
	stdout, _, err := executeCommand(full...)
	if err != nil && strings.Contains(err.Error(), "no matching requirements") {
		return nil
	}
	require.NoError(t, err, "query must succeed: %v", args)

	var ids []string
	for _, line := range strings.Split(stdout, "\n") {
		if line == "" || strings.HasPrefix(line, "Found ") || strings.HasPrefix(line, "ID") ||
			strings.HasPrefix(line, "---") || strings.HasPrefix(line, " ") {
			continue
		}
		if m := smokeIDLine.FindStringSubmatch(line); m != nil {
			ids = append(ids, m[1])
		}
	}
	sort.Strings(ids)
	return ids
}

// findingIDs returns the requirement ids a failed gate listed under its
// violations, parsed from the rendered verdict a CI log would show.
func findingIDs(t *testing.T, stderr string) []string {
	t.Helper()
	var ids []string
	for _, line := range strings.Split(stderr, "\n") {
		// A finding line is indented six spaces under its violation.
		if !strings.HasPrefix(line, "      ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ids = append(ids, fields[0])
		}
	}
	sort.Strings(ids)
	return ids
}

// ─────────────────────────────────────────────────────────────────────────────
// Real use cases: policies that make sense for what the source document is
// ─────────────────────────────────────────────────────────────────────────────

// A STIG-style scan is gated on overall compliance, which is the number an
// authorising official actually reads. The real InSpec multi-overlay scan sits
// far below any plausible bar, so this is a policy that FAILS honestly rather
// than a contrived one.
func TestSmoke_StigCompliancePercentage(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "rhel-stig.json", fixtures.Results.InspecMultilayered)

	_, stderr, err := executeCommand("validate", "threshold", doc, "-I", "{compliance: {min: 80}}")
	require.Error(t, err, "a 5-baseline scan this far below 80% must fail the gate")
	assert.Contains(t, stderr, "rhel-stig.json", "the verdict names the document CI was gating")
	assert.Regexp(t, `compliance \d+\.\d+% is below minimum 80\.00%`, stderr)

	// A compliance bound is a property of the whole document, so it names no
	// requirement — asserted here because "lists nothing" is a real contract and
	// this document has 271 failures it could wrongly have listed.
	assert.Empty(t, findingIDs(t, stderr), "a percentage bound has no single offender to name")

	// And the same document passes a bar it actually clears, so the gate is not
	// simply always-red.
	_, _, err = executeCommand("validate", "threshold", doc, "-I", "{compliance: {min: 5}}")
	require.NoError(t, err)
}

// A vulnerability scan is gated on severity of exposure, not on a count of
// findings. Prisma Cloud output carries real CVSS scores, so this is the policy
// a team actually writes: nothing critical may be failing.
func TestSmoke_NothingFailingAboveCVSS9(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "prisma-scan.json", fixtures.Results.DuplicateBaselines)

	spec := `{rules: [{name: nothing failing above CVSS 9, where: {status: failed, cvss: ">=9"}, max: 0}]}`
	_, stderr, err := executeCommand("validate", "threshold", doc, "-I", spec)
	require.Error(t, err, "this scan has failing criticals")
	assert.Contains(t, stderr, "nothing failing above CVSS 9")

	// THE CONSISTENCY ASSERTION. The requirements the rule named must be exactly
	// those `hdf query` returns for the same predicate. Two surfaces, one
	// question — a divergence here is the bug class no unit test can catch,
	// because each surface has its own green tests.
	assert.Equal(t,
		queryIDs(t, doc, "--status", "failed", "--cvss", ">=9"),
		findingIDs(t, stderr),
		"a rule and hdf query must select the same requirements for the same predicate")

	// A bar this document clears, so the predicate is not matching everything.
	_, _, err = executeCommand("validate", "threshold", doc,
		"-I", `{rules: [{name: headroom, where: {status: failed, cvss: ">=11"}, max: 0}]}`)
	require.NoError(t, err, "no CVSS is above 10, so this bound cannot be breached")
}

// EPSS is the exploit PROBABILITY, and gating on it is the policy a team writes
// when it cannot patch everything. Real Grype 0.117.0 output carries real
// FIRST.org scores, so this runs against genuine data rather than a table.
func TestSmoke_EpssGateOnRealScores(t *testing.T) {
	dir := t.TempDir()
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "..",
		"hdf-converters", "converters", "grype-to-hdf", "fixtures", "input", "directory_scan.json"))
	require.NoError(t, err, "the real grype directory-scan fixture must be readable")
	doc := convertToHDF(t, dir, "grype", "grype-epss.json", source)

	spec := `{rules: [{name: nothing above EPSS 0.03, where: {epss: ">=0.03"}, max: 0}]}`
	_, stderr, err := executeCommand("validate", "threshold", doc, "-I", spec)
	require.Error(t, err)
	assert.Equal(t,
		queryIDs(t, doc, "--epss", ">=0.03"),
		findingIDs(t, stderr),
		"the EPSS rule and hdf query must agree")

	// The scores are real, so the bound discriminates rather than selecting all.
	all := queryIDs(t, doc)
	hits := queryIDs(t, doc, "--epss", ">=0.03")
	require.NotEmpty(t, hits)
	assert.Less(t, len(hits), len(all), "a real EPSS bound must narrow, or it proves nothing")
}

// Filing a POA&M satisfies a POA&M gate. This test previously pinned the opposite
// as a KNOWN GAP (hdf-libs-s4rmq): the poams predicate read requirements[].poams[]
// while `hdf amend apply` writes statusOverrides[], and nothing in the toolchain
// writes poams[] at all — so "every failure has a current plan" could never pass
// however many POA&Ms were filed. The predicate now reads both. The inverted
// assertions below are deliberate: this file is where that behaviour is pinned, so
// a regression shows up here rather than in a user's pipeline.
func TestSmoke_PoamGateIsSatisfiedByAnAppliedPoam(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)
	amended := applySmokeAmendments(t, dir, doc)

	unplanned := `{rules: [{name: every failure has a current plan, where: {status: failed, poams: none-valid}, max: 0}]}`

	_, before, err := executeCommand("validate", "threshold", doc, "-I", unplanned)
	require.Error(t, err, "the unamended scan has failures with no plan")
	beforeIDs := findingIDs(t, before)
	require.NotEmpty(t, beforeIDs)

	_, after, err := executeCommand("validate", "threshold", amended, "-I", unplanned)
	// Still an error, because the corpus deliberately leaves one failure
	// unadjudicated — that is what keeps this assertion from being vacuous.
	require.Error(t, err, "one failure in the corpus has no plan at all")
	afterIDs := findingIDs(t, after)
	assert.Less(t, len(afterIDs), len(beforeIDs))

	// The invariant, stated so it survives fixture churn: a requirement GOVERNED BY
	// A POA&M must NOT be counted as unplanned. Reverting the fix turns this red.
	planned := queryIDs(t, amended, "--status", "failed", "--disposition", "poam")
	require.NotEmpty(t, planned, "the corpus must contain a failing requirement governed by a POA&M")
	for _, id := range planned {
		assert.NotContains(t, afterIDs, id,
			"%s is governed by a POA&M and must not count as unplanned", id)
	}

	// The two predicates answer DIFFERENT questions and set equality is NOT an
	// invariant the engine holds — asserting it would be a false red waiting for
	// whoever adds a realistic row. `poams` asks whether the requirement CARRIES a
	// live plan; `disposition poam` asks whether a plan is what GOVERNS it. They
	// diverge whenever a newer override outranks the plan: append an
	// enrich-authored riskAdjustment (no status, so the finding stays failed) to a
	// poam-governed requirement and disposition names riskAdjustment while the plan
	// is still filed and still in force. That predates this change and is pinned
	// for the poams[] path too — WAIVER-NEWER-THAN-POAM sits in the shared table's
	// `poams valid` case and NOT in its `disposition poam` case.
	//
	// So the assertion is one-directional, which is the part that matters here:
	// every requirement the governing-plan view finds must also be found by the
	// carries-a-plan view. The reverse may legitimately be larger.
	governed := queryIDs(t, amended, "--status", "failed", "--disposition", "poam")
	carries := queryIDs(t, amended, "--status", "failed", "--poams", "valid")
	require.NotEmpty(t, governed, "the corpus must contain a failing requirement governed by a plan")
	for _, id := range governed {
		assert.Contains(t, carries, id,
			"%s is GOVERNED by a plan, so it must also COUNT as carrying one", id)
	}

	// An unadjudicated requirement carries no plan. This is the ABSENT case, not
	// the lapsed one: every override in the smoke corpus expires 2099-12-31, and
	// CVE-2022-42919 carries no override at all. Lapsed expiry is pinned where a
	// lapsed row exists — hdf-engine/testdata/amendment-filter-cases.json, whose
	// POAM-OVERRIDE-LAPSED row sits in the none-valid cases.
	assert.Empty(t, queryIDs(t, amended, "--poams", "valid", "--id", "*CVE-2022-42919*"),
		"a requirement with no override carries no plan")
}

// A requirement where TWO amendments compete. The card singles this out as the
// newest and least exercised resolution, and it is: hdf-libs-wft3f.14 settled
// that overrides and POA&Ms resolve as ONE ordered set by appliedAt, and nothing
// at the CLI layer exercised a genuinely contested requirement.
func TestSmoke_ContestedRequirementResolvesByRecency(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)
	amended := applySmokeAmendments(t, dir, doc)

	// Grype/CVE-2020-13844 carries a waiver applied 2024-06-01 AND a POA&M
	// applied 2025-01-01. The newer entry governs the disposition even though the
	// older one is a waiver.
	contested := queryIDs(t, amended, "--disposition", "poam", "--id", "Grype/CVE-2020-13844")
	assert.Equal(t, []string{"Grype/CVE-2020-13844"}, contested,
		"the more recently applied amendment governs, whichever kind it is")

	assert.Empty(t, queryIDs(t, amended, "--disposition", "waiver", "--id", "Grype/CVE-2020-13844"),
		"the superseded waiver must not also claim the requirement")

	// And a requirement whose only amendment IS a waiver still reports one, so
	// the assertion above is about recency rather than waivers being ignored.
	assert.NotEmpty(t, queryIDs(t, amended, "--disposition", "waiver"),
		"other requirements are still governed by waivers")
}

// Every amendment type the schema defines that CAN be applied is represented, so
// a gate keyed on disposition is exercised against each rather than against the
// two that happened to be convenient.
func TestSmoke_EveryApplicableAmendmentTypeIsCovered(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)
	amended := applySmokeAmendments(t, dir, doc)

	// operationalRequirement is deliberately ABSENT and that is not an oversight:
	// it is valid to author and invalid once merged, because Standalone_Override
	// forbids it carrying a status while Status_Override requires one. Tracked as
	// hdf-libs-r42je.
	//
	// riskAdjustment is absent from THIS corpus for a different and measured
	// reason: merge-grype has ten failing requirements, six are amended here, and
	// the remainder is needed unadjudicated so the composite policy's rule has
	// something to fire on. Adding a seventh override consumed the last one and
	// turned TestSmoke_CompositePolicyGridAndRuleTogether red. It is covered
	// instead by the test below, against its own corpus.
	for _, kind := range []string{"waiver", "attestation", "falsePositive", "inherited", "poam"} {
		t.Run(kind, func(t *testing.T) {
			assert.NotEmpty(t, queryIDs(t, amended, "--disposition", kind),
				"%s must be reachable as a disposition after apply", kind)
		})
	}
}

// riskAdjustment is the one amendment type that changes a SCORE rather than a
// status, so it is the only one whose effect the disposition filter alone cannot
// show. Applied alone, against its own corpus, so the shared one keeps its
// unadjudicated requirement.
func TestSmoke_InForceRiskAdjustmentRescoresWithoutSuppressing(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)

	out := filepath.Join(dir, "adjusted.json")
	_, _, err := executeCommand("amend", "apply",
		"--results", doc,
		"--amendments", filepath.Join("testdata", "threshold-smoke-risk-adjustment.json"),
		"-o", out)
	require.NoError(t, err, "an in-force risk adjustment must apply")

	const id = "Grype/CVE-2022-42919"
	assert.Contains(t, queryIDs(t, out, "--disposition", "riskAdjustment"), id,
		"riskAdjustment must be reachable as a disposition after apply")

	// The pair is the point: the adjudication moves the EFFECTIVE score and leaves
	// the requirement's own score alone. Asserting only one of them would pass
	// against an implementation that overwrote the original.
	assert.NotEmpty(t, queryIDs(t, out, "--id", id, "--raw-impact", ">=0.7"),
		"the requirement's own impact must survive the re-score")
	assert.NotEmpty(t, queryIDs(t, out, "--id", id, "--impact", "<0.4"),
		"the effective impact must reflect the re-score")
	assert.Empty(t, queryIDs(t, out, "--id", id, "--impact", ">=0.7"),
		"and nothing may still report the pre-adjustment effective impact")

	// A risk adjustment re-scores; it does not suppress. The finding still fails.
	assert.NotEmpty(t, queryIDs(t, out, "--id", id, "--status", "failed"),
		"a re-scored finding still fails — riskAdjustment is not a waiver")
}

// An amendment that has already lapsed cannot be applied at all, which is the
// CLI-level half of "a lapsed amendment no longer governs". The engine half — a
// lapsed override in an already-amended document being ignored — is pinned by the
// shared amendment case table and is not repeated here.
func TestSmoke_ExpiredAmendmentIsRefusedByApply(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)
	expired := filepath.Join("testdata", "threshold-smoke-expired-amendment.json")

	_, _, err := executeCommand("amend", "apply",
		"--results", doc, "--amendments", expired, "-o", filepath.Join(dir, "out.json"))
	require.Error(t, err, "an expired amendment must not be applied")
	assert.Contains(t, err.Error(), "expired")
}

// applySmokeAmendments applies the committed amendment fixture through the real
// command, so the amended document under test is one the tooling actually
// produces rather than one assembled here.
func applySmokeAmendments(t *testing.T, dir, results string) string {
	t.Helper()
	out := filepath.Join(dir, "amended.json")
	_, _, err := executeCommand("amend", "apply",
		"--results", results,
		"--amendments", filepath.Join("testdata", "threshold-smoke-amendments.json"),
		"-o", out)
	require.NoError(t, err, "applying the smoke amendments must succeed")
	return out
}

// The card's own first failing test: a policy combining a GRID bound, a RULE with
// an amendments predicate, and a compliance minimum, asserting the verdict and the
// exit code. Every other policy here exercises one mechanism; an operator writes
// both in one file, and the two halves are evaluated by different code — the grid
// counts through the control map, a rule filters — so a policy carrying both is
// the only place their interaction shows.
func TestSmoke_CompositePolicyGridAndRuleTogether(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)
	amended := applySmokeAmendments(t, dir, doc)

	policy := writeResultsAt(t, dir, "composite.yaml", strings.Join([]string{
		"compliance:",
		"  min: 95",
		"failed:",
		"  total:",
		"    max: 0",
		"rules:",
		"  - name: nothing failing is unadjudicated",
		"    where:",
		"      status: failed",
		"      disposition: {not: [waiver, poam, riskAdjustment]}",
		"    max: 0",
	}, "\n")+"\n")

	_, stderr, err := executeCommand("validate", "threshold", amended, "-T", policy)
	require.Error(t, err, "this document breaches all three bounds")

	// All three halves report, in one verdict, against one document.
	assert.Contains(t, stderr, "compliance", "the percentage bound reports")
	assert.Contains(t, stderr, "failed.total", "the grid count bound reports")
	assert.Contains(t, stderr, "nothing failing is unadjudicated", "the rule reports")

	// The count in the grid's message and the rule's are computed by DIFFERENT
	// code over the same document — the control map versus the filter — so a
	// divergence between them is invisible to either mechanism's own tests.
	grid := regexp.MustCompile(`failed\.total: (\d+) exceeds`).FindStringSubmatch(stderr)
	require.NotNil(t, grid, "the grid bound must report a count; got: %s", stderr)
	assert.Equal(t, grid[1], fmt.Sprint(len(queryIDs(t, amended, "--status", "failed"))),
		"the grid's count and hdf query must agree about the same document")

	// And a composite policy the document SATISFIES passes as a whole, so the
	// failure above is not simply a policy that can never pass.
	lenient := writeResultsAt(t, dir, "lenient.yaml", strings.Join([]string{
		"compliance:",
		"  min: 1",
		"failed:",
		"  total:",
		"    max: 99",
		"rules:",
		"  - name: nothing above CVSS 11",
		"    where:",
		"      cvss: \">=11\"",
		"    max: 0",
	}, "\n")+"\n")
	_, _, err = executeCommand("validate", "threshold", amended, "-T", lenient)
	require.NoError(t, err, "a composite policy the document satisfies must pass as a whole")
}

// A generated threshold must validate its own document. This is the round trip
// hdf-libs-tqgp fixed, and it exercises every bucket of the grid at once against
// real converter output — the broadest single assertion available.
func TestSmoke_GeneratedThresholdValidatesItsOwnDocument(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"grype.json", fixtures.Results.MergeGrype},
		{"zap.json", fixtures.Results.MergeZap},
		{"inspec.json", fixtures.Results.InspecMultilayered},
		{"prisma.json", fixtures.Results.DuplicateBaselines},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			doc := smokeDoc(t, dir, tc.name, tc.body)
			gen := filepath.Join(dir, "generated.yaml")

			_, _, err := executeCommand("generate", "threshold", doc, "-o", gen)
			require.NoError(t, err, "generating a threshold from a real document must succeed")

			_, stderr, err := executeCommand("validate", "threshold", doc, "-T", gen)
			require.NoError(t, err,
				"a generated threshold must validate the document it came from; stderr: %s", stderr)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge cases
// ─────────────────────────────────────────────────────────────────────────────

// A document whose requirements carry NO ids: ZAP output has four baselines and
// no requirement ids. A finding line still has to say something useful, and a
// controls list has to behave rather than panic.
func TestSmoke_DocumentWithoutRequirementIDs(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "zap.json", fixtures.Results.MergeZap)

	_, stderr, err := executeCommand("validate", "threshold", doc, "-I", "{failed: {total: {max: 0}}}")
	require.Error(t, err, "every ZAP requirement is failed")
	assert.Contains(t, stderr, "zap.json")
	assert.NotEmpty(t, findingIDs(t, stderr), "findings are listed even without ids")

	// A controls list naming something absent is refused, and says so, rather
	// than passing because nothing matched.
	_, stderr, err = executeCommand("validate", "threshold", doc,
		"-I", "{failed: {total: {controls: [NOPE-1]}}}")
	require.Error(t, err)
	assert.Contains(t, stderr, "NOPE-1")
}

// Duplicate requirement ids are real converter output, not a fixture artefact.
// A gate over such a document must still count and name correctly.
func TestSmoke_DuplicateRequirementIDs(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "prisma.json", fixtures.Results.DuplicateBaselines)

	_, stderr, err := executeCommand("validate", "threshold", doc, "-I", "{failed: {total: {max: 0}}}")
	require.Error(t, err)

	// The count in the message must equal the number of lines under it. A
	// document with repeated ids is exactly where a de-duplicating bug would
	// make those two disagree.
	m := regexp.MustCompile(`failed\.total: (\d+) exceeds`).FindStringSubmatch(stderr)
	require.NotNil(t, m, "the violation must report a count; got: %s", stderr)
	assert.Equal(t, m[1], fmt.Sprint(len(findingIDs(t, stderr))),
		"the findings listed must be as many as the message counted")
}

// The grammar, end to end on a real document: a scalar, a list and a negation in
// one predicate, plus the refusals. Each is pinned in the engine's tables; this
// asserts they survive the whole path from a policy file to a verdict.
func TestSmoke_PredicateGrammarThroughTheRealCommand(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)

	t.Run("scalar and list forms together", func(t *testing.T) {
		policy := writeResultsAt(t, dir, "mixed.yaml", strings.Join([]string{
			"rules:",
			"  - name: mixed forms",
			"    where:",
			"      status: failed",             // scalar
			"      severity: [critical, high]", // list
			"    max: 0",
		}, "\n")+"\n")
		_, stderr, err := executeCommand("validate", "threshold", doc, "-T", policy)
		// require, not if: guarding the assertions behind "did it fail" meant the
		// subtest passed silently the moment the rule stopped matching.
		require.Error(t, err, "this document has failing highs")
		assert.Equal(t,
			queryIDs(t, doc, "--status", "failed", "--severity", "critical", "--severity", "high"),
			findingIDs(t, stderr),
			"the rule and the query must select the same set for the same predicate")
	})

	// Negation gets its own subtest against an AMENDED document, and asserts a set
	// DIFFERENCE rather than an equality, because neither of those is incidental.
	//
	// It cannot be checked the way every other predicate here is checked: `hdf
	// query` has no flag for negation at all, so there is no "same question asked
	// of the other surface" to compare against. The effect is pinned instead by
	// arithmetic over two positive queries, which the CLI can express.
	//
	// And it must negate `poam`, not `waiver`. A waiver resolves the requirement to
	// passed, so `status: failed` with `disposition: waiver` is empty on EVERY
	// document and negating it excludes nothing — the predicate would be a no-op
	// and the subtest would pass against a filter that ignored disposition
	// entirely. A POA&M leaves the status failed, so negating it removes real rows.
	t.Run("negation excludes exactly the governed rows", func(t *testing.T) {
		amended := applySmokeAmendments(t, dir, doc)

		allFailing := queryIDs(t, amended, "--status", "failed")
		governed := queryIDs(t, amended, "--status", "failed", "--disposition", "poam")
		require.NotEmpty(t, governed,
			"the corpus must leave some failing requirement under a plan, or this asserts nothing")
		require.Less(t, len(governed), len(allFailing),
			"and must leave some failing requirement NOT under a plan, or the rule matches nothing")

		policy := writeResultsAt(t, dir, "negation.yaml", strings.Join([]string{
			"rules:",
			"  - name: failing and not under a plan",
			"    where:",
			"      status: failed",
			"      disposition: {not: [poam]}",
			"    max: 0",
		}, "\n")+"\n")
		_, stderr, err := executeCommand("validate", "threshold", amended, "-T", policy)
		require.Error(t, err)

		governedSet := make(map[string]bool, len(governed))
		for _, id := range governed {
			governedSet[id] = true
		}
		var expected []string
		for _, id := range allFailing {
			if !governedSet[id] {
				expected = append(expected, id)
			}
		}
		assert.Equal(t, expected, findingIDs(t, stderr),
			"a negated disposition must select every failing requirement except the governed ones")
	})

	// The refusal cases that used to sit here were DELETED, not lost: each was a
	// strictly weaker restatement of a test that already asserts more. Three live
	// in threshold_test.go, which pins the same spec string AND the rule name AND
	// the accepted counterpart — TestValidateThreshold_ColonlessTagIsRefused,
	// _TypoInsideNotIsRefused, and the empty-mapping row. The fourth, an empty
	// `not`, is pinned in hdf-engine/go/values_test.go instead: it is a decoder
	// refusal rather than a CLI one, so no CLI-level test asserts it and this
	// comment should not imply otherwise. Repeating any of them here would have
	// made this file look broader than it is, which is the opposite of what a
	// smoke test is for.
}

// Several per-tool policies in one invocation, which is the shape a pipeline
// gating many scanners uses. Each violation must name the policy it came from,
// or a red build says which document failed but not which rule.
func TestSmoke_PerToolPoliciesAreAttributed(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)
	strict := writeResultsAt(t, dir, "osv.yaml", "failed:\n  total:\n    max: 0\n")
	loose := writeResultsAt(t, dir, "grype.yaml", "failed:\n  total:\n    max: 999\n")

	_, stderr, err := executeCommand("validate", "threshold", doc, "-T", strict, "-T", loose)
	require.Error(t, err, "one of the two policies is breached")
	// The label is the path the policy was given, so match on its basename.
	assert.Contains(t, stderr, "osv.yaml] failed.total", "the breached policy is named")
	assert.NotContains(t, stderr, "grype.yaml]", "the satisfied policy is not blamed")
}

// --no-findings suppresses the list without changing the verdict, which is what
// makes it safe for a gate over thousands of findings.
func TestSmoke_NoFindingsKeepsTheVerdict(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "prisma.json", fixtures.Results.DuplicateBaselines)

	_, withList, err := executeCommand("validate", "threshold", doc, "-I", "{failed: {total: {max: 0}}}")
	require.Error(t, err)
	require.NotEmpty(t, findingIDs(t, withList))

	_, without, err := executeCommand("validate", "threshold", doc, "-I", "{failed: {total: {max: 0}}}", "--no-findings")
	require.Error(t, err, "suppressing the list must not change the verdict")
	assert.Contains(t, without, "failed.total")
	assert.Empty(t, findingIDs(t, without))
}

// SAF's scalar shorthand means EXACTLY that many, not "at most". A pipeline
// migrating a SAF threshold file depends on it.
func TestSmoke_SafScalarShorthandMeansExactly(t *testing.T) {
	dir := t.TempDir()
	doc := smokeDoc(t, dir, "scan.json", fixtures.Results.MergeGrype)

	failed := len(queryIDs(t, doc, "--status", "failed"))
	require.Positive(t, failed)

	_, _, err := executeCommand("validate", "threshold", doc,
		"-I", fmt.Sprintf("{failed: {total: %d}}", failed))
	require.NoError(t, err, "the exact count must satisfy the shorthand")

	_, _, err = executeCommand("validate", "threshold", doc,
		"-I", fmt.Sprintf("{failed: {total: %d}}", failed+1))
	require.Error(t, err, "a scalar bound is exact, so one more must fail")
}
