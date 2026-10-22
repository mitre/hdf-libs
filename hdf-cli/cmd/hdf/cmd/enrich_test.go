package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrichFixturePath resolves a committed shared enrich fixture (the real OASIS
// Poison Ivy bundle + its paired results doc) from the sibling hdf-converters package.
func enrichFixturePath(name string) string {
	return filepath.Join("..", "..", "..", "..", "hdf-converters", "shared", "enrich-fixtures", name)
}

func findEnrichedReq(t *testing.T, data []byte, id string) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	for _, b := range doc["baselines"].([]interface{}) {
		for _, r := range b.(map[string]interface{})["requirements"].([]interface{}) {
			req := r.(map[string]interface{})
			if req["id"] == id {
				return req
			}
		}
	}
	t.Fatalf("requirement %q not found", id)
	return nil
}

func TestEnrichCmd_AutoDetectSTIXToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"-o", out)
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "results", detectHDFDocumentType(data), "output is an HDF results doc")

	// Enrichment landed: the CVE-2012-0158 finding carries the matching STIX ref.
	refs := findEnrichedReq(t, data, "CVE-2012-0158")["externalReferences"].([]interface{})
	require.Len(t, refs, 1)
	ref := refs[0].(map[string]interface{})
	assert.Equal(t, "stix", ref["sourceName"])
	assert.Equal(t, "threat-intel", ref["kind"])
	assert.Equal(t, "vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab34361a2", ref["externalId"])
}

func TestEnrichCmd_OutputValidates(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"-o", out)
	require.NoError(t, err)

	stdout, _, verr := executeCommand("validate", out)
	require.NoError(t, verr)
	assert.Contains(t, stdout, "valid HDF results")
}

func TestEnrichCmd_FromStixAssert(t *testing.T) {
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"--from", "stix")
	require.NoError(t, err)
}

func TestEnrichCmd_Stdout(t *testing.T) {
	stdout, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"))
	require.NoError(t, err)
	assert.Contains(t, stdout, `"sourceName": "stix"`)
}

func TestEnrichCmd_NoMisroute(t *testing.T) {
	// A results doc is not a STIX bundle — auto-detect must fail, not misroute.
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("results-input.json"))
	require.Error(t, err)

	// --from stix asserted on a non-bundle → error (assert-then-detect, no force-parse).
	_, _, err2 := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("results-input.json"),
		"--from", "stix")
	require.Error(t, err2)
}

func TestEnrichCmd_UnsupportedFrom(t *testing.T) {
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-stix21.json"),
		"--from", "bogus")
	require.Error(t, err)
}

func TestEnrichCmd_ResultsPositionalMustBeResults(t *testing.T) {
	// First positional must be a results doc; passing the bundle there → error.
	_, _, err := executeCommand("enrich",
		enrichFixturePath("poison-ivy-stix21.json"),
		enrichFixturePath("poison-ivy-stix21.json"))
	require.Error(t, err)
}

func TestEnrichCmd_RejectsSchemaInvalidResults(t *testing.T) {
	// A doc that sniffs as results (has a baselines key) but is not valid HDF
	// must be rejected at the boundary, matching the events commands.
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"baselines":[{"bogus":true}]}`), 0o600))
	_, _, err := executeCommand("enrich", bad, enrichFixturePath("poison-ivy-stix21.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid hdf-results document")
}

func TestEnrichCmd_Recompute(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := executeCommand("enrich",
		enrichFixturePath("results-with-cvss.json"),
		enrichFixturePath("poison-ivy-exploited-stix21.json"),
		"--recompute-cvss", "-o", out)
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	// Output is schema-valid.
	stdout, _, verr := executeCommand("validate", out)
	require.NoError(t, verr)
	assert.Contains(t, stdout, "valid HDF results")

	// End-to-end: the authored inline riskAdjustment carries the recomputed
	// impact and a not-yet-expired review horizon, so any downstream
	// effective-impact resolver will surface it.
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	var req hdf.EvaluatedRequirement
	found := false
	for _, b := range results.Baselines {
		for _, r := range b.Requirements {
			if r.ID == "CVE-2012-0158" {
				req = r
				found = true
			}
		}
	}
	require.True(t, found, "CVE-2012-0158 finding present")
	require.Len(t, req.StatusOverrides, 1, "riskAdjustment authored")

	authored := req.StatusOverrides[0]
	require.NotNil(t, authored.Impact, "riskAdjustment carries an impact value")
	assert.InDelta(t, 0.98, authored.Impact.Value, 1e-9, "E:H recompute of the 9.8 base vector → impact 0.98")
	assert.True(t, authored.ExpiresAt.After(time.Now()), "review horizon is in the future")
}

// externalReferences[] is declared on five document types — results, system, plan,
// comparison and evidence-package — but enrich read its first argument as results
// and refused everything else, so there was no way to attach threat intel or an
// advisory to a system or a plan even though the schema models it. evidence-package
// is deliberately excluded here: hdf evidence add-reference owns that array on that
// type, and two commands writing one field on one document is the ambiguity worth
// avoiding.
func TestEnrich_AttachesReferencesToASystemDocument(t *testing.T) {
	dir := t.TempDir()
	sysBody, err := os.ReadFile(filepath.Join("cmd", "hdf", "cmd", "testdata", "evidence-verify", "system.json"))
	if err != nil {
		// The test runs with the package dir as CWD, so try the direct path too.
		sysBody, err = os.ReadFile(filepath.Join("testdata", "evidence-verify", "system.json"))
	}
	require.NoError(t, err)
	sysPath := filepath.Join(dir, "system.json")
	require.NoError(t, os.WriteFile(sysPath, sysBody, 0o600))
	out := filepath.Join(dir, "enriched.json")

	_, _, enrichErr := executeCommand("enrich", sysPath, enrichFixturePath("poison-ivy-stix21.json"), "-o", out)
	require.NoError(t, enrichErr, "a system document declares externalReferences and must be enrichable")

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))

	refs, ok := doc["externalReferences"].([]interface{})
	require.True(t, ok, "the references must land at the system document's root")
	assert.NotEmpty(t, refs, "at least one STIX object should have been attached")

	// A system document has no requirements, so nothing may be invented to match on.
	assert.NotContains(t, string(data), `"requirements"`,
		"enrich must not fabricate a requirement to hang a reference from")

	// And the enriched document must still be a valid system document.
	_, _, validateErr := executeCommand("validate", out)
	require.NoError(t, validateErr, "the enriched system document must still validate")
}

// The acceptance surface, as one table so a type cannot be added to the code without
// a row here. Four types declare externalReferences AND are enrichment targets;
// evidence-package declares the field but `hdf evidence add-reference` owns it; and
// baseline and amendments declare it nowhere. Each refusal must say WHY and, where
// there is somewhere better to go, where.
func TestEnrich_AcceptsEveryTypeThatDeclaresExternalReferences(t *testing.T) {
	bundle := enrichFixturePath("poison-ivy-stix21.json")
	evidenceFixture := func(t *testing.T, name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("testdata", "evidence-verify", name))
		require.NoError(t, err)
		return b
	}

	for _, tc := range []struct {
		name, fixture, wantErr string
	}{
		{name: "results", fixture: "rhel9-results.json"},
		{name: "system", fixture: "system.json"},
		{name: "plan", fixture: "plan.json"},
		{name: "comparison", fixture: "comparison.json"},
		{
			name: "evidence-package", fixture: "evidence.json",
			wantErr: "`hdf evidence add-reference`",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, tc.fixture)
			require.NoError(t, os.WriteFile(in, evidenceFixture(t, tc.fixture), 0o600))
			out := filepath.Join(dir, "enriched.json")

			_, _, err := executeCommand("enrich", in, bundle, "-o", out)
			if tc.wantErr != "" {
				require.Error(t, err, "%s must be refused", tc.name)
				assert.Contains(t, err.Error(), tc.wantErr,
					"the refusal must point at the command that owns that array")
				assert.NoFileExists(t, out, "a refused enrich must write nothing")
				return
			}
			require.NoError(t, err, "%s declares externalReferences and must be enrichable", tc.name)
			// Every enriched document must still validate against its OWN schema.
			_, _, validateErr := executeCommand("validate", out)
			require.NoError(t, validateErr, "the enriched %s must still validate", tc.name)
		})
	}
}

// baseline and amendments declare no externalReferences[] anywhere, so the refusal
// has to say that rather than pointing at another command — there is nowhere to go.
func TestEnrich_RefusesATypeThatDeclaresNoExternalReferences(t *testing.T) {
	dir := t.TempDir()
	amendments := filepath.Join(dir, "amendments.json")
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "hdf-fixtures", "amendments", "uc-01-fixed-amendments.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(amendments, body, 0o600))

	_, _, enrichErr := executeCommand("enrich", amendments, enrichFixturePath("poison-ivy-stix21.json"),
		"-o", filepath.Join(dir, "out.json"))
	require.Error(t, enrichErr)
	assert.Contains(t, enrichErr.Error(), "declares no externalReferences[]",
		"the refusal must name the reason, not just decline")
}

// The type comes from the document's own content, never from its name. A system
// document called results.json is still a system document, and enriching it must not
// validate it against the results schema.
func TestEnrich_DetectsTheTypeFromContentNotTheFilename(t *testing.T) {
	dir := t.TempDir()
	body, err := os.ReadFile(filepath.Join("testdata", "evidence-verify", "system.json"))
	require.NoError(t, err)
	misleading := filepath.Join(dir, "definitely-results.json")
	require.NoError(t, os.WriteFile(misleading, body, 0o600))
	out := filepath.Join(dir, "out.json")

	_, stderr, enrichErr := executeCommand("enrich", misleading, enrichFixturePath("poison-ivy-stix21.json"), "-o", out)
	require.NoError(t, enrichErr, "the filename must not make this a results document")
	assert.Contains(t, stderr, "at the document root",
		"a system document has no findings, so everything attaches at the root")

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Contains(t, doc, "externalReferences")
	assert.NotContains(t, doc, "baselines", "nothing may be invented to make it look like results")
}

// --recompute-cvss authors a riskAdjustment on a finding. The other three types have
// no findings, so the flag is refused with the reason rather than silently ignored —
// silently ignoring it would let an operator believe a posture change was applied.
func TestEnrich_RecomputeCVSSIsResultsOnly(t *testing.T) {
	dir := t.TempDir()
	body, err := os.ReadFile(filepath.Join("testdata", "evidence-verify", "system.json"))
	require.NoError(t, err)
	sys := filepath.Join(dir, "system.json")
	require.NoError(t, os.WriteFile(sys, body, 0o600))
	out := filepath.Join(dir, "out.json")

	_, _, enrichErr := executeCommand("enrich", sys, enrichFixturePath("poison-ivy-stix21.json"),
		"--recompute-cvss", "-o", out)
	require.Error(t, enrichErr, "--recompute-cvss must be refused on a system document")
	assert.Contains(t, enrichErr.Error(), "results-only")
	assert.Contains(t, enrichErr.Error(), "no findings to apply one to",
		"the message must explain why, not just refuse")
	assert.NoFileExists(t, out, "a refused run writes nothing")

	// Unchanged for results: the flag still works where findings exist.
	_, _, resultsErr := executeCommand("enrich", enrichFixturePath("results-input.json"),
		enrichFixturePath("poison-ivy-exploited-stix21.json"), "--recompute-cvss",
		"-o", filepath.Join(dir, "results-out.json"))
	require.NoError(t, resultsErr, "results must keep accepting --recompute-cvss")
}

// `hdf enrich --help` must name the same container the enrich pass names in its
// truncation warning: the label is derived from the shared table both languages
// assert against, so the help cannot drift from observable behaviour again.
func TestEnrichCmd_HelpNamesTheSameRootAsTheWarning(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "hdf-converters", "shared", "enrich-stix-warning-cases.json"))
	require.NoError(t, err)
	var want struct {
		DocumentRootWarning string `json:"documentRootWarning"`
		ForbiddenPhrase     string `json:"forbiddenPhrase"`
	}
	require.NoError(t, json.Unmarshal(raw, &want))

	label := regexp.MustCompile(`enrich-stix (.+) references`).FindStringSubmatch(want.DocumentRootWarning)
	require.Len(t, label, 2, "the shared warning carries the container label")

	long := NewEnrichCmd().Long
	assert.Contains(t, long, label[1], "help names the container the truncation warning names")
	assert.NotContains(t, long, want.ForbiddenPhrase, "help must not name a container the pass never reports")
}
