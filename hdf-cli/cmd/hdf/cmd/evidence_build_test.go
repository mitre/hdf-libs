package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The evidence-package schema permits seven Content_Type values; build reached
// four. A package that cannot name the plan it was assessed against cannot be
// completeness-verified without a second command, so plan and baseline are
// carried here alongside the root planRef that verify reads.
func TestEvidenceBuild_ReferencesPlanAndBaseline(t *testing.T) {
	tmpDir := t.TempDir()

	write := func(name, body string) string {
		p := filepath.Join(tmpDir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}

	systemPath := write("system.json",
		`{"name": "portal", "components": [{"name": "c1", "type": "application"}]}`)
	resultsPath := write("results.json", noTargetsJSON)
	planPath := write("plan.json",
		`{"name": "q3-plan", "assessments": [{"baselineRef": "RHEL9-STIG"}]}`)
	baselinePath := write("baseline.json",
		`{"name": "rhel9-stig", "requirements": []}`)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
		"--plan", planPath,
		"--baseline", baselinePath,
		"-o", outputPath,
	)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	types := make([]string, 0)
	for _, c := range pkg["contents"].([]interface{}) {
		types = append(types, c.(map[string]interface{})["type"].(string))
	}
	assert.Contains(t, types, "hdf-plan", "the plan must be listed in contents")
	assert.Contains(t, types, "hdf-baseline", "the baseline must be listed in contents")

	// planRef is what `hdf evidence verify` reads to check completeness; build
	// must set it so no separate `evidence set --plan-ref` step is needed.
	assert.Equal(t, "plan.json", pkg["planRef"],
		"build must set root planRef from --plan")
}

// writeEvidenceInputs lays down one document of every kind a package can carry.
// The BOM is real CycloneDX shape: it must NOT fingerprint as an HDF document,
// which is what lets --bom accept it.
func writeEvidenceInputs(t *testing.T, dir string) map[string]string {
	t.Helper()
	docs := map[string]string{
		"system.json":   `{"name": "portal", "components": [{"name": "c1", "type": "application"}]}`,
		"results.json":  noTargetsJSON,
		"plan.json":     `{"name": "q3-plan", "assessments": [{"baselineRef": "RHEL9-STIG"}]}`,
		"baseline.json": `{"name": "rhel9-stig", "requirements": []}`,
		// Representative CycloneDX: a real SBOM carries components[], which is
		// what made an earlier --bom fingerprint guard reject real input while
		// this fixture passed. Keep components[] here or that bug returns unseen.
		"sbom.cdx.json": `{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
			"components": [{"type": "library", "name": "openssl", "version": "3.0.2"}]}`,
		"amendments.json": `{"name": "waivers", "overrides": []}`,
		"comparison.json": `{"formatVersion": "1.0.0", "comparisonMode": "temporal", "sources": [], "summary": {}, "requirementDiffs": []}`,
	}
	paths := make(map[string]string, len(docs))
	for name, body := range docs {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		paths[name] = p
	}
	return paths
}

// Every Content_Type the schema permits must be reachable from build. A type the
// schema allows but the CLI cannot emit is a hole in the package, not a missing
// convenience — the seven values are the contract.
func TestEvidenceBuild_ReachesAllSevenContentTypes(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--plan", p["plan.json"],
		"--baseline", p["baseline.json"],
		"--bom", p["sbom.cdx.json"],
		"--amendments", p["amendments.json"],
		"--comparison", p["comparison.json"],
		"-o", outputPath,
	)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	seen := map[string]bool{}
	for _, c := range pkg["contents"].([]interface{}) {
		entry := c.(map[string]interface{})
		seen[entry["type"].(string)] = true
		// A content entry without a checksum cannot be verified later, which
		// defeats the point of listing it.
		cs, ok := entry["checksum"].(map[string]interface{})
		require.True(t, ok, "entry %v has no checksum", entry["uri"])
		assert.Equal(t, "sha256", cs["algorithm"])
		assert.Len(t, cs["value"], 64, "checksum for %v is not a sha256 hex digest", entry["uri"])
	}

	for _, want := range []string{
		"hdf-system", "hdf-results", "hdf-plan",
		"hdf-baseline", "bom", "hdf-amendments", "hdf-comparison",
	} {
		assert.True(t, seen[want], "content type %q is not reachable from build", want)
	}
	assert.Len(t, seen, 7, "expected all seven Content_Type values, got %v", seen)

	// build validates before it writes; assert it independently so a future
	// change that drops that guard fails here.
	require.NoError(t, validateHDFDocument(data), "the emitted package must satisfy the schema")
}

// A real accreditation carries waivers from more than one source. Single-valued
// flags could not express that.
func TestEvidenceBuild_AmendmentsAndComparisonAreRepeatable(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)

	second := filepath.Join(tmpDir, "amendments-2.json")
	require.NoError(t, os.WriteFile(second,
		[]byte(`{"name": "platform-waivers", "overrides": []}`), 0o600))
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--amendments", p["amendments.json"],
		"--amendments", second,
		"-o", outputPath,
	)
	require.NoError(t, err)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	count := 0
	for _, c := range pkg["contents"].([]interface{}) {
		if c.(map[string]interface{})["type"] == "hdf-amendments" {
			count++
		}
	}
	assert.Equal(t, 2, count, "both amendments documents must be listed")
}

// A mistyped content entry is worse than a refused one: verify reads these types
// to judge completeness, so a baseline filed as a plan produces a confident
// wrong verdict.
func TestEvidenceBuild_RejectsMistypedDocument(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--plan", p["baseline.json"], // a baseline handed to --plan
		"-o", outputPath,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected plan")
	assert.NoFileExists(t, outputPath, "no package should be written when an input is mistyped")
}

// --bom must accept a real CycloneDX SBOM. hdfengine.Detect classifies ANY root
// `components` key as an HDF system, and components[] is CycloneDX's primary
// field, so any fingerprint guard on --bom rejects the dominant BOM format. This
// test exists to keep one from being reintroduced.
func TestEvidenceBuild_BomAcceptsRealCycloneDX(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	// Precondition: this fixture really does fingerprint as an HDF system, which
	// is the collision that makes a guard here wrong.
	sbom, readErr := os.ReadFile(p["sbom.cdx.json"])
	require.NoError(t, readErr)
	require.Equal(t, "system", detectHDFDocumentType(sbom),
		"precondition: a CycloneDX SBOM collides with the HDF system fingerprint")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--bom", p["sbom.cdx.json"],
		"-o", outputPath,
	)
	require.NoError(t, err, "a real CycloneDX SBOM must be accepted by --bom")

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	found := false
	for _, c := range pkg["contents"].([]interface{}) {
		if c.(map[string]interface{})["type"] == "bom" {
			found = true
		}
	}
	assert.True(t, found, "the SBOM must be listed as a bom content entry")
}

// An unset shell variable (--amendments "$AMEND") was a no-op before these flags
// became repeatable. It must stay one: readInputFile("") reads stdin, so without
// this the build swallows stdin and lists a content entry whose uri is ".".
func TestEvidenceBuild_EmptyPathElementIsANoOp(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--amendments", "",
		"--baseline", "",
		"--bom", "",
		"--comparison", "",
		"-o", outputPath,
	)
	require.NoError(t, err, "empty path elements must be ignored, not read as stdin")

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	entries := pkg["contents"].([]interface{})
	assert.Len(t, entries, 2, "only the system and results documents should be listed")
	for _, c := range entries {
		assert.NotEqual(t, ".", c.(map[string]interface{})["uri"],
			"an empty path must never become a content entry")
	}
}

// Repeatability was asserted only for --amendments; the other three flags carry
// the same contract and nothing held them to it.
func TestEvidenceBuild_BaselineBomAndComparisonAreRepeatable(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)

	second := func(name, body string) string {
		q := filepath.Join(tmpDir, name)
		require.NoError(t, os.WriteFile(q, []byte(body), 0o600))
		return q
	}
	baseline2 := second("baseline-2.json", `{"name": "pg-stig", "requirements": []}`)
	bom2 := second("sbom-2.cdx.json", `{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"components": [{"type": "library", "name": "zlib", "version": "1.3"}]}`)
	comparison2 := second("comparison-2.json",
		`{"formatVersion": "1.0.0", "comparisonMode": "fleet", "sources": [], "summary": {}, "requirementDiffs": []}`)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--baseline", p["baseline.json"], "--baseline", baseline2,
		"--bom", p["sbom.cdx.json"], "--bom", bom2,
		"--comparison", p["comparison.json"], "--comparison", comparison2,
		"-o", outputPath,
	)
	require.NoError(t, err)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	counts := map[string]int{}
	for _, c := range pkg["contents"].([]interface{}) {
		counts[c.(map[string]interface{})["type"].(string)]++
	}
	assert.Equal(t, 2, counts["hdf-baseline"], "both baselines must be listed")
	assert.Equal(t, 2, counts["bom"], "both BOMs must be listed")
	assert.Equal(t, 2, counts["hdf-comparison"], "both comparisons must be listed")
}

// The point of build setting planRef: `evidence verify` is documented as
// verifying a package against its assessment plan, and planRef is what it reads.
// Before this card that needed a second command (`evidence set --plan-ref`), so a
// one-command build produced a package verify could not fully check.
//
// Uses the real evidence-verify fixtures, and writes the package into their
// directory because content URIs are relative to the package.
func TestEvidenceBuild_VerifiesAgainstThePlanWithoutEvidenceSet(t *testing.T) {
	outputPath := filepath.Join(evidenceFixtureDir, "built-complete-package.json")
	t.Cleanup(func() { _ = os.Remove(outputPath) })

	_, _, err := executeCommand("evidence", "build",
		"--system", filepath.Join(evidenceFixtureDir, "system.json"),
		"--results", filepath.Join(evidenceFixtureDir, "rhel9-results.json"),
		"--results", filepath.Join(evidenceFixtureDir, "postgres-results.json"),
		"--plan", filepath.Join(evidenceFixtureDir, "plan.json"),
		"-o", outputPath,
	)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	require.Equal(t, "plan.json", pkg["planRef"],
		"precondition: build must have set planRef itself")

	_, _, verifyErr := executeCommand("evidence", "verify", outputPath)
	require.NoError(t, verifyErr,
		"verify must succeed against a package built in one command")
}

// The complement, and the reason the test above is not vacuous: if build wrote no
// planRef, or verify ignored it, there would be no plan to check against and the
// success above would prove nothing. Here the plan demands two baselines and the
// package carries results for only one, so verify must FAIL and name the gap.
func TestEvidenceBuild_PlanRefIsActuallyReadByVerify(t *testing.T) {
	outputPath := filepath.Join(evidenceFixtureDir, "built-incomplete-package.json")
	t.Cleanup(func() { _ = os.Remove(outputPath) })

	_, _, err := executeCommand("evidence", "build",
		"--system", filepath.Join(evidenceFixtureDir, "system.json"),
		"--results", filepath.Join(evidenceFixtureDir, "rhel9-results.json"),
		"--plan", filepath.Join(evidenceFixtureDir, "plan.json"),
		"-o", outputPath,
	)
	require.NoError(t, err)

	_, _, verifyErr := executeCommand("evidence", "verify", outputPath)
	require.Error(t, verifyErr,
		"verify must detect the plan baseline that has no results")
	assert.Contains(t, verifyErr.Error(), "PostgreSQL-STIG",
		"the failure must name the uncovered baseline, proving the plan was read")
}

// --results carries the same empty-path hazard as the four array flags: it was
// already StringArrayVar before this card, so `--results ""` read stdin. Fixed
// here rather than left as a sibling inconsistency, since --baseline "" is now
// safe and a user has no reason to expect the two to differ.
func TestEvidenceBuild_EmptyResultsPathIsANoOp(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"--results", "",
		"-o", outputPath,
	)
	require.NoError(t, err, "an empty --results element must be ignored, not read as stdin")

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	entries := pkg["contents"].([]interface{})
	assert.Len(t, entries, 2, "only the system and the one real results document")
	for _, c := range entries {
		assert.NotEqual(t, ".", c.(map[string]interface{})["uri"])
	}
}
