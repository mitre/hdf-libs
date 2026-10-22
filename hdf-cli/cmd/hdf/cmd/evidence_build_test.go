package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	// planRef is what `hdf evidence info --verify` reads to check completeness; build
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
		assert.Equal(t, evidenceDigestAlgo, cs["algorithm"])
		assert.Len(t, cs["value"], len(evidenceDigestHex(nil)),
			"checksum for %v is not a %s hex digest", entry["uri"], evidenceDigestAlgo)
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

// --bom must accept a real CycloneDX SBOM. hdfengine.Detect classifies a root
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

// The point of build setting planRef: `evidence info --verify` is documented as
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

	_, _, verifyErr := executeCommand("evidence", "info", "--verify", outputPath)
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

	_, _, verifyErr := executeCommand("evidence", "info", "--verify", outputPath)
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

// A content reference is a path relative to the package's own directory, and the
// package sits at the root of the base directory — the artifacts folder a CI
// orchestrator hands from job to job. Documents may sit flat beside it or in
// subdirectories, as the pipeline prefers. Writing the basename describes only the
// flat layout, so a document in a subdirectory produced a ref that cannot resolve
// even though the resolver has always handled subdirectories.
func TestEvidenceBuild_RefsArePackageRelativeNotBasenames(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "scans"), 0o750))

	// Real fixtures, copied into a subdirectory layout.
	copyFixture := func(name, dest string) string {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
		require.NoError(t, err)
		p := filepath.Join(tmpDir, dest)
		require.NoError(t, os.WriteFile(p, src, 0o600))
		return p
	}
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "meta"), 0o750))
	systemPath := copyFixture("system.json", filepath.Join("meta", "system.json"))
	resultsPath := copyFixture("rhel9-results.json", filepath.Join("scans", "rhel9-results.json"))

	// A plan demanding only the baseline the copied results cover.
	planPath := filepath.Join(tmpDir, "meta", "plan.json")
	require.NoError(t, os.WriteFile(planPath,
		[]byte(`{"name": "q3", "assessments": [{"baselineRef": "RHEL9-STIG"}]}`), 0o600))

	outputPath := filepath.Join(tmpDir, "pkg.json")
	_, _, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
		"--plan", planPath,
		"-o", outputPath,
	)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	uris := map[string]string{}
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		uris[e["type"].(string)] = e["uri"].(string)
	}
	assert.Equal(t, "scans/rhel9-results.json", uris["hdf-results"],
		"a document in a subdirectory must keep its path relative to the package")
	assert.Equal(t, "meta/system.json", uris["hdf-system"],
		"the system document's subdirectory must survive too")

	// AC1 names systemRef and planRef alongside the content entries; they follow
	// the same rule, and forward slashes regardless of host OS.
	assert.Equal(t, "meta/system.json", pkg["systemRef"], "systemRef must be package-relative")
	assert.Equal(t, "meta/plan.json", pkg["planRef"], "planRef must be package-relative")

	// The point of the ref being right: the package must actually verify.
	_, _, verifyErr := executeCommand("evidence", "info", "--verify", outputPath)
	require.NoError(t, verifyErr,
		"a package whose documents sit in subdirectories must verify")
}

// AC3's branch: a document outside the package's own subtree is not a content
// reference at all. It must be refused by name, with both remedies stated, and no
// package written — never silently degraded to a basename that cannot resolve.
func TestEvidenceBuild_RefusesDocumentOutsideThePackageTree(t *testing.T) {
	outside := t.TempDir()
	base := t.TempDir()

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "system.json"))
	require.NoError(t, err)
	systemPath := filepath.Join(base, "system.json")
	require.NoError(t, os.WriteFile(systemPath, src, 0o600))

	strayResults := filepath.Join(outside, "rhel9-results.json")
	resSrc, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(strayResults, resSrc, 0o600))

	outputPath := filepath.Join(base, "pkg.json")
	_, _, buildErr := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", strayResults,
		"-o", outputPath,
	)
	require.Error(t, buildErr, "a document outside the package's directory must be refused")
	assert.Contains(t, buildErr.Error(), strayResults, "the error must name the document")
	assert.Contains(t, buildErr.Error(), "outside the evidence package's directory")
	assert.Contains(t, buildErr.Error(), "add-evidence",
		"the error must state the externalEvidence remedy")
	assert.NoFileExists(t, outputPath, "no package may be written when a reference cannot be formed")
}

// Regression guard for a false rejection this card introduced and fixed: the
// reference must be computed with symlinks resolved, because `evidence info --verify`
// confines through SafePath, which resolves them. Comparing lexically made two
// spellings of ONE directory look like different directories — on macOS /tmp
// versus /private/tmp — and refused a document plainly inside the package's
// directory, prescribing a remedy that was already satisfied.
func TestEvidenceBuild_SymlinkedSpellingIsNotOutsideTheTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevated privileges on Windows; the resolution logic is OS-independent")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	require.NoError(t, os.MkdirAll(target, 0o750))
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(target, link))

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "system.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(target, "system.json"), src, 0o600))
	resSrc, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(target, "rhel9-results.json"), resSrc, 0o600))

	// The system document is named through the symlink, the package through the
	// real path. Same directory, two spellings.
	outputPath := filepath.Join(target, "pkg.json")
	_, _, buildErr := executeCommand("evidence", "build",
		"--system", filepath.Join(link, "system.json"),
		"--results", filepath.Join(target, "rhel9-results.json"),
		"-o", outputPath,
	)
	require.NoError(t, buildErr,
		"a document reached by a symlinked spelling of the package's own directory is not outside it")

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	for _, c := range pkg["contents"].([]interface{}) {
		uri := c.(map[string]interface{})["uri"].(string)
		assert.NotContains(t, uri, "..", "a same-directory document must not produce a traversing reference")
	}

	_, _, verifyErr := executeCommand("evidence", "info", "--verify", outputPath, "--checksums-only")
	require.NoError(t, verifyErr, "the package build produced must verify")
}

// Writing to stdout leaves no package directory, so references are bare
// filenames. The warning must say that once and say only what is true: an earlier
// version claimed the document was "not beside the package" and fired for every
// absolute path, i.e. for flat layouts that were perfectly fine.
func TestEvidenceBuild_StdoutWarnsOnceAndOnlyAboutStdout(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)

	_, stderr, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
	)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(stderr, "Warning:"),
		"exactly one warning, however many documents are listed")
	assert.Contains(t, stderr, "bare filenames")
	// The warning must name the consequence that costs evidence, not only the portability
	// one: a bare filename does not identify a document uniquely, which is why two
	// documents sharing a filename are refused rather than recorded under one reference.
	assert.Contains(t, stderr, "does not identify a document uniquely",
		"the warning must say references are not unique per document, not merely unresolvable")
	assert.NotContains(t, stderr, "not beside the package",
		"the old claim was false for a flat layout")
}

// A missing output directory must blame the output directory. Before this check it
// blamed the input document — "<doc> is outside the evidence package's directory
// (<missing dir>); move it under that directory" — prescribing a move that would
// not have helped, because the fault was the -o path. Same class of wrongness as
// the stdout warning.
func TestEvidenceBuild_MissingOutputDirectoryBlamesTheOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)

	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", p["results.json"],
		"-o", filepath.Join(tmpDir, "does-not-exist", "pkg.json"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist",
		"the error must name the missing output directory")
	assert.NotContains(t, err.Error(), "add-evidence",
		"it must not prescribe the out-of-tree remedy for a missing output directory")
	assert.NotContains(t, err.Error(), "outside the evidence package",
		"the input document is not at fault")
}

// A reference cannot be computed for a document whose path does not resolve — a
// broken symlink in an artifacts directory is the realistic case. The failure must
// surface: an earlier version swallowed every EvalSymlinks error and fell back to
// the lexical path, which silently reintroduced the /tmp-versus-/private/tmp
// mismatch the resolution exists to prevent, with no error to show for it.
func TestEvidenceBuild_DanglingSymlinkDocumentSurfacesTheFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevated privileges on Windows; the resolution logic is OS-independent")
	}
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)

	dangling := filepath.Join(tmpDir, "vanished-results.json")
	require.NoError(t, os.Symlink(filepath.Join(tmpDir, "no-such-file.json"), dangling))

	outputPath := filepath.Join(tmpDir, "pkg.json")
	_, _, err := executeCommand("evidence", "build",
		"--system", p["system.json"],
		"--results", dangling,
		"-o", outputPath,
	)
	require.Error(t, err, "an unresolvable document path must fail, not degrade to a lexical reference")
	assert.Contains(t, err.Error(), "vanished-results.json", "the error must name the document")
	assert.Contains(t, err.Error(), "no-such-file.json", "and the target it could not resolve")
	// Counted, not Contains: a message stating the fault twice contains the phrase too.
	assert.Equal(t, 1, strings.Count(err.Error(), "failed to resolve "+dangling),
		"one fault must be stated once; got %q", err.Error())
	assert.Equal(t, 1, strings.Count(err.Error(), dangling),
		"and names the document once, so a re-wrap naming it again fails whatever "+
			"wording it uses; got %q", err.Error())
	assert.NoFileExists(t, outputPath)
}

// packageRelativeRef resolves two paths, and an unresolvable BASE is the case a
// document's name would not explain — so the message has to say which of the two
// failed, and say the resolve failure once. Called directly because no CLI route gets
// here with an unresolvable base: build stats the output directory first, and update
// takes the directory of the package file it has just read.
func TestPackageRelativeRef_StatesAnUnresolvablePackageDirectoryOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevated privileges on Windows; the resolution logic is OS-independent")
	}
	dir := t.TempDir()
	docPath := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(docPath, []byte("{}"), 0o600))
	danglingBase := filepath.Join(dir, "artifacts")
	require.NoError(t, os.Symlink(filepath.Join(dir, "no-such-dir"), danglingBase))

	_, err := packageRelativeRef(danglingBase, docPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "package directory",
		"the message must say it is the base, not the document, that did not resolve")
	assert.Contains(t, err.Error(), danglingBase, "and name it")
	assert.Contains(t, err.Error(), "no-such-dir", "and the target it could not resolve")
	// Counted, not Contains: a message stating the fault twice contains the phrase too.
	assert.Equal(t, 1, strings.Count(err.Error(), "failed to resolve"),
		"one fault must be stated once; got %q", err.Error())
	assert.Equal(t, 1, strings.Count(err.Error(), danglingBase),
		"and names the base once, so a re-wrap naming it again fails whatever "+
			"wording it uses; got %q", err.Error())
}

// evidence info --verify reads contents[].type to judge completeness, so a document
// filed under the wrong Content_Type produces a confident wrong verdict rather
// than an error. --plan and --baseline have always refused a mistyped document;
// --amendments and --comparison accepted anything readable, because card .1 made
// them repeatable under an AC that forbade tightening what they took. All four
// are checked here together so the asymmetry cannot come back on one flag.
func TestEvidenceBuild_RefusesAMistypedDocumentOnEveryContentFlag(t *testing.T) {
	for _, tc := range []struct {
		flag     string
		wrongDoc string
		gotType  string
	}{
		{flag: "plan", wrongDoc: "rhel9-results.json", gotType: "results"},
		{flag: "baseline", wrongDoc: "rhel9-results.json", gotType: "results"},
		{flag: "amendments", wrongDoc: "plan.json", gotType: "plan"},
		{flag: "comparison", wrongDoc: "rhel9-results.json", gotType: "results"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			dir := t.TempDir()
			for _, n := range []string{"system.json", "rhel9-results.json", "plan.json"} {
				body, readErr := os.ReadFile(filepath.Join("testdata", "evidence-verify", n))
				require.NoError(t, readErr)
				require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
			}
			out := filepath.Join(dir, "pkg.json")

			_, _, err := executeCommand("evidence", "build",
				"--system", filepath.Join(dir, "system.json"),
				"--results", filepath.Join(dir, "rhel9-results.json"),
				"--"+tc.flag, filepath.Join(dir, tc.wrongDoc),
				"-o", out,
			)

			require.Error(t, err)
			assert.Contains(t, err.Error(),
				"is an HDF "+tc.gotType+" document, expected "+tc.flag,
				"the refusal must name both the detected type and what the flag promised")
			assert.NoFileExists(t, out, "a refused build must not leave a package behind")
		})
	}
}

// Card .1 made the repeatable flags drop an empty path element, so a shell that
// expands an unset variable into `--baseline ""` builds a package rather than
// failing. Fingerprint-checking must not turn those back into errors: an empty
// element has no document to detect, so it has to be dropped before the guard.
func TestEvidenceBuild_AnEmptyPathElementStaysANoOpOnEveryContentFlag(t *testing.T) {
	for _, flag := range []string{"plan", "baseline", "amendments", "comparison"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			for _, n := range []string{"system.json", "rhel9-results.json"} {
				body, readErr := os.ReadFile(filepath.Join("testdata", "evidence-verify", n))
				require.NoError(t, readErr)
				require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
			}
			out := filepath.Join(dir, "pkg.json")

			_, _, err := executeCommand("evidence", "build",
				"--system", filepath.Join(dir, "system.json"),
				"--results", filepath.Join(dir, "rhel9-results.json"),
				"--"+flag, "",
				"-o", out,
			)
			require.NoError(t, err)

			data, readErr := os.ReadFile(out)
			require.NoError(t, readErr)
			var pkg struct {
				Contents []struct{ Type string } `json:"contents"`
			}
			require.NoError(t, json.Unmarshal(data, &pkg))

			types := make([]string, len(pkg.Contents))
			for i, c := range pkg.Contents {
				types[i] = c.Type
			}
			assert.Equal(t, []string{"hdf-system", "hdf-results"}, types,
				"the empty element must add nothing, so only system and results are listed")
		})
	}
}

// sameBasenameResults writes the SAME-NAMED results document into n date-style
// subdirectories with genuinely different bytes, which is the shape that collides: a
// system scanned daily whose output is always called audit.json.
func sameBasenameResults(t *testing.T, dir string, days ...string) []string {
	t.Helper()
	paths := make([]string, 0, len(days))
	for i, day := range days {
		sub := filepath.Join(dir, day)
		require.NoError(t, os.MkdirAll(sub, 0o750))
		p := filepath.Join(sub, "audit.json")
		body := fmt.Sprintf(`{"name": "scan-%d", "baselines": [{"name": "b%d", "requirements": []}]}`, i, i)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		paths = append(paths, p)
	}
	return paths
}

// Two documents recorded under ONE reference make a package that fails its own
// verification: the single reference carries both checksums, so at least one must be
// reported as a mismatch and the operator's evidence is accused of tampering.
func TestEvidenceBuild_RefusesTwoDocumentsThatWouldShareAReference(t *testing.T) {
	dir := t.TempDir()
	docs := writeEvidenceInputs(t, dir)
	scans := sameBasenameResults(t, dir, "2026-09-28", "2026-09-29")

	_, _, err := executeCommand("evidence", "build",
		"--system", docs["system.json"],
		"--results", scans[0], "--results", scans[1])
	require.Error(t, err, "a package whose reference names two documents must not be written")
	assert.Contains(t, err.Error(), scans[0], "the error must name the first source path")
	assert.Contains(t, err.Error(), scans[1], "and the second")
	assert.Contains(t, err.Error(), "audit.json", "and the reference they would share")
}

// The same document given twice is a different case and gets its own message, rather than
// one that reads as if two different files collided.
func TestEvidenceBuild_RefusesTheSameDocumentTwice(t *testing.T) {
	dir := t.TempDir()
	docs := writeEvidenceInputs(t, dir)

	_, _, err := executeCommand("evidence", "build",
		"--system", docs["system.json"],
		"--results", docs["results.json"], "--results", docs["results.json"])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "twice", "the message must say the document was given twice")
	assert.Contains(t, err.Error(), docs["results.json"])
}

// Guards against over-refusal in three directions: distinct basenames, a single document,
// and — with -o, where references keep their subdirectories — the very same-basename set
// that collides on stdout.
func TestEvidenceBuild_StillBuildsWhenReferencesAreDistinct(t *testing.T) {
	t.Run("distinct basenames to stdout", func(t *testing.T) {
		dir := t.TempDir()
		docs := writeEvidenceInputs(t, dir)
		second := filepath.Join(dir, "other-results.json")
		require.NoError(t, os.WriteFile(second, []byte(noTargetsJSON), 0o600))
		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"],
			"--results", docs["results.json"], "--results", second)
		require.NoError(t, err)
	})

	t.Run("a single document to stdout", func(t *testing.T) {
		dir := t.TempDir()
		docs := writeEvidenceInputs(t, dir)
		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"], "--results", docs["results.json"])
		require.NoError(t, err)
	})

	t.Run("same basenames in subdirectories, with -o", func(t *testing.T) {
		dir := t.TempDir()
		docs := writeEvidenceInputs(t, dir)
		scans := sameBasenameResults(t, dir, "2026-09-28", "2026-09-29")
		out := filepath.Join(dir, "pkg.json")
		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"],
			"--results", scans[0], "--results", scans[1], "-o", out)
		require.NoError(t, err, "-o keeps the subdirectories, so these references are distinct")
		uris := map[string]bool{}
		for _, c := range readEvidenceDoc(t, out)["contents"].([]interface{}) {
			entry, _ := c.(map[string]interface{})
			uri, _ := entry["uri"].(string)
			assert.False(t, uris[uri], "no reference may repeat: %s", uri)
			uris[uri] = true
		}
		assert.Contains(t, uris, "2026-09-28/audit.json")
		assert.Contains(t, uris, "2026-09-29/audit.json")
	})
}

// The typed flags (--plan, --baseline, --amendments, --comparison) record references
// through a different function than --results and --system, so a check on one path leaves
// the other open. Both are covered here, plus a collision ACROSS the two, which is what
// the single shared claims map exists for.
func TestEvidenceBuild_RefusesACollisionOnEveryPathThatRecordsAReference(t *testing.T) {
	sameNamed := func(t *testing.T, dir, name string, bodies ...string) []string {
		t.Helper()
		out := make([]string, 0, len(bodies))
		for i, body := range bodies {
			sub := filepath.Join(dir, fmt.Sprintf("dir%d", i))
			require.NoError(t, os.MkdirAll(sub, 0o750))
			p := filepath.Join(sub, name)
			require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
			out = append(out, p)
		}
		return out
	}

	t.Run("two --baseline documents, the typed-flag path", func(t *testing.T) {
		dir := t.TempDir()
		docs := writeEvidenceInputs(t, dir)
		b := sameNamed(t, dir, "baseline.json",
			`{"name": "rhel9-stig", "requirements": []}`,
			`{"name": "pgsql-stig", "requirements": []}`)

		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"], "--results", docs["results.json"],
			"--baseline", b[0], "--baseline", b[1])
		require.Error(t, err, "the typed-flag path must refuse a collision too")
		assert.Contains(t, err.Error(), b[0])
		assert.Contains(t, err.Error(), b[1])
		assert.Contains(t, err.Error(), "baseline.json")
	})

	t.Run("a --results and a --baseline sharing one reference", func(t *testing.T) {
		dir := t.TempDir()
		docs := writeEvidenceInputs(t, dir)
		// Same basename, different directories, different content types: the collision is
		// between the two PATHS that record references, not within either one.
		results := sameNamed(t, dir, "shared.json", noTargetsJSON)[0]
		baseline := filepath.Join(dir, "dir1", "shared.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(baseline), 0o750))
		require.NoError(t, os.WriteFile(baseline,
			[]byte(`{"name": "rhel9-stig", "requirements": []}`), 0o600))

		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"], "--results", results, "--baseline", baseline)
		require.Error(t, err, "a collision across the two recording paths must be refused")
		assert.Contains(t, err.Error(), "shared.json")
	})
}

// One document reached by two spellings is ONE document. Keying the collision on the path
// as typed reported it as two, with a message that was false four ways: it is not two
// documents; the package verifies fine because both checksums are identical; it prescribed
// -o when -o was already passed; and "give them distinct filenames" would have the
// operator copy one evidence document under two names. Under -o this is the only
// collision branch reachable at all, since two distinct files always get distinct
// package-relative references.
func TestEvidenceBuild_RecognizesOneDocumentReachedByTwoSpellings(t *testing.T) {
	setup := func(t *testing.T) (dir string, docs map[string]string, aliased, canonical string) {
		t.Helper()
		dir = t.TempDir()
		docs = writeEvidenceInputs(t, dir)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "2026-09-30"), 0o750))
		canonical = filepath.Join(dir, "2026-09-30", "audit.json")
		require.NoError(t, os.WriteFile(canonical, []byte(noTargetsJSON), 0o600))
		require.NoError(t, os.Symlink("2026-09-30", filepath.Join(dir, "latest")))
		aliased = filepath.Join(dir, "latest", "audit.json")
		return dir, docs, aliased, canonical
	}

	assertSameDocument := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "same document",
			"one document under two spellings must be reported as one document")
		assert.NotContains(t, err.Error(), "cannot verify",
			"the package would verify: both checksums are identical")
		assert.NotContains(t, err.Error(), "distinct filenames",
			"copying one evidence document under two names is not a remedy")
		assert.NotContains(t, err.Error(), "-o <file>",
			"prescribing -o is a dead end when the document is simply listed twice")
	}

	t.Run("directory symlink, with -o", func(t *testing.T) {
		dir, docs, aliased, canonical := setup(t)
		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"], "--results", aliased, "--results", canonical,
			"-o", filepath.Join(dir, "pkg.json"))
		assertSameDocument(t, err)
	})

	t.Run("uncleaned spelling, to stdout", func(t *testing.T) {
		_, docs, _, canonical := setup(t)
		// Built by concatenation: filepath.Join would clean this back to `canonical`.
		dotted := filepath.Dir(canonical) + "/../2026-09-30/audit.json"
		_, _, err := executeCommand("evidence", "build",
			"--system", docs["system.json"], "--results", canonical, "--results", dotted)
		assertSameDocument(t, err)
	})
}

// The resolve step runs before the document is read on the stdout path, so a reference
// that cannot be resolved is surfaced there rather than degraded to the lexical form —
// degrading would silently reintroduce the /tmp-versus-/private/tmp mismatch resolvedAbs
// exists to prevent. Asserted on the MISSING TARGET, not merely on the document name: the
// read error that a degraded path would produce names the document too, so naming the
// document alone cannot tell the two apart.
func TestEvidenceBuild_SurfacesAnUnresolvableReferenceOnTheStdoutPath(t *testing.T) {
	dir := t.TempDir()
	docs := writeEvidenceInputs(t, dir)
	dangling := filepath.Join(dir, "dangling.json")
	require.NoError(t, os.Symlink(filepath.Join(dir, "no-such-scan.json"), dangling))

	_, _, err := executeCommand("evidence", "build",
		"--system", docs["system.json"], "--results", dangling)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dangling.json", "the error must name the document")
	assert.Contains(t, err.Error(), "no-such-scan.json",
		"and the target it could not resolve, which a degraded lexical fallback would not")
	// Counted, not Contains: a message stating the fault twice contains the phrase too.
	assert.Equal(t, 1, strings.Count(err.Error(), "failed to resolve "+dangling),
		"one fault must be stated once; got %q", err.Error())
	assert.Equal(t, 1, strings.Count(err.Error(), dangling),
		"and names the document once, so a re-wrap naming it again fails whatever "+
			"wording it uses; got %q", err.Error())
}

// rhel9ResultsJSON covers a named baseline. noTargetsJSON ({"baselines": []}) does not,
// and computeCompleteness derives allBaselinesAssessed from the baseline names it finds —
// so an assertion that the flag is false is vacuous against an empty results document and
// survives the removal of the rule it is meant to pin.
const rhel9ResultsJSON = `{"baselines": [{"name": "RHEL9-STIG",
	"requirements": [{"id": "SV-1", "impact": 0.5, "tags": {},
		"descriptions": [{"label": "default", "data": "Test"}],
		"results": [{"status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z"}]}]}],
	"statistics": {"duration": 0}}`

// hdf-evidence-package's top-level required is ["name","contents"] — systemRef is
// optional — but build refused without --system, so a schema-valid package that
// records no system could not be produced at all. A library is not a system: it has
// no authorization boundary, no FIPS 199 categorization and no authorizing official,
// and what its assessment asserts is narrower. That package is a normal product.
func TestEvidenceBuild_BuildsAContentsOnlyPackageWithoutASystem(t *testing.T) {
	tmpDir := t.TempDir()
	p := writeEvidenceInputs(t, tmpDir)
	outputPath := filepath.Join(tmpDir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--results", p["results.json"], "-o", outputPath)
	require.NoError(t, err, "a package recording no system is schema-valid and must build")

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	// Absent, not empty-string: an empty uri-reference claims a reference to nothing,
	// which is a different and worse claim than making none.
	_, recorded := pkg["systemRef"]
	assert.False(t, recorded, "no --system must record no systemRef at all")

	types := make([]string, 0)
	for _, c := range pkg["contents"].([]interface{}) {
		types = append(types, c.(map[string]interface{})["type"].(string))
	}
	assert.Equal(t, []string{"hdf-results"}, types,
		"contents lists what was given and nothing standing in for a system")
	assert.NoError(t, validateHDFDocument(data), "the package must validate")
}

// Every claim the note makes is asserted against the SAME run that printed it. A
// Contains() on help or notice text asserts the phrasing back at the test and can
// hold a false sentence in place indefinitely, so each clause is paired with the
// observable it describes.
func TestEvidenceBuild_SaysPlainlyThatThePackageAssertsNoSystem(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "pkg.json")
	resultsPath := filepath.Join(tmpDir, "rhel9.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(rhel9ResultsJSON), 0o600))

	_, stderr, err := executeCommand("evidence", "build",
		"--results", resultsPath, "-o", outputPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	cc, _ := pkg["completenessCheck"].(map[string]interface{})
	require.NotNil(t, cc)

	// Claim: the package asserts no system — and records no systemRef.
	assert.Contains(t, stderr, "asserts no system")
	_, recorded := pkg["systemRef"]
	assert.False(t, recorded)

	// Claim: neither coverage claim is made. Both are claims ABOUT system components;
	// with no system document there is nothing to check the results against, and
	// computeCompleteness reads allBaselinesAssessed off the results alone.
	assert.Contains(t, stderr, "claims neither full baseline coverage nor component coverage")
	assert.Equal(t, false, cc["allBaselinesAssessed"])
	assert.Equal(t, false, cc["allComponentsCovered"])

	// Claim: the package is named "evidence-package" — no system name to take, and
	// "unnamed-system" would assert a system exists and is merely nameless.
	assert.Contains(t, stderr, `named "evidence-package"`)
	assert.Equal(t, "evidence-package", pkg["name"])

	// Claim: the two remedies it names are real flags on a real command.
	setHelp, _, helpErr := executeCommand("evidence", "set", "--help")
	require.NoError(t, helpErr)
	assert.Contains(t, setHelp, "--system-ref")
	assert.Contains(t, setHelp, "--name")

	// The retired refusal must not survive anywhere the operator reads.
	assert.NotContains(t, stderr, "--system is required")
}

// The refusal was in two places, and relaxing only the flag path would leave build
// inconsistent with itself: --from-dir is the CI shape (a job drops its scans in a
// directory), and a software-package pipeline's directory has no system document in
// it at all. An explicit --system plus a scanned one stays a hard error.
func TestEvidenceBuild_FromDirWithNoSystemDocumentStillBuilds(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "results.json"), []byte(noTargetsJSON), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err, "a scanned directory with no system document must still build")
	assert.Contains(t, stderr, "asserts no system")
	assert.NotContains(t, stderr, "needs exactly one")

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	_, recorded := pkg["systemRef"]
	assert.False(t, recorded)
	assert.Len(t, pkg["contents"], 1)
}

// contents[] has minItems 1, so an empty scan would otherwise surface as "evidence
// package failed validation before write" — blaming the package for an empty
// directory. Reachable only here: the flag path requires a results document.
func TestEvidenceBuild_FromDirWithNoDocumentsAtAllIsRefused(t *testing.T) {
	dir := t.TempDir()
	_, _, err := executeCommand("evidence", "build",
		"--from-dir", dir, "-o", filepath.Join(dir, "pkg.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no HDF documents")
	assert.NotContains(t, err.Error(), "failed validation",
		"the empty directory is the fault, not the package it would have produced")
}

// A system-less package must not fail verify, and what verify cannot check must be
// named rather than left to inference. Measured, not assumed: completeness is read
// from the PLAN, never from the system document, so a plan-less package skips the
// check and a plan-bearing one performs it in full without a system.
func TestEvidenceVerify_SystemlessPackageIsNotAFailure(t *testing.T) {
	dir := t.TempDir()
	p := writeEvidenceInputs(t, dir)
	pkgPath := filepath.Join(dir, "pkg.json")

	_, _, buildErr := executeCommand("evidence", "build",
		"--results", p["results.json"], "-o", pkgPath)
	require.NoError(t, buildErr)

	_, stderr, err := executeCommand("evidence", "info", "--verify", pkgPath)
	require.NoError(t, err, "a package recording no system must not fail verify")
	assert.Contains(t, stderr, "no planRef in evidence package",
		"what was skipped must be named, and it is the plan that is missing — not the system")

	// With a plan, the completeness check runs to a verdict with no system document
	// anywhere in the package. The results cover the baseline the plan requires, so a
	// pass here is the completeness check's own verdict and not a vacuous skip.
	covering := filepath.Join(dir, "rhel9-results.json")
	require.NoError(t, os.WriteFile(covering, []byte(rhel9ResultsJSON), 0o600))
	withPlan := filepath.Join(dir, "pkg-plan.json")
	_, _, planBuildErr := executeCommand("evidence", "build",
		"--results", covering, "--plan", p["plan.json"],
		"--baseline", p["baseline.json"], "-o", withPlan)
	require.NoError(t, planBuildErr)
	_, planStderr, planVerifyErr := executeCommand("evidence", "info", "--verify", withPlan)
	require.NoError(t, planVerifyErr,
		"completeness is checked against the plan, so it reaches a verdict without a system")
	assert.Contains(t, planStderr, "Completeness check passed: all 1 planned baselines have results",
		"the completeness verdict must be reached, not skipped")
	assert.NotContains(t, planStderr, "no planRef")
}

// Relaxing the zero-system case reordered the switch that decides which scanned
// system a package takes, so both surviving branches are pinned here: one is still
// discovered and recorded, and more than one is still refused by name.
func TestEvidenceBuild_FromDirStillResolvesExactlyOneSystem(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "results.json"), []byte(noTargetsJSON), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "system-a.json"),
		[]byte(`{"name":"portal","components":[{"name":"c1","type":"application"}]}`), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err)
	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	assert.Equal(t, "system-a.json", pkg["systemRef"], "a single scanned system is still recorded")
	assert.Equal(t, "portal-evidence-package", pkg["name"], "and still names the package")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "system-b.json"),
		[]byte(`{"name":"portal2","components":[{"name":"c2","type":"application"}]}`), 0o600))
	_, _, twoErr := executeCommand("evidence", "build",
		"--from-dir", dir, "-o", filepath.Join(dir, "pkg2.json"))
	require.Error(t, twoErr, "two scanned systems have no second pointer to live under")
	assert.Contains(t, twoErr.Error(), "contains 2 HDF system documents")
}

// bomFixture writes a copy of an evidence fixture with a leading UTF-8 BOM, which is
// what some Windows tools prepend. Not a fabricated document: the bytes are the real
// fixture's, with the three-byte mark in front.
func bomFixture(t *testing.T, dir, name, fixture string) (path string, raw []byte) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, fixture))
	require.NoError(t, err)
	raw = append([]byte{0xEF, 0xBB, 0xBF}, src...)
	path = filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path, raw
}

// A package built from a BOM-carrying document verifies and bundles. It did neither: the
// write path hashed the bytes with the BOM stripped off (readInputFile strips it so
// parsers see clean bytes) while verification re-reads the file raw and bundle archives
// it raw — so a freshly built package failed its own verification and bundle refused it,
// blaming the operator's evidence for a difference the tooling created.
//
// The recorded checksum is of the bytes ON DISK, which is the rule the rest of the
// pipeline already followed: add-evidence and add-reference hash raw, the archive carries
// raw, verification hashes raw.
func TestEvidenceBuild_ABOMCarryingDocumentVerifiesAndBundles(t *testing.T) {
	dir := t.TempDir()
	results, raw := bomFixture(t, dir, "rhel9.json", "rhel9-results.json")
	pkgPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build", "--results", results, "-o", pkgPath)
	require.NoError(t, err)

	// Keyed on the RECORDED reference, which build writes package-relative — not the
	// path handed on the command line. Looking it up by the absolute path returned an
	// empty string and the assertion read as a wrong digest rather than a missed lookup.
	assert.Equal(t, evidenceDigestHex(raw),
		checksumOf(t, updatedPackage(t, pkgPath), filepath.Base(results)),
		"the recorded checksum must be of the bytes on disk, BOM included")

	// And both consumers agree, which is the point rather than a bonus.
	_, _, verr := executeCommand("evidence", "info", "--verify", pkgPath, "--checksums-only")
	require.NoError(t, verr, "a freshly built package must verify")

	_, _, berr := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "out.zip"))
	require.NoError(t, berr, "and must bundle")
}

// Every typed document build records goes through appendTyped, not buildContentEntry —
// --plan, --baseline, --amendments and --comparison. A mutant that made appendTyped hash
// the stripped bytes killed NO test, so this pins it: the --results path alone was
// covered, and "every writer uses the chosen rule" was an assertion about four paths
// backed by one.
func TestEvidenceBuild_ATypedDocumentIsHashedAsItIsOnDisk(t *testing.T) {
	dir := t.TempDir()
	results, _ := bomFixture(t, dir, "rhel9.json", "rhel9-results.json")
	plan, planRaw := bomFixture(t, dir, "plan.json", "plan.json")
	pkgPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--results", results, "--plan", plan, "-o", pkgPath)
	require.NoError(t, err)

	assert.Equal(t, evidenceDigestHex(planRaw),
		checksumOf(t, updatedPackage(t, pkgPath), filepath.Base(plan)),
		"a plan document is hashed as it is on disk, like every other typed entry")

	_, _, verr := executeCommand("evidence", "info", "--verify", pkgPath, "--checksums-only")
	require.NoError(t, verr, "and the package verifies")
}
