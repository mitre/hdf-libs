package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scanTree lays out an artifacts directory the way a CI job would hand one over:
// a package destination at the root, documents flat and in subdirectories.
func scanTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "meta"), 0o750))

	copyFixture := func(name, dest string) {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, dest), src, 0o600))
	}
	write := func(dest, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, dest), []byte(body), 0o600))
	}

	copyFixture("system.json", "system.json")
	copyFixture("rhel9-results.json", filepath.Join("scans", "rhel9-results.json"))
	write(filepath.Join("meta", "plan.json"), `{"name":"q3","assessments":[{"baselineRef":"RHEL9-STIG"}]}`)
	write(filepath.Join("meta", "baseline.json"), `{"name":"rhel9-stig","requirements":[]}`)
	write("waivers.json", `{"name":"waivers","overrides":[]}`)
	write("drift.json", `{"formatVersion":"1.0.0","comparisonMode":"temporal","sources":[],"summary":{},"requirementDiffs":[]}`)
	return dir
}

// The card's named first test: every HDF document type a directory can hold must
// be classified by content and routed to its Content_Type.
func TestEvidenceBuild_FromDirClassifiesEveryHDFType(t *testing.T) {
	dir := scanTree(t)
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	byType := map[string]string{}
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		byType[e["type"].(string)] = e["uri"].(string)
	}
	assert.Equal(t, "system.json", byType["hdf-system"])
	assert.Equal(t, "scans/rhel9-results.json", byType["hdf-results"],
		"a subdirectory document keeps its package-relative path")
	assert.Equal(t, "meta/plan.json", byType["hdf-plan"])
	assert.Equal(t, "meta/baseline.json", byType["hdf-baseline"])
	assert.Equal(t, "waivers.json", byType["hdf-amendments"])
	assert.Equal(t, "drift.json", byType["hdf-comparison"])
	assert.Equal(t, "meta/plan.json", pkg["planRef"], "a scanned plan still sets planRef")
}

// The collision that matters most here. hdfengine.Detect classifies ANY root
// `components` key as an HDF system, and components[] is CycloneDX's primary
// field — so a blind Detect files real SBOMs as system documents, which then
// collide with the real one. Routing must consult the BOM discriminator first.
func TestEvidenceBuild_FromDirRoutesCycloneDXToBomNotSystem(t *testing.T) {
	dir := scanTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "webtier.cdx.json"),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
			"components":[{"type":"library","name":"openssl","version":"3.0.2"}]}`), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err, "a CycloneDX SBOM must not be mistaken for a second system document")

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	systems, boms := 0, ""
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		switch e["type"] {
		case "hdf-system":
			systems++
		case "bom":
			boms = e["uri"].(string)
		}
	}
	assert.Equal(t, 1, systems, "exactly the real system document")
	assert.Equal(t, "webtier.cdx.json", boms, "the SBOM belongs under the bom content type")
}

// Two system documents cannot both be the package's system; the error must name
// both so the operator can see which one to move.
func TestEvidenceBuild_FromDirRequiresExactlyOneSystem(t *testing.T) {
	dir := scanTree(t)
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "system.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "meta", "other-system.json"), src, 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, buildErr := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.Error(t, buildErr)
	assert.Contains(t, buildErr.Error(), "system.json")
	assert.Contains(t, buildErr.Error(), filepath.Join("meta", "other-system.json"))
	assert.NoFileExists(t, outputPath)
}

// A foreign artifact is not dropped in silence: it is reported with the command
// that would include it, because guessing a format would be fabrication.
func TestEvidenceBuild_FromDirReportsNonHDFFilesWithTheCommand(t *testing.T) {
	dir := scanTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "corpus.ndjson"),
		[]byte(`{"@timestamp":"2026-01-01T00:00:00Z"}`+"\n"), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err)
	assert.Contains(t, stderr, "corpus.ndjson", "a foreign artifact must be reported")
	assert.Contains(t, stderr, "add-evidence", "with the command that would include it")
}

// Two detected types have NO Content_Type: a requirement-change-event, and an
// evidence package itself (which a re-scan of the same directory would find).
// Both must be reported as unsupported rather than mis-typed into contents[].
func TestEvidenceBuild_FromDirReportsTypesWithNoContentType(t *testing.T) {
	dir := scanTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "event.json"),
		[]byte(`{"requirementId":"V-1","state":"updated","before":{},"after":{}}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "old-package.json"),
		[]byte(`{"name":"prior","contents":[]}`), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	for _, c := range pkg["contents"].([]interface{}) {
		uri := c.(map[string]interface{})["uri"].(string)
		assert.NotEqual(t, "event.json", uri, "a change event has no Content_Type")
		assert.NotEqual(t, "old-package.json", uri, "an evidence package has no Content_Type")
	}
	assert.Contains(t, stderr, "event.json")
	assert.Contains(t, stderr, "old-package.json")
}

// An explicitly-named document must not also be picked up by the scan.
func TestEvidenceBuild_FromDirDoesNotDoubleListExplicitFiles(t *testing.T) {
	dir := scanTree(t)
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build",
		"--from-dir", dir,
		"--results", filepath.Join(dir, "scans", "rhel9-results.json"),
		"-o", outputPath)
	require.NoError(t, err)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	count := 0
	for _, c := range pkg["contents"].([]interface{}) {
		if c.(map[string]interface{})["uri"] == "scans/rhel9-results.json" {
			count++
		}
	}
	assert.Equal(t, 1, count, "a document named explicitly must be listed once, not twice")
}

// The scan stays inside the tree: a symlink pointing out of it must not drag an
// outside document into the package.
func TestEvidenceBuild_FromDirDoesNotFollowSymlinksOutOfTheTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevated privileges on Windows; the traversal logic is OS-independent")
	}
	dir := scanTree(t)
	outside := t.TempDir()
	stray := filepath.Join(outside, "stray-results.json")
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(stray, src, 0o600))
	require.NoError(t, os.Symlink(stray, filepath.Join(dir, "linked-results.json")))

	outputPath := filepath.Join(dir, "pkg.json")
	_, _, buildErr := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, buildErr)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	for _, c := range pkg["contents"].([]interface{}) {
		assert.NotEqual(t, "linked-results.json", c.(map[string]interface{})["uri"],
			"a symlink leaving the tree must not be listed")
	}
}

// The skip-set and the scanned paths must normalize the same way. filepath.
// EvalSymlinks does not absolutize, so a relative --from-dir with an absolute
// explicit path (or the reverse) previously failed to match and listed the
// document twice. Exercises the mixed form the earlier test could not.
func TestEvidenceBuild_FromDirSkipsExplicitFilesAcrossPathForms(t *testing.T) {
	dir := scanTree(t)
	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	// --from-dir is relative; the explicit --results is absolute.
	absResults := filepath.Join(dir, "scans", "rhel9-results.json")
	_, _, buildErr := executeCommand("evidence", "build",
		"--from-dir", ".",
		"--results", absResults,
		"-o", "pkg.json")
	require.NoError(t, buildErr)

	data, readErr := os.ReadFile(filepath.Join(dir, "pkg.json"))
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	count := 0
	for _, c := range pkg["contents"].([]interface{}) {
		if c.(map[string]interface{})["type"] == "hdf-results" {
			count++
		}
	}
	assert.Equal(t, 1, count,
		"the explicitly-named results document must be listed once despite the mixed path forms")
}

// The report must be readable and its suggestion copy-pasteable: paths are
// absolute internally so the skip-set matches any form the caller typed, but a
// full /private/tmp/... path in the printed add-evidence command is not something
// anyone can use.
func TestEvidenceBuild_FromDirReportsRelativePaths(t *testing.T) {
	dir := scanTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "corpus.ndjson"),
		[]byte(`{"@timestamp":"2026-01-01T00:00:00Z"}`+"\n"), 0o600))

	_, stderr, err := executeCommand("evidence", "build",
		"--from-dir", dir, "-o", filepath.Join(dir, "pkg.json"))
	require.NoError(t, err)

	assert.Contains(t, stderr, "--uri scans/corpus.ndjson",
		"the suggested command must carry a package-relative uri")
	assert.Contains(t, stderr, "Skipped scans/corpus.ndjson",
		"the skipped path must be shown relative to the scanned directory")
	// The package target is deliberately NOT shortened: it is whatever -o named,
	// and the suggestion has to point at that exact file to be usable.
	assert.Contains(t, stderr, filepath.Join(dir, "pkg.json"),
		"the suggested command names the package the caller asked for")
}

// Following the ">1 plans" error's own advice must not make a plan vanish. Before
// this, `--from-dir` with an explicit `--plan` listed that plan and dropped every
// other one: absent from contents[], absent from stderr, exit 0 — so the loud
// failure the command itself told you to resolve became a silent one. planRef names
// which plan is the bar; contents[] is the manifest of documents carried.
func TestEvidenceBuild_FromDirListsEveryPlanNotJustPlanRef(t *testing.T) {
	dir := scanTree(t)
	other := filepath.Join(dir, "meta", "plan-b.json")
	require.NoError(t, os.WriteFile(other,
		[]byte(`{"name":"plan-b","assessments":[{"baselineRef":"PostgreSQL-STIG"}]}`), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build",
		"--from-dir", dir,
		"--plan", filepath.Join(dir, "meta", "plan.json"),
		"-o", outputPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	plans := []string{}
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		if e["type"] == "hdf-plan" {
			plans = append(plans, e["uri"].(string))
		}
	}
	assert.Len(t, plans, 2, "both plan documents must be listed")
	assert.Contains(t, plans, "meta/plan.json")
	assert.Contains(t, plans, "meta/plan-b.json", "the plan that is not planRef must still be carried")
	assert.Equal(t, "meta/plan.json", pkg["planRef"], "planRef names the assessment bar")
	assert.Contains(t, stderr, "planRef is meta/plan.json",
		"the notice must name which plan became planRef, in the scanned directory's terms")
	assert.Contains(t, stderr, "not the assessment bar: meta/plan-b.json",
		"and name the plans that did not, rather than counting them")
}

// A symlink is skipped rather than followed — os.Root refuses an escaping one and
// following an in-tree one would list the same bytes twice — but the skip must be
// visible, since the command's contract is that nothing is dropped in silence.
func TestEvidenceBuild_FromDirReportsSkippedSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevated privileges on Windows; the traversal logic is OS-independent")
	}
	dir := scanTree(t)
	require.NoError(t, os.Symlink(
		filepath.Join(dir, "scans", "rhel9-results.json"),
		filepath.Join(dir, "alias-results.json")))

	_, stderr, err := executeCommand("evidence", "build",
		"--from-dir", dir, "-o", filepath.Join(dir, "pkg.json"))
	require.NoError(t, err)
	assert.Contains(t, stderr, "alias-results.json")
	assert.Contains(t, stderr, "a symlink", "the skip must state why")
}

// Plans and systems are deliberately asymmetric: an explicit --plan MERGES with
// scanned plans (planRef is singular, contents[] is a manifest), while an explicit
// --system plus a scanned system is a hard error (a package has exactly one system
// and there is no second pointer to carry the others). The asymmetry is correct but
// nothing pinned it, and it is exactly what a "make these consistent" refactor would
// flatten without noticing.
func TestEvidenceBuild_FromDirPlansMergeButSystemsDoNot(t *testing.T) {
	dir := scanTree(t)
	outputPath := filepath.Join(dir, "pkg.json")

	// Plans merge: the explicitly-named plan plus the one the scan finds.
	other := filepath.Join(dir, "meta", "plan-b.json")
	require.NoError(t, os.WriteFile(other,
		[]byte(`{"name":"plan-b","assessments":[{"baselineRef":"PostgreSQL-STIG"}]}`), 0o600))
	_, stderr, err := executeCommand("evidence", "build",
		"--from-dir", dir, "--plan", filepath.Join(dir, "meta", "plan.json"), "-o", outputPath)
	require.NoError(t, err, "an explicit --plan merges with scanned plans")
	assert.Contains(t, stderr, "meta/plan-b.json",
		"the notice must name the plan that is not planRef, not just count it")

	// Systems do not: there is no second pointer for the extras to live under.
	_, _, sysErr := executeCommand("evidence", "build",
		"--from-dir", dir,
		"--system", filepath.Join(evidenceFixtureDir, "system.json"),
		"-o", filepath.Join(dir, "pkg2.json"))
	require.Error(t, sysErr, "an explicit --system plus a scanned system must not merge")
	assert.Contains(t, sysErr.Error(), "exactly one system document")
}

// A skipped symlink must be reported under its OWN name. Resolving the path before
// display printed the target instead, which made the message's own advice — "name
// its target explicitly" — nonsense, since it was already showing the target.
func TestEvidenceBuild_FromDirNamesTheSymlinkNotItsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevated privileges on Windows; the display logic is OS-independent")
	}
	dir := scanTree(t)
	require.NoError(t, os.Symlink(
		filepath.Join(dir, "scans", "rhel9-results.json"),
		filepath.Join(dir, "alias-results.json")))

	_, stderr, err := executeCommand("evidence", "build",
		"--from-dir", dir, "-o", filepath.Join(dir, "pkg.json"))
	require.NoError(t, err)
	assert.Contains(t, stderr, "Skipped alias-results.json",
		"the link's own name, not the target it points at")
}
