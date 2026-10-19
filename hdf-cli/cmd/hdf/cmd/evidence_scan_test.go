package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// The collision that matters most here. hdfengine.Detect classifies a root
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

// One document named in a different PATH FORM from the one the walk produces is
// still listed once. This was written when the skip-set compared normalized path
// strings, where mixing relative and absolute forms made it miss; the set now
// compares filesystem identity, so the path form cannot matter in principle —
// which is exactly why the case is worth keeping asserted rather than assumed.
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
// absolute internally, but a full /private/tmp/... path in the printed
// add-evidence command is not something anyone can use.
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

// One document reached by two paths must be listed once. A HARDLINK is the
// portable way to reproduce this: it gives two different path strings for one
// inode on every filesystem, where the card's original reproduction — the same
// file named in two letter-cases — only reproduces on a case-insensitive volume
// and would be a no-op on the Linux CI leg. Both land on the same cause: the
// skip-set compared resolved path STRINGS, which two spellings of one file do
// not share.
func TestEvidenceBuild_FromDirListsOneDocumentOnceWhenNamedByAnotherPath(t *testing.T) {
	dir := scanTree(t)
	original := filepath.Join(dir, "scans", "rhel9-results.json")
	alias := filepath.Join(dir, "scans", "rhel9-results-alias.json")
	if err := os.Link(original, alias); err != nil {
		t.Skipf("filesystem does not support hard links: %v", err)
	}

	outputPath := filepath.Join(dir, "pkg.json")
	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "--results", alias, "-o", outputPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	var listed []string
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		if e["type"] == "hdf-results" {
			listed = append(listed, e["uri"].(string))
		}
	}
	assert.Len(t, listed, 1,
		"the explicitly named path and the scanned one are the same file; it must be recorded once, got %v", listed)
}

// The card's own reproduction, which only exists on a case-insensitive volume
// (APFS, NTFS) — so the filesystem is PROBED rather than assumed from runtime.GOOS,
// because a case-sensitive APFS volume and a case-insensitive ext4 mount both exist.
// On a case-sensitive volume the two names are genuinely two files and there is
// nothing to deduplicate, which is why the identity key must not be a lower-cased
// string. The portable cousin of this test is the hard-link one above.
func TestEvidenceBuild_FromDirListsOneDocumentOnceWhenNamedInAnotherCase(t *testing.T) {
	dir := scanTree(t)
	original := filepath.Join(dir, "scans", "rhel9-results.json")
	miscased := filepath.Join(dir, "scans", "RHEL9-results.json")
	if _, err := os.Stat(miscased); err != nil {
		t.Skipf("filesystem is case-sensitive, so %s is not the same file: %v",
			filepath.Base(miscased), err)
	}
	// The probe said they are one file; confirm it by identity before relying on it.
	a, errA := os.Stat(original)
	b, errB := os.Stat(miscased)
	require.NoError(t, errA)
	require.NoError(t, errB)
	require.True(t, os.SameFile(a, b), "the probe claimed one file; os.SameFile disagrees")

	outputPath := filepath.Join(dir, "pkg.json")
	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "--results", miscased, "-o", outputPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	var listed []string
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		if e["type"] == "hdf-results" {
			listed = append(listed, e["uri"].(string))
		}
	}
	assert.Len(t, listed, 1,
		"one document named in two letter-cases must be recorded once, got %v", listed)
}

// An SPDX 3.x SBOM is JSON-LD: { "@context", "@graph" } with NO top-level
// spdxVersion, so a matcher keyed on that field classifies a real SBOM foreign.
// The discriminator was confirmed by reading the fixtures themselves — all three
// carry "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld" — rather
// than by guessing at the spec, and both SPDX generations are asserted here so
// recognizing the new one cannot quietly cost the old one.
func TestEvidenceBuild_FromDirRoutesBothSPDXGenerationsToBom(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
	}{
		{"SPDX 2.x, by its top-level spdxVersion", "spdx-sbom.json"},
		{"SPDX 3.x JSON-LD, by its @context", "spdx-ai-model-1.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := scanTree(t)
			src, readErr := os.ReadFile(bomFixturePath(t, tc.fixture))
			require.NoError(t, readErr)
			// Named so nothing can route it by filename, which AC 3 forbids.
			require.NoError(t, os.WriteFile(filepath.Join(dir, "inventory.json"), src, 0o600))
			outputPath := filepath.Join(dir, "pkg.json")

			_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
			require.NoError(t, err)

			data, _ := os.ReadFile(outputPath)
			var pkg map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &pkg))

			byType := map[string]string{}
			for _, c := range pkg["contents"].([]interface{}) {
				e := c.(map[string]interface{})
				byType[e["type"].(string)] = e["uri"].(string)
			}
			assert.Equal(t, "inventory.json", byType["bom"],
				"a real SBOM belongs under the bom content type, not reported as foreign")
		})
	}
}

// AC 5, and the risk the wider detector introduces: the previous matcher read two
// named fields, so it could only ever over-reject. Delegating asks a detector that
// knows five formats, so the question becomes whether it over-ACCEPTS. The existing
// foreign-artifact test asserts only that the path is REPORTED on stderr; this one
// pins absence from contents[] directly, for a document the wider detector could
// plausibly claim.
func TestEvidenceBuild_FromDirStillReportsAForeignJSONObjectAsForeign(t *testing.T) {
	dir := scanTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "terraform.tfstate.json"),
		[]byte(`{"version":4,"terraform_version":"1.7.5","serial":12,
			"resources":[{"mode":"managed","type":"aws_s3_bucket","name":"evidence"}]}`), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		assert.NotEqual(t, "terraform.tfstate.json", e["uri"],
			"a document no detector recognizes must not be recorded as %v", e["type"])
	}
	assert.Contains(t, stderr, "terraform.tfstate.json",
		"and it must be reported rather than dropped in silence")
}

// The regression 52n0c.11 introduced and 52n0c.46 fixed, pinned at the level where
// it hurt. A declined BOM is not merely "reported foreign": hdfengine.Detect reaches components after five more specific keys, so a CycloneDX SBOM spelling its
// bomFormat in lower case became a SECOND system document and --from-dir refused the
// whole build. The existing routing test uses the exact-case spelling, so it could
// not catch this.
func TestEvidenceBuild_FromDirRoutesACycloneDXSBOMWhateverItsFormatCasing(t *testing.T) {
	for _, spelling := range []string{"CycloneDX", "cyclonedx", "CYCLONEDX"} {
		t.Run(spelling, func(t *testing.T) {
			dir := scanTree(t)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "inventory.json"),
				[]byte(`{"bomFormat":"`+spelling+`","specVersion":"1.5","version":1,
					"components":[{"type":"library","name":"openssl","version":"3.0.2"}]}`), 0o600))
			outputPath := filepath.Join(dir, "pkg.json")

			_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
			require.NoError(t, err,
				"a CycloneDX SBOM must not be promoted to a second system document")

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
			assert.Equal(t, "inventory.json", boms, "the SBOM belongs under the bom content type")
		})
	}
}

// The commonest SPDX 3 document, and the one the first attempt at this card
// missed: the SOFTWARE profile. bom.DetectFormat declines it, because it answers
// which format can be normalized, and of the SPDX-3 profiles only the AI/dataset
// one can be — so the
// three fixtures in this repo routed for the wrong reason, each carrying an
// ai_AIPackage OR a dataset_DatasetPackage — spdx-ai-dataset-1.json carries none
// of the former. A document with no AI package, no dataset package and no
// VEX relationship has nothing but its @context to classify it.
//
// Built from a real fixture by dropping WHOLE elements, which is the permitted
// trim; no string inside a kept element is edited.
func TestEvidenceBuild_FromDirRoutesAnSPDX3SoftwareProfileSBOM(t *testing.T) {
	raw, readErr := os.ReadFile(bomFixturePath(t, "spdx-ai-model-1.json"))
	require.NoError(t, readErr)
	var src map[string]any
	require.NoError(t, json.Unmarshal(raw, &src))

	graph, ok := src["@graph"].([]any)
	require.True(t, ok, "the fixture must carry a @graph")
	kept := make([]any, 0, len(graph))
	dropped := 0
	for _, el := range graph {
		m, isMap := el.(map[string]any)
		if isMap {
			switch m["type"] {
			case "ai_AIPackage", "dataset_DatasetPackage":
				dropped++
				continue
			}
		}
		kept = append(kept, el)
	}
	require.Positive(t, dropped, "the fixture must have carried the elements this test removes")
	trimmed, marshalErr := json.Marshal(map[string]any{"@context": src["@context"], "@graph": kept})
	require.NoError(t, marshalErr)

	dir := scanTree(t)
	// Named so nothing can route it by filename.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "inventory.json"), trimmed, 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err)

	data, _ := os.ReadFile(outputPath)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))
	byType := map[string]string{}
	systems := 0
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		byType[e["type"].(string)] = e["uri"].(string)
		if e["type"] == "hdf-system" {
			systems++
		}
	}
	assert.Equal(t, "inventory.json", byType["bom"],
		"an SPDX 3 software-profile SBOM is a BOM, whatever ParseBom can normalize")
	assert.Equal(t, 1, systems, "and it must not be promoted to a second system document")
}

// add() stats rather than lstats, so naming a SYMLINK explicitly skips its TARGET
// in the scan — one document, once. It is recorded under the target's path, not
// the link's, because resolvedAbs resolves symlinks before anything is recorded.
//
// Under lstat the set records the link's own inode, the scan stops skipping the
// target, and the build is REFUSED by the downstream same-document guard rather
// than listing both. Either way the property was unpinned until now, and a
// mutation run proved it.
func TestEvidenceBuild_FromDirNamingASymlinkSkipsItsTarget(t *testing.T) {
	dir := scanTree(t)
	target := filepath.Join(dir, "scans", "rhel9-results.json")
	link := filepath.Join(dir, "scans", "rhel9-results-link.json")
	require.NoError(t, os.Symlink(target, link))

	outputPath := filepath.Join(dir, "pkg.json")
	_, _, err := executeCommand("evidence", "build", "--from-dir", dir, "--results", link, "-o", outputPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	var listed []string
	for _, c := range pkg["contents"].([]interface{}) {
		e := c.(map[string]interface{})
		if e["type"] == "hdf-results" {
			listed = append(listed, e["uri"].(string))
		}
	}
	require.Len(t, listed, 1,
		"the named symlink and the scanned target are one document; got %v", listed)
	assert.Equal(t, "scans/rhel9-results.json", listed[0],
		"recorded under the resolved target, which is what resolvedAbs produces")
}

// The scan funnelled every non-regular kind into one bucket and called them all
// symlinks, so a fifo was reported as a symlink and told to name its target —
// advice that means nothing for a pipe. nonRegularKind already names each kind.
func TestEvidenceBuild_FromDirNamesTheKindItSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("syscall.Mkfifo does not exist on Windows")
	}
	dir := scanTree(t)
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "apipe"), 0o600))
	require.NoError(t, os.Symlink("system.json", filepath.Join(dir, "alink.json")))

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir,
		"-o", filepath.Join(dir, "pkg.json"))
	require.NoError(t, err)

	var pipeLine, linkLine string
	for _, l := range strings.Split(stderr, "\n") {
		switch {
		case strings.Contains(l, "apipe"):
			pipeLine = l
		case strings.Contains(l, "alink.json"):
			linkLine = l
		}
	}
	require.NotEmpty(t, pipeLine, "the fifo must be reported, not dropped")
	require.NotEmpty(t, linkLine, "the symlink must be reported too")

	assert.Contains(t, pipeLine, "a named pipe", "a fifo must be named as one")
	assert.NotContains(t, pipeLine, "a symlink", "a fifo is not a symlink")
	// The advice is only true of a symlink, so it must travel with that kind alone.
	assert.NotContains(t, pipeLine, "Name its target",
		"a pipe has no target to name; that advice belongs to a symlink")

	assert.Contains(t, linkLine, "a symlink", "a symlink still says symlink")
	assert.Contains(t, linkLine, "Name its target", "and keeps its advice")
}
