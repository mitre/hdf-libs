package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createBaseSystem writes a system document with a single "juice-shop"
// component (imported from the plain CycloneDX SBOM fixture) and returns its
// path. Used as the target for add-component / update-component tests.
func createBaseSystem(t *testing.T) string {
	t.Helper()
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())
	return sysFile
}

// createSystemFrom builds a system document from an arbitrary BOM fixture and
// returns its path — used to seed reconcile tests whose existing components must
// carry the source subjects' boms[].uniqueId.
func createSystemFrom(t *testing.T, fixture, from string) string {
	t.Helper()
	sysFile := filepath.Join(t.TempDir(), "system.json")
	args := []string{"system", "create", bomFixturePath(t, fixture), "-o", sysFile}
	if from != "" {
		args = append(args, "--from", from)
	}
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	require.NoError(t, cmd.Execute())
	return sysFile
}

func readSystemComponents(t *testing.T, sysFile string) []interface{} {
	t.Helper()
	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	comps, _ := sys["components"].([]interface{})
	return comps
}

func findComponentByName(t *testing.T, sysFile, name string) map[string]interface{} {
	t.Helper()
	for _, c := range readSystemComponents(t, sysFile) {
		if comp, ok := c.(map[string]interface{}); ok && comp["name"] == name {
			return comp
		}
	}
	t.Fatalf("component %q not found in %s", name, sysFile)
	return nil
}

// firstBOMOf returns the first boms[] entry of a component read back from JSON.
func firstBOMOf(t *testing.T, comp map[string]interface{}) map[string]interface{} {
	t.Helper()
	boms, ok := comp["boms"].([]interface{})
	require.True(t, ok, "component has no boms[]")
	require.NotEmpty(t, boms)
	bm, ok := boms[0].(map[string]interface{})
	require.True(t, ok)
	return bm
}

// ---- add-component --from format-assertion tests ----

// add-component ingests a CycloneDX ML-BOM as a correctly-typed aiModel
// component carrying a normalized ai-model BOM (not mislabeled bomType=sbom).
func TestSystemAddComponent_MLBOM_IngestsAIModel(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "Model"})
	require.NoError(t, cmd.Execute())

	comp := findComponentByName(t, sysFile, "Model")
	assert.Equal(t, "aiModel", comp["type"])
	assert.Equal(t, "ai-model", firstBOMOf(t, comp)["bomType"])
}

// Auto-detected ML-BOM (no --from) is ingested the same way.
func TestSystemAddComponent_MLBOM_IngestsAIModel_AutoDetect(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--component-name", "Model"})
	require.NoError(t, cmd.Execute())

	comp := findComponentByName(t, sysFile, "Model")
	assert.Equal(t, "aiModel", comp["type"])
	assert.Equal(t, "ai-model", firstBOMOf(t, comp)["bomType"])
}

func TestSystemAddComponent_FromFormat_MLBOMMismatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "Other"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

// A multi-subject SPDX-3 AI-BOM fans out into one correctly-typed component per
// subject, each stamped with its source spdxId as boms[].uniqueId.
func TestSystemAddComponent_SPDXAI_FansOutSubjects(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json") // 2 ai_AIPackage + 1 dataset

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "spdx-ai"})
	require.NoError(t, cmd.Execute())

	require.Len(t, readSystemComponents(t, sysFile), 4) // 1 base + 3 subjects

	word := findComponentByName(t, sysFile, "word-model")
	assert.Equal(t, "aiModel", word["type"])
	assert.Equal(t, "https://my-first-aibom.com/word-model", firstBOMOf(t, word)["uniqueId"])

	ds := findComponentByName(t, sysFile, "IAMdataset")
	assert.Equal(t, "dataset", ds["type"])
	assert.Equal(t, "dataset", firstBOMOf(t, ds)["bomType"])
}

// A single-subject SPDX-3 document is one component, so --component-name applies
// (cardinality 1) just as it does for an SBOM/ML-BOM.
func TestSystemAddComponent_SPDXAI_SingleSubjectNameOverride(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-dataset-1.json") // exactly 1 dataset subject

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "spdx-ai", "--component-name", "MyDataset"})
	require.NoError(t, cmd.Execute())

	comp := findComponentByName(t, sysFile, "MyDataset")
	assert.Equal(t, "dataset", comp["type"])
}

// --component-name is invalid on a multi-subject input (it can name only one).
func TestSystemAddComponent_ComponentNameMultiSubjectErrors(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "spdx-ai", "--component-name", "X"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one resulting component")
}

// --component-name-prefix namespaces every subject; it is rejected on a
// single-component input (--component-name is for that).
func TestSystemAddComponent_Prefix(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "spdx-ai", "--component-name-prefix", "build42-"})
	require.NoError(t, cmd.Execute())

	comp := findComponentByName(t, sysFile, "build42-word-model")
	assert.Equal(t, "aiModel", comp["type"])
}

func TestSystemAddComponent_PrefixSingleSubjectErrors(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--component-name-prefix", "x-"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multi-subject")
}

func TestSystemAddComponent_NameAndPrefixMutuallyExclusive(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--component-name", "A", "--component-name-prefix", "b-"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// A duplicate human-friendly name warns but is not rejected (names are labels).
func TestSystemAddComponent_DuplicateNameWarns(t *testing.T) {
	sysFile := createBaseSystem(t) // component "juice-shop"
	bomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--component-name", "juice-shop"})
	require.NoError(t, cmd.Execute())

	count := 0
	for _, c := range readSystemComponents(t, sysFile) {
		if comp, ok := c.(map[string]interface{}); ok && comp["name"] == "juice-shop" {
			count++
		}
	}
	assert.Equal(t, 2, count)
}

func TestSystemAddComponent_FromFormat_CycloneDXMatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--from", "cyclonedx", "--component-name", "SecondTier"})
	require.NoError(t, cmd.Execute())
}

func TestSystemAddComponent_FromFormat_CycloneDXRejectsMLBOM(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "cyclonedx", "--component-name", "Model"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemAddComponent_FromFormat_Unknown(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--from", "bogus", "--component-name", "X"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --from format")
}

func TestSystemAddComponent_MissingPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "--system", sysFile, "--component-name", "X"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arg")
}

func TestSystemAddComponent_URLPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "https://artifacts.example.com/sbom/auth.cdx.json", "--system", sysFile, "--component-name", "AuthService"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "auth.cdx.json")
}

// A URL input can't be read to derive a name, so --component-name is required.
func TestSystemAddComponent_URLRequiresComponentName(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "https://artifacts.example.com/sbom/auth.cdx.json", "--system", sysFile})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--component-name is required")
}

// A URL input can't be fetched to verify its format, so --from is rejected.
func TestSystemAddComponent_FromFormat_URLRejected(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "https://artifacts.example.com/sbom/auth.cdx.json", "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "AuthService"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL")
}

// loadBOM must reject oversized input via the size gate before json.Unmarshal.
func TestSystemAddComponent_OversizedInputRejected(t *testing.T) {
	sysFile := createBaseSystem(t)
	big := make([]byte, 2*1024*1024)
	for i := range big {
		big[i] = 'a'
	}
	f := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(f, big, 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", f, "--system", sysFile, "--component-name", "X", "--max-size", "1"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

// applyNamePrefix numbers only the nameless subjects, independent of position:
// a named subject never consumes a number.
func TestApplyNamePrefix(t *testing.T) {
	comps := []map[string]interface{}{
		{"name": "alpha"},
		{"name": ""},
		{"name": "gamma"},
		{"name": ""},
	}
	applyNamePrefix(comps, "p-")
	assert.Equal(t, "p-alpha", comps[0]["name"])
	assert.Equal(t, "p-1", comps[1]["name"])
	assert.Equal(t, "p-gamma", comps[2]["name"])
	assert.Equal(t, "p-2", comps[3]["name"])
}

// ---- add-component multi-file batch tests (whlr.1) ----

// Multiple positional BOM files are each fanned out via the shared builder and
// accumulated into ONE system-document write; --component-name-prefix namespaces
// every subject across the whole batch (a single batch-level pass), and formats
// are detected per file when --from is omitted.
func TestSystemAddComponent_MultiFile_FansOutAll(t *testing.T) {
	sysFile := createBaseSystem(t)                   // 1 component: juice-shop
	sbom := bomFixturePath(t, "cyclonedx-sbom.json") // 1 subject: juice-shop
	ai := bomFixturePath(t, "spdx-ai-model-1.json")  // 3 subjects: word-model, line-model, IAMdataset

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbom, ai, "--system", sysFile, "--component-name-prefix", "build42-"})
	require.NoError(t, cmd.Execute())

	// 1 base + 1 (sbom) + 3 (spdx-ai) = 5, all present after a single write.
	require.Len(t, readSystemComponents(t, sysFile), 5)
	for _, name := range []string{"build42-juice-shop", "build42-word-model", "build42-line-model", "build42-IAMdataset"} {
		findComponentByName(t, sysFile, name) // fatals if missing
	}
}

// --component-name (singular) names exactly one component, so it is invalid when
// more than one file is given (the batch expects >1 component).
func TestSystemAddComponent_MultiFile_RejectsComponentName(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbom := bomFixturePath(t, "cyclonedx-sbom.json")
	ai := bomFixturePath(t, "spdx-ai-model-1.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbom, ai, "--system", sysFile, "--component-name", "X"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple files")
}

// ---- add-component multi-file all-or-nothing tests (whlr.2) ----

// A batch containing any un-ingestible file writes NOTHING — the system document
// is left byte-for-byte unchanged, and even the good file's component is not added.
func TestSystemAddComponent_MultiFile_AllOrNothing_BadFileWritesNothing(t *testing.T) {
	sysFile := createBaseSystem(t) // 1 component: juice-shop
	before, err := os.ReadFile(sysFile)
	require.NoError(t, err)

	good := bomFixturePath(t, "cyclonedx-sbom.json")
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"not":"a recognized bom"}`), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", good, bad, "--system", sysFile})
	require.Error(t, cmd.Execute())

	after, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a batch with any bad file must write nothing")
	require.Len(t, readSystemComponents(t, sysFile), 1) // base only; the good file was NOT ingested
}

// Every failing file is reported, not just the first (process-all, report-all —
// NOT fail-fast on the first bad file).
func TestSystemAddComponent_MultiFile_AllOrNothing_ReportsAllFailures(t *testing.T) {
	sysFile := createBaseSystem(t)
	dir := t.TempDir()
	bad1 := filepath.Join(dir, "bad1.json")
	bad2 := filepath.Join(dir, "bad2.json")
	require.NoError(t, os.WriteFile(bad1, []byte(`{"not":"a bom"}`), 0o600))
	require.NoError(t, os.WriteFile(bad2, []byte("not even json"), 0o600))

	_, stderr, err := executeCommand("system", "add-component", bad1, bad2, "--system", sysFile)
	require.Error(t, err)
	assert.Contains(t, stderr, "bad1.json", "first bad file must be reported")
	assert.Contains(t, stderr, "bad2.json", "second bad file must also be reported (report-all, not fail-fast)")
	require.Len(t, readSystemComponents(t, sysFile), 1) // nothing written
}

// ---- add-component multi-file --from semantics tests (whlr.3) ----

// In multi-file mode --from is a SINGLE uniform assertion applied to every file:
// if any file's detected format disagrees, the batch errors and writes nothing.
func TestSystemAddComponent_MultiFile_From_UniformAssertionErrorsOnDisagreement(t *testing.T) {
	sysFile := createBaseSystem(t)
	before, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	cdx := bomFixturePath(t, "cyclonedx-sbom.json")
	ai := bomFixturePath(t, "spdx-ai-model-1.json") // detected as spdx-3-ai, not cyclonedx

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", cdx, ai, "--system", sysFile, "--from", "cyclonedx"})
	require.Error(t, cmd.Execute())

	after, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a --from that disagrees with any file writes nothing")
}

// A uniform --from that matches every file ingests them all.
func TestSystemAddComponent_MultiFile_From_UniformAssertionMatchingSucceeds(t *testing.T) {
	sysFile := createBaseSystem(t)
	cdx := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", cdx, cdx, "--system", sysFile, "--from", "cyclonedx"})
	require.NoError(t, cmd.Execute())
	require.Len(t, readSystemComponents(t, sysFile), 3) // 1 base + 2 (both cyclonedx)
}

// --from is a single value, NEVER a positional/CSV list mapped to file order: a
// comma-joined value is treated as one (unknown) alias, not split per file.
func TestSystemAddComponent_MultiFile_From_NoPositionalCSV(t *testing.T) {
	sysFile := createBaseSystem(t)
	cdx := bomFixturePath(t, "cyclonedx-sbom.json")
	ai := bomFixturePath(t, "spdx-ai-model-1.json")

	_, stderr, err := executeCommand("system", "add-component", cdx, ai, "--system", sysFile, "--from", "cyclonedx,spdx-ai")
	require.Error(t, err)
	// A CSV --from is treated as one (unknown) alias, never split per file.
	assert.Contains(t, stderr, "unknown --from format")
	require.Len(t, readSystemComponents(t, sysFile), 1) // nothing written
}

// A URL cannot be read to derive component metadata, and --component-name (the
// single-file escape hatch for URLs) is invalid with multiple files. Rather than
// leave the user with the unsatisfiable "--component-name is required" error, a
// URL among multiple args is rejected early with a clear URL-specific message.
func TestSystemAddComponent_MultiFile_RejectsURL(t *testing.T) {
	sysFile := createBaseSystem(t)
	before, err := os.ReadFile(sysFile)
	require.NoError(t, err)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFixturePath(t, "cyclonedx-sbom.json"),
		"https://artifacts.example.com/auth.cdx.json", "--system", sysFile})
	execErr := cmd.Execute()
	require.Error(t, execErr)
	assert.Contains(t, execErr.Error(), "URL", "a URL in multi-file mode must be rejected with a clear URL-specific message")

	after, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Equal(t, before, after, "nothing written")
}

// ---- update-component --from format-assertion tests ----

// Targeted update replaces the named component's boms[] entry from a
// single-subject BOM — including swapping an SBOM for an ML-BOM.
func TestSystemUpdateComponent_MLBOM_Targeted(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "cyclonedx-mlbom"})
	require.NoError(t, cmd.Execute())

	comp := findComponentByName(t, sysFile, "juice-shop")
	assert.Equal(t, "aiModel", comp["type"])
	assert.Equal(t, "ai-model", firstBOMOf(t, comp)["bomType"])
}

func TestSystemUpdateComponent_MLBOM_Targeted_AutoDetect(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, "ai-model", firstBOMOf(t, findComponentByName(t, sysFile, "juice-shop"))["bomType"])
}

func TestSystemUpdateComponent_FromFormat_MLBOMMismatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "cyclonedx-mlbom"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

// Targeted update fully replaces metadata: switching a component from an ML-BOM
// (aiModel, carries modelId) to a plain SBOM must drop the now-stale derived keys.
func TestSystemUpdateComponent_TargetedReplacesDerivedMetadata(t *testing.T) {
	sysFile := createBaseSystem(t)

	add := NewRootCmd()
	add.SetArgs([]string{"system", "add-component", bomFixturePath(t, "cyclonedx-mlbom.json"), "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "TheModel"})
	require.NoError(t, add.Execute())
	require.Contains(t, findComponentByName(t, sysFile, "TheModel"), "modelId") // aiModel carries modelId

	upd := NewRootCmd()
	upd.SetArgs([]string{"system", "update-component", bomFixturePath(t, "cyclonedx-sbom.json"), "--system", sysFile, "--component-name", "TheModel", "--from", "cyclonedx"})
	require.NoError(t, upd.Execute())

	comp := findComponentByName(t, sysFile, "TheModel")
	assert.NotContains(t, comp, "modelId", "stale modelId must be removed on SBOM refresh")
	assert.NotContains(t, comp, "version", "stale version must be removed on SBOM refresh")
	assert.Equal(t, "application", comp["type"])
	assert.Equal(t, "sbom", firstBOMOf(t, comp)["bomType"])
}

// Targeted mode (--component-name) cannot take a multi-subject BOM — the user is
// told to omit --component-name and reconcile instead.
func TestSystemUpdateComponent_TargetedRejectsMultiSubject(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "spdx-ai"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reconcile by subject id")
}

// Reconcile refreshes each subject in place by matching boms[].uniqueId against
// the components a prior `system create` produced from the same source.
func TestSystemUpdateComponent_ReconcileByUniqueID(t *testing.T) {
	sysFile := createSystemFrom(t, "spdx-ai-model-1.json", "spdx-ai") // 3 subjects
	require.Len(t, readSystemComponents(t, sysFile), 3)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFixturePath(t, "spdx-ai-model-1.json"), "--system", sysFile, "--from", "spdx-ai"})
	require.NoError(t, cmd.Execute())

	// Same three subjects, refreshed in place — no growth, identities preserved.
	require.Len(t, readSystemComponents(t, sysFile), 3)
	word := findComponentByName(t, sysFile, "word-model")
	assert.Equal(t, "https://my-first-aibom.com/word-model", firstBOMOf(t, word)["uniqueId"])
}

// Reconcile with a disjoint BOM + --add-new: existing components are left
// unchanged (unmatched-existing warning) while the new subjects are appended.
func TestSystemUpdateComponent_ReconcileUnmatchedExistingLeftIntact(t *testing.T) {
	sysFile := createSystemFrom(t, "spdx-ai-model-1.json", "spdx-ai") // 3 subjects
	require.Len(t, readSystemComponents(t, sysFile), 3)

	other := bomFixturePath(t, "spdx-ai-model-2.json") // 2 subjects, different spdxIds

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", other, "--system", sysFile, "--from", "spdx-ai", "--add-new"})
	require.NoError(t, cmd.Execute())

	// 3 originals (untouched) + 2 appended.
	assert.Len(t, readSystemComponents(t, sysFile), 5)
	// An original is still present with its unchanged uniqueId.
	word := findComponentByName(t, sysFile, "word-model")
	assert.Equal(t, "https://my-first-aibom.com/word-model", firstBOMOf(t, word)["uniqueId"])
}

// buildComponentsFromBOM guards against a format it can't build (defensive:
// loadBOM already rejects unrecognized input upstream).
func TestBuildComponentsFromBOM_UnsupportedFormat(t *testing.T) {
	_, err := buildComponentsFromBOM([]byte("{}"), map[string]interface{}{}, "bogus", bomComponentBuildOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported BOM format")
}

// A subject that matches no existing component is skipped unless --add-new.
func TestSystemUpdateComponent_ReconcileAddNew(t *testing.T) {
	sysFile := createSystemFrom(t, "spdx-ai-dataset-1.json", "spdx-ai") // 1 dataset subject
	require.Len(t, readSystemComponents(t, sysFile), 1)

	base := bomFixturePath(t, "spdx-ai-model-1.json") // 3 unrelated subjects

	// Without --add-new: nothing matches → error, no growth.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", base, "--system", sysFile, "--from", "spdx-ai"})
	require.Error(t, cmd.Execute())
	require.Len(t, readSystemComponents(t, sysFile), 1)

	// With --add-new: the 3 unmatched subjects are appended.
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "update-component", base, "--system", sysFile, "--from", "spdx-ai", "--add-new"})
	require.NoError(t, cmd2.Execute())
	assert.Len(t, readSystemComponents(t, sysFile), 4)
}

func TestSystemUpdateComponent_FromFormat_SPDXMatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "spdx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "spdx"})
	require.NoError(t, cmd.Execute())
}

func TestSystemUpdateComponent_FromFormat_CycloneDXRejectsMLBOM(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "cyclonedx"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemUpdateComponent_FromFormat_Unknown(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "bogus"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --from format")
}

func TestSystemUpdateComponent_MissingPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", "--system", sysFile, "--component-name", "juice-shop"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arg")
}

func TestSystemUpdateComponent_URLPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", "https://artifacts.example.com/sbom/juice.cdx.json", "--system", sysFile, "--component-name", "juice-shop"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "juice.cdx.json")
}

// findComponentByBOMUniqueID returns the live component map and boms slice so
// the reconcile caller mutates them directly instead of re-asserting
// components[ci].(map) / comp["boms"].([]interface{}).
func TestFindComponentByBOMUniqueID_ReturnsResolvedComponent(t *testing.T) {
	comp := map[string]interface{}{
		"name": "word-model",
		"boms": []interface{}{
			map[string]interface{}{"uniqueId": "id-a"},
			map[string]interface{}{"uniqueId": "id-b"},
		},
	}
	components := []interface{}{comp}

	ci, bi, gotComp, gotBoms, ok := findComponentByBOMUniqueID(components, "id-b")
	require.True(t, ok)
	assert.Equal(t, 0, ci)
	assert.Equal(t, 1, bi)

	// The returned refs are the live objects: mutating them updates the slice,
	// so the caller never re-asserts (the cross-function invariant is gone).
	gotBoms[bi] = map[string]interface{}{"uniqueId": "refreshed"}
	gotComp["boms"] = gotBoms
	assert.Equal(t, "refreshed", comp["boms"].([]interface{})[1].(map[string]interface{})["uniqueId"])
}

// A component whose boms is stored as a differently-typed slice (or whose entry
// is not a map) is the exact input that would have panicked the old caller's
// unchecked comp["boms"].([]interface{}) assertion. The finder must skip it and
// return only a fully-usable component.
func TestFindComponentByBOMUniqueID_SkipsMalformedComponents(t *testing.T) {
	valid := map[string]interface{}{
		"name": "keeper",
		"boms": []interface{}{map[string]interface{}{"uniqueId": "match"}},
	}
	components := []interface{}{
		"not-a-map",
		map[string]interface{}{"name": "no-boms"},
		map[string]interface{}{"boms": []map[string]interface{}{{"uniqueId": "match"}}}, // wrong boms type
		valid,
	}

	require.NotPanics(t, func() {
		ci, bi, gotComp, gotBoms, ok := findComponentByBOMUniqueID(components, "match")
		require.True(t, ok)
		assert.Equal(t, 3, ci)
		assert.Equal(t, 0, bi)
		assert.Equal(t, "keeper", gotComp["name"])
		assert.Len(t, gotBoms, 1)
	})
}
