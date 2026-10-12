package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const evidenceFixture = `{
  "name": "Q1-2026 Authorization Package",
  "preparedBy": {"identifier": "issm@agency.gov", "type": "email"},
  "preparedAt": "2026-03-15T00:00:00Z",
  "systemRef": "portal-prod.hdf-system.json",
  "contents": [
    {"type": "hdf-system", "uri": "portal-prod.hdf-system.json"},
    {"type": "hdf-baseline", "uri": "rhel9-stig.hdf-baseline.json", "checksum": {"algorithm": "sha256", "value": "abc123"}},
    {"type": "hdf-results", "uri": "scan-2026-03.hdf-results.json", "checksum": {"algorithm": "sha256", "value": "def456"}},
    {"type": "hdf-amendments", "uri": "waivers.hdf-amendments.json"},
    {"type": "hdf-comparison", "uri": "diff-q4-q1.hdf-comparison.json"}
  ],
  "completenessCheck": {
    "allBaselinesAssessed": true,
    "allComponentsCovered": true,
    "expiredWaivers": 0,
    "unresolvedPoams": 2,
    "compliancePercent": 94
  }
}`

func writeEvidenceFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "evidence.json")
	require.NoError(t, os.WriteFile(p, []byte(evidenceFixture), 0o600))
	return p
}

func TestEvidenceInfoCommand(t *testing.T) { //nolint:dupl
	t.Run("displays evidence info in human-readable format", func(t *testing.T) {
		fixture := writeEvidenceFixture(t)
		stdout, _, err := executeCommand("evidence", "info", fixture)
		require.NoError(t, err)

		assert.Contains(t, stdout, "Evidence Package: Q1-2026 Authorization Package")
		assert.Contains(t, stdout, "Prepared by: issm@agency.gov")
		assert.Contains(t, stdout, "Prepared at: 2026-03-15T00:00:00Z")
		assert.Contains(t, stdout, "System: portal-prod.hdf-system.json")
		assert.Contains(t, stdout, "Contents (5):")
		assert.Contains(t, stdout, "hdf-system")
		assert.Contains(t, stdout, "portal-prod.hdf-system.json")
		assert.Contains(t, stdout, "rhel9-stig.hdf-baseline.json")
		// The tick is gone from the default path: nothing is hashed there, so nothing
		// may be rendered as checked. This assertion used to pin the tick, which is
		// what made the defect in 52n0c.37 look like intended behaviour.
		assert.Contains(t, stdout, "checksum recorded")
		assert.NotContains(t, stdout, "\u2713",
			"the tick belongs to a computed match under --verify, not to the summary")
		assert.Contains(t, stdout, "waivers.hdf-amendments.json")
		// Attributed, not bare: the schema calls the stored block non-authoritative, so
		// the heading says the package recorded it rather than implying info found it.
		assert.Contains(t, stdout, "Completeness, as recorded by the package")
		assert.Contains(t, stdout, "All baselines assessed: yes")
		assert.Contains(t, stdout, "All components covered: yes")
		assert.Contains(t, stdout, "Expired waivers: 0")
		assert.Contains(t, stdout, "Unresolved POA&Ms: 2")
		assert.Contains(t, stdout, "Compliance: 94%")
	})

	t.Run("displays evidence info in JSON format", func(t *testing.T) {
		fixture := writeEvidenceFixture(t)
		stdout, _, err := executeCommand("evidence", "info", "--json", fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
		assert.Equal(t, "Q1-2026 Authorization Package", doc["name"])
		assert.Equal(t, "portal-prod.hdf-system.json", doc["systemRef"])
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "info", "/nonexistent/file.json")
		require.Error(t, err)
	})

	t.Run("returns usage error with no args", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "info")
		require.Error(t, err)
	})
}

func TestBoolYesNo(t *testing.T) {
	assert.Equal(t, "yes", boolYesNo(true))
	assert.Equal(t, "no", boolYesNo(false))
}

// Absorbed from hdf-libs-52n0c.37. info printed "✓ checksum" on the mere PRESENCE of the
// checksum key, so an entry recording a BLANK value and one whose reference is a remote
// URI nobody fetched both displayed as checked. The tick claimed verification that never
// happened — and in the default path nothing is hashed at all, so no line may imply it.
// A blank value is schema-valid: Checksum.value has no minLength.
func TestEvidenceInfo_DefaultPathReportsWhatIsRecordedNotWhatIsChecked(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "pkg.json")
	pkg := map[string]any{
		"name": "recorded-states",
		"contents": []any{
			map[string]any{"type": "hdf-results", "uri": "a.json",
				"checksum": map[string]any{"algorithm": "sha256", "value": strings.Repeat("a", 64)}},
			map[string]any{"type": "hdf-results", "uri": "b.json",
				"checksum": map[string]any{"algorithm": "sha256", "value": ""}},
			map[string]any{"type": "hdf-plan", "uri": "c.json"},
		},
		"externalEvidence": []any{
			map[string]any{"uri": "https://logs.example.gov/x.ndjson", "format": "raw-log",
				"checksum": map[string]any{"algorithm": "sha256", "value": strings.Repeat("b", 64)}},
		},
	}
	out, err := json.MarshalIndent(pkg, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, out, 0o600))

	stdout, _, runErr := executeCommand("evidence", "info", pkgPath)
	require.NoError(t, runErr)

	// Nothing was hashed, so no tick anywhere — not for the entry with a checksum, and
	// certainly not for the remote one nobody fetched.
	assert.NotContains(t, stdout, "✓", "the default path hashes nothing, so it may not tick")
	assert.NotContains(t, stdout, "checked")
	assert.NotContains(t, stdout, "verified")

	// Three RECORDED states, distinguished: a value, an empty value, and none at all.
	// The middle one is the defect — it used to read identically to the first.
	assert.Contains(t, stdout, "checksum recorded")
	assert.Contains(t, stdout, "checksum recorded but empty")
	assert.Contains(t, stdout, "no checksum recorded")

	// And the remote entry is reported as recording one, which is true: info did not
	// fetch it, so its reachability is not info's claim to make.
	assert.Contains(t, stdout, "https://logs.example.gov/x.ndjson")
}

// The second half of the same defect, one field over. The schema says of
// Completeness_Check: "Informational summary of assessment completeness. Not
// authoritative — tools should compute these from the referenced documents." So the
// default path printing that block under a bare "Completeness:" heading presents a claim
// it never established, exactly as the presence-tick did. It must say the package RECORDS
// this, and point at where a computed answer comes from.
func TestEvidenceInfo_LabelsTheStoredCompletenessAsRecorded(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "pkg.json")
	pkg := map[string]any{
		"name":     "stored-completeness",
		"contents": []any{map[string]any{"type": "hdf-results", "uri": "a.json"}},
		// A block claiming full coverage. Nothing here was computed from anything.
		"completenessCheck": map[string]any{
			"allBaselinesAssessed": true,
			"allComponentsCovered": true,
			"compliancePercent":    100,
		},
	}
	out, err := json.MarshalIndent(pkg, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, out, 0o600))

	stdout, _, runErr := executeCommand("evidence", "info", pkgPath)
	require.NoError(t, runErr)

	assert.Contains(t, stdout, "as recorded",
		"the heading must attribute the numbers to the document, not to this command")
	assert.Contains(t, stdout, "--verify",
		"and point at where a computed answer comes from")
	assert.NotContains(t, stdout, "\nCompleteness:\n",
		"the bare heading reads as this command's finding")
}

// The refusal was stated in the help and correct in the binary, and NOTHING RAN IT: the
// whole branch could be deleted and the suite stayed green. That is the "a gate must be
// wired to something that runs it" failure, found by the AC review rather than by me.
//
// Refused rather than ignored, because a flag that silently does nothing is how an
// operator comes to believe a check ran. --require-checksums-match is included via
// Changed() rather than by value: it defaults TRUE, so its value cannot distinguish the
// default from an operator explicitly typing =false.
func TestEvidenceInfo_RefusesVerifyOnlyFlagsWithoutVerify(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "pkg.json")
	pkg := map[string]any{"name": "stray-flags",
		"contents": []any{map[string]any{"type": "hdf-results", "uri": "a.json"}}}
	out, err := json.MarshalIndent(pkg, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, out, 0o600))

	for _, tc := range []struct{ name, flag string }{
		{"checksums-only", "--checksums-only"},
		{"require-reachable", "--require-reachable"},
		// The one the old rationale wrongly excluded: it defaults true, so only
		// Changed() can tell an explicit =false from the default.
		{"require-checksums-match set explicitly", "--require-checksums-match=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, runErr := executeCommand("evidence", "info", pkgPath, tc.flag)
			require.Error(t, runErr, "%s does nothing without --verify and must be refused", tc.flag)
			assert.Contains(t, runErr.Error(), "only mean(s) something with --verify")
			assert.Contains(t, runErr.Error(), strings.Split(tc.flag, "=")[0],
				"the refusal must name the flag the operator actually typed")
		})
	}

	// And the default, with nothing set, is not refused — the refusal keys on what was
	// typed, not on the flags' values.
	_, _, okErr := executeCommand("evidence", "info", pkgPath)
	require.NoError(t, okErr, "an unset --require-checksums-match must not trip the refusal")
}
